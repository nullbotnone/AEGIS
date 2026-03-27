/* SPDX-License-Identifier: GPL-2.0
 * AEGIS eBPF Attestation Probe
 *
 * Monitors syscall tracepoints for AI agent behavior attestation:
 * - File operations (openat/openat2, read, write)
 * - Network connections (connect, sendto)
 * - Process execution (execve)
 */

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/openat2.h>
#include <linux/socket.h>
#include <linux/types.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define MAX_PATH_LEN 256
#define MAX_ENDPOINT_LEN 128

#ifndef O_WRONLY
#define O_WRONLY 1
#endif
#ifndef O_RDWR
#define O_RDWR 2
#endif
#ifndef O_CREAT
#define O_CREAT 0100
#endif
#ifndef O_TRUNC
#define O_TRUNC 01000
#endif

#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef AF_INET6
#define AF_INET6 10
#endif

struct aegis_sockaddr {
    __u16 sa_family;
    char sa_data[14];
};


/* Action types - must match attestation.py */
#define ACTION_FILE_READ      1
#define ACTION_FILE_WRITE     2
#define ACTION_NETWORK_CONN   3
#define ACTION_TOOL_INVOKE    4

/* Minimal syscall tracepoint context. */
struct trace_event_raw_sys_enter {
    __u16 common_type;
    __u8 common_flags;
    __u8 common_preempt_count;
    __s32 common_pid;
    __s64 id;
    __u64 args[6];
};

/* Event structure sent to userspace via ring buffer. */
struct __attribute__((packed)) aegis_event {
    __u64 timestamp;
    __u32 pid;
    __u32 tid;
    __u32 uid;
    __u32 action_type;
    __u64 size;
    char path[MAX_PATH_LEN];
    char endpoint[MAX_ENDPOINT_LEN];
    __u32 endpoint_port;
};

/* Per-agent state tracking. */
struct agent_state {
    __u64 agent_id;
    __u64 session_id;
    __u64 job_id;
    __u64 file_read_bytes;
    __u64 file_write_bytes;
    __u64 network_egress_bytes;
    __u64 connection_count;
    __u64 last_update;
    __u8 tracked;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct agent_state);
    __uint(max_entries, 2048);
} aegis_agent_states SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 128 * 1024);
} aegis_events SEC(".maps");

struct aegis_config {
    __u64 sample_rate;
    __u64 enable_network;
    __u64 enable_file;
    __u64 enable_exec;
    __u64 monitor_uid;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct aegis_config);
    __uint(max_entries, 1);
} aegis_config SEC(".maps");

static __always_inline __u64 get_timestamp(void)
{
    return bpf_ktime_get_ns();
}

static __always_inline struct aegis_config *get_config(void)
{
    __u32 key = 0;
    return bpf_map_lookup_elem(&aegis_config, &key);
}

static __always_inline void get_process_info(__u32 *pid, __u32 *tid, __u32 *uid)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid = bpf_get_current_uid_gid();

    *pid = pid_tgid >> 32;
    *tid = (__u32)pid_tgid;
    *uid = (__u32)uid_gid;
}

static __always_inline int should_track_current(const struct aegis_config *cfg)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 uid = (__u32)bpf_get_current_uid_gid();

    if (cfg && cfg->monitor_uid != 0 && cfg->monitor_uid != uid)
        return 0;

    if (cfg && cfg->sample_rate > 1 && ((__u32)pid_tgid % cfg->sample_rate) != 0)
        return 0;

    return 1;
}

static __always_inline void read_user_path(char path[MAX_PATH_LEN], const char *src)
{
    __builtin_memset(path, 0, MAX_PATH_LEN);
    if (!src)
        return;
    if (bpf_probe_read_user_str(path, MAX_PATH_LEN, src) < 0)
        path[0] = 0;
}

static __always_inline void copy_path(char dst[MAX_PATH_LEN], const char *src)
{
#pragma unroll
    for (int i = 0; i < MAX_PATH_LEN; i++) {
        char c = 0;

        if (src)
            c = src[i];

        dst[i] = c;
        if (c == 0)
            break;
    }
}

static __always_inline void copy_endpoint(char dst[MAX_ENDPOINT_LEN], const char *src)
{
#pragma unroll
    for (int i = 0; i < MAX_ENDPOINT_LEN; i++) {
        char c = 0;

        if (src)
            c = src[i];

        dst[i] = c;
        if (c == 0)
            break;
    }
}

static __always_inline long emit_event(
    __u32 action_type,
    __u64 size,
    const char *path,
    const char *endpoint,
    __u32 port
)
{
    __u32 pid, tid, uid;
    struct aegis_event *event;

    get_process_info(&pid, &tid, &uid);

    event = bpf_ringbuf_reserve(&aegis_events, sizeof(struct aegis_event), 0);
    if (!event)
        return 0;

    __builtin_memset(event, 0, sizeof(*event));
    event->timestamp = get_timestamp();
    event->pid = pid;
    event->tid = tid;
    event->uid = uid;
    event->action_type = action_type;
    event->size = size;
    event->endpoint_port = port;

    if (path)
        copy_path(event->path, path);
    if (endpoint)
        copy_endpoint(event->endpoint, endpoint);

    bpf_ringbuf_submit(event, 0);
    return 0;
}

static __always_inline void update_agent_state(
    __u32 pid,
    __u64 read_bytes,
    __u64 write_bytes,
    __u64 net_bytes,
    int conn
)
{
    struct agent_state *state = bpf_map_lookup_elem(&aegis_agent_states, &pid);

    if (!state) {
        struct agent_state new_state = {
            .last_update = get_timestamp(),
            .tracked = 1,
        };

        bpf_map_update_elem(&aegis_agent_states, &pid, &new_state, BPF_ANY);
        state = bpf_map_lookup_elem(&aegis_agent_states, &pid);
    }

    if (!state)
        return;

    state->file_read_bytes += read_bytes;
    state->file_write_bytes += write_bytes;
    state->network_egress_bytes += net_bytes;
    if (conn)
        state->connection_count += 1;
    state->last_update = get_timestamp();
}

static __always_inline int handle_open_event(const char *filename, int flags)
{
    char path[MAX_PATH_LEN];
    __u32 action = ACTION_FILE_READ;
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    read_user_path(path, filename);

    if (flags & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC))
        action = ACTION_FILE_WRITE;

    emit_event(action, 0, path, 0, 0);
    update_agent_state(
        pid,
        action == ACTION_FILE_READ ? 4096 : 0,
        action == ACTION_FILE_WRITE ? 4096 : 0,
        0,
        0
    );

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_sys_enter_openat(struct trace_event_raw_sys_enter *ctx)
{
    struct aegis_config *cfg = get_config();
    const char *filename;
    int flags;

    if (cfg && !cfg->enable_file)
        return 0;
    if (!should_track_current(cfg))
        return 0;

    filename = (const char *)ctx->args[1];
    flags = (int)ctx->args[2];
    return handle_open_event(filename, flags);
}

SEC("tracepoint/syscalls/sys_enter_openat2")
int trace_sys_enter_openat2(struct trace_event_raw_sys_enter *ctx)
{
    struct aegis_config *cfg = get_config();
    const char *filename;
    const struct open_how *how_ptr;
    struct open_how how = {};

    if (cfg && !cfg->enable_file)
        return 0;
    if (!should_track_current(cfg))
        return 0;

    filename = (const char *)ctx->args[1];
    how_ptr = (const struct open_how *)ctx->args[2];
    if (how_ptr)
        bpf_probe_read_user(&how, sizeof(how), how_ptr);

    return handle_open_event(filename, (int)how.flags);
}

SEC("tracepoint/syscalls/sys_enter_connect")
int trace_sys_enter_connect(struct trace_event_raw_sys_enter *ctx)
{
    struct aegis_config *cfg = get_config();
    const void *addr;
    struct aegis_sockaddr sa = {};
    char endpoint[MAX_ENDPOINT_LEN] = {};
    __u32 port = 0;
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    if (cfg && !cfg->enable_network)
        return 0;
    if (!should_track_current(cfg))
        return 0;

    addr = (const void *)ctx->args[1];
    if (!addr)
        return 0;
    if (bpf_probe_read_user(&sa, sizeof(sa), addr) < 0)
        return 0;

    if (sa.sa_family == AF_INET) {
        struct sockaddr_in addr_in = {};

        if (bpf_probe_read_user(&addr_in, sizeof(addr_in), addr) < 0)
            return 0;

        endpoint[0] = 'i';
        endpoint[1] = 'p';
        endpoint[2] = 'v';
        endpoint[3] = '4';
        port = bpf_ntohs(addr_in.sin_port);
    } else if (sa.sa_family == AF_INET6) {
        struct sockaddr_in6 addr_in6 = {};

        if (bpf_probe_read_user(&addr_in6, sizeof(addr_in6), addr) < 0)
            return 0;

        endpoint[0] = 'i';
        endpoint[1] = 'p';
        endpoint[2] = 'v';
        endpoint[3] = '6';
        port = bpf_ntohs(addr_in6.sin6_port);
    } else {
        return 0;
    }

    emit_event(ACTION_NETWORK_CONN, 0, 0, endpoint, port);
    update_agent_state(pid, 0, 0, 0, 1);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_sys_enter_execve(struct trace_event_raw_sys_enter *ctx)
{
    struct aegis_config *cfg = get_config();
    const char *filename;
    char path[MAX_PATH_LEN];

    if (cfg && !cfg->enable_exec)
        return 0;
    if (!should_track_current(cfg))
        return 0;

    filename = (const char *)ctx->args[0];
    read_user_path(path, filename);
    emit_event(ACTION_TOOL_INVOKE, 0, path, 0, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_read")
int trace_sys_enter_read(struct trace_event_raw_sys_enter *ctx)
{
    struct aegis_config *cfg = get_config();
    __u64 count;
    __u32 pid;

    if (cfg && !cfg->enable_file)
        return 0;
    if (!should_track_current(cfg))
        return 0;

    count = ctx->args[2];
    if (count == 0 || count > (1 << 20))
        return 0;

    pid = bpf_get_current_pid_tgid() >> 32;
    update_agent_state(pid, count, 0, 0, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_write")
int trace_sys_enter_write(struct trace_event_raw_sys_enter *ctx)
{
    struct aegis_config *cfg = get_config();
    __u64 count;
    __u32 pid;

    if (cfg && !cfg->enable_file)
        return 0;
    if (!should_track_current(cfg))
        return 0;

    count = ctx->args[2];
    if (count == 0 || count > (1 << 20))
        return 0;

    pid = bpf_get_current_pid_tgid() >> 32;
    update_agent_state(pid, 0, count, 0, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sendto")
int trace_sys_enter_sendto(struct trace_event_raw_sys_enter *ctx)
{
    struct aegis_config *cfg = get_config();
    __u64 len;
    __u32 pid;

    if (cfg && !cfg->enable_network)
        return 0;
    if (!should_track_current(cfg))
        return 0;

    len = ctx->args[2];
    if (len == 0 || len > (1 << 26))
        return 0;

    pid = bpf_get_current_pid_tgid() >> 32;
    update_agent_state(pid, 0, 0, len, 0);
    return 0;
}

char _license[] SEC("license") = "GPL";
