/* SPDX-License-Identifier: GPL-2.0
 * AEGIS eBPF Attestation Probe
 * 
 * Monitors syscalls for AI agent behavior attestation:
 * - File operations (openat, read, write)
 * - Network connections (connect)
 * - Process execution (execve)
 * 
 * Compile with:
 *   clang -target bpf -D__TARGET_ARCH_x86_64 -O2 -Wall \
 *     -I/usr/include -I/usr/include/bpf \
 *     -c aegis_probe.c -o aegis_probe.bpf.o
 */

#include <linux/bpf.h>
#include <linux/bpf_perf_event.h>
#include <linux/btf.h>
#include <linux/errno.h>
#include <linux/filter.h>
#include <linux/kernel.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <net/sock.h>
#include <uapi/linux/limits.h>
#include <uapi/linux/mman.h>
#include <uapi/linux/mount.h>
#include <uapi/linux/net.h>
#include <uapi/linux/openat2.h>
#include <uapi/linux/prctl.h>
#include <uapi/linux/socket.h>
#include <uapi/linux/stat.h>
#include <uapi/linux/syscall.h>
#include <uapi/linux/uio.h>
#include <uapi/linux/unistd.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/* Maximum path length to capture */
#define MAX_PATH_LEN 256
#define MAX_ENDPOINT_LEN 128

/* Action types - must match attestation.py */
#define ACTION_FILE_READ      1
#define ACTION_FILE_WRITE     2
#define ACTION_NETWORK_CONN   3
#define ACTION_TOOL_INVOKE    4

/* Event structure sent to userspace via ring buffer */
struct aegis_event {
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

/* Per-agent state tracking */
struct agent_state {
    __u64 agent_id;
    __u64 session_id;
    __u64 job_id;           /* Slurm job ID if available */
    __u64 file_read_bytes;
    __u64 file_write_bytes;
    __u64 network_egress_bytes;
    __u64 connection_count;
    __u64 last_update;
    __u8 tracked;           /* 1 if this PID is being tracked */
};

/* Global state: keyed by PID */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct agent_state);
    __uint(max_entries, 2048);
} aegis_agent_states SEC(".maps");

/* Ring buffer for event delivery */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 128 * 1024);  /* 128KB ring buffer */
} aegis_events SEC(".maps");

/* Configuration map (set from userspace) */
struct aegis_config {
    __u64 sample_rate;          /* Sample every N syscalls */
    __u64 enable_network;       /* Enable network monitoring */
    __u64 enable_file;          /* Enable file monitoring */
    __u64 enable_exec;          /* Enable exec monitoring */
    __u64 monitor_uid;          /* Only track this UID (0 = all) */
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct aegis_config);
    __uint(max_entries, 1);
} aegis_config SEC(".maps");

/* Get current timestamp */
static __always_inline __u64 get_timestamp(void)
{
    return bpf_ktime_get_ns();
}

/* Read string from user memory safely */
static __always_inline long 
read_user_string(char *dst, const char __user *src, int max_len)
{
    int len = 0;
    char c;
    
    #pragma unroll
    for (int i = 0; i < max_len; i++) {
        if (bpf_probe_read_user(&c, 1, src + i) != 0)
            break;
        dst[i] = c;
        if (c == 0)
            break;
        len++;
    }
    dst[max_len - 1] = 0;
    return len;
}

/* Get process info */
static __always_inline void
get_process_info(__u32 *pid, __u32 *tid, __u32 *uid)
{
    struct task_struct *task = bpf_get_current_task();
    *pid = BPF_CORE_READ(task, pid);
    *tid = BPF_CORE_READ(task, tid);
    *uid = BPF_CORE_READ(task, cred->uid.val);
}

/* Emit event to ring buffer */
static __always_inline long
emit_event(__u32 action_type, __u64 size, 
           const char *path, const char *endpoint, __u32 port)
{
    __u32 pid, tid, uid;
    get_process_info(&pid, &tid, &uid);
    
    /* Check config - should we track this? */
    __u32 key = 0;
    struct aegis_config *cfg = bpf_map_lookup_elem(&aegis_config, &key);
    if (cfg && cfg->monitor_uid != 0 && cfg->monitor_uid != uid)
        return 0;
    
    struct aegis_event *event = bpf_ringbuf_reserve(&aegis_events, 
                                                      sizeof(struct aegis_event), 
                                                      0);
    if (!event)
        return 0;
    
    event->timestamp = get_timestamp();
    event->pid = pid;
    event->tid = tid;
    event->uid = uid;
    event->action_type = action_type;
    event->size = size;
    event->endpoint_port = port;
    
    if (path)
        bpf_probe_read_kernel_str(event->path, MAX_PATH_LEN, path);
    if (endpoint)
        bpf_probe_read_kernel_str(event->endpoint, MAX_ENDPOINT_LEN, endpoint);
    
    bpf_ringbuf_submit(event, 0);
    return 0;
}

/* Update agent state */
static __always_inline void
update_agent_state(__u32 pid, __u64 read_bytes, __u64 write_bytes, 
                   __u64 net_bytes, int conn)
{
    struct agent_state *state = bpf_map_lookup_elem(&aegis_agent_states, &pid);
    if (!state) {
        struct agent_state new_state = {
            .agent_id = 0,
            .session_id = 0,
            .job_id = 0,
            .file_read_bytes = 0,
            .file_write_bytes = 0,
            .network_egress_bytes = 0,
            .connection_count = 0,
            .last_update = get_timestamp(),
            .tracked = 1,
        };
        bpf_map_update_elem(&aegis_agent_states, &pid, &new_state, BPF_ANY);
        state = bpf_map_lookup_elem(&aegis_agent_states, &pid);
    }
    
    if (state) {
        state->file_read_bytes += read_bytes;
        state->file_write_bytes += write_bytes;
        state->network_egress_bytes += net_bytes;
        if (conn)
            state->connection_count += 1;
        state->last_update = get_timestamp();
    }
}

/* ============================================================
 * SYSCALL HOOKS
 * ============================================================ */

/* Trace: sys_openat / sys_openat2 */
SEC("tp/syscalls/sys_enter_openat")
int trace_sys_enter_openat(struct pt_regs *ctx)
{
    /* Check config */
    __u32 key = 0;
    struct aegis_config *cfg = bpf_map_lookup_elem(&aegis_config, &key);
    if (cfg && !cfg->enable_file)
        return 0;
    
    /* Get flags - determine if this is a read or write */
    int flags = PT_REGS_PARM2(ctx);
    int mode = PT_REGS_PARM3(ctx);
    
    /* Get filename */
    const char __user *filename = (const char __user *)PT_REGS_PARM1(ctx);
    char path[MAX_PATH_LEN];
    read_user_string(path, filename, MAX_PATH_LEN);
    
    /* Determine action type based on flags */
    __u32 action = ACTION_FILE_READ;
    if (flags & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC))
        action = ACTION_FILE_WRITE;
    
    /* Emit event */
    emit_event(action, 0, path, NULL, 0);
    
    /* Update state */
    update_agent_state(bpf_get_current_pid_tgid() >> 32, 
                       action == ACTION_FILE_READ ? 4096 : 0,
                       action == ACTION_FILE_WRITE ? 4096 : 0,
                       0, 0);
    
    return 0;
}

/* Trace: sys_connect */
SEC("tp/syscalls/sys_enter_connect")
int trace_sys_enter_connect(struct pt_regs *ctx)
{
    /* Check config */
    __u32 key = 0;
    struct aegis_config *cfg = bpf_map_lookup_elem(&aegis_config, &key);
    if (cfg && !cfg->enable_network)
        return 0;
    
    /* Get socket descriptor and address */
    int sockfd = PT_REGS_PARM1(ctx);
    struct sockaddr __user *addr = (struct sockaddr __user *)PT_REGS_PARM2(ctx);
    
    /* Read sockaddr - we only care about AF_INET/AF_INET6 */
    struct sockaddr_in addr_in;
    bpf_probe_read_user(&addr_in, sizeof(addr_in), addr);
    
    /* Only track IP connections */
    if (addr_in.sin_family != AF_INET && addr_in.sin_family != AF_INET6)
        return 0;
    
    /* Convert IP to string */
    char endpoint[MAX_ENDPOINT_LEN];
    __u32 port = 0;
    
    if (addr_in.sin_family == AF_INET) {
        __u8 *ip = (__u8 *)&addr_in.sin_addr.s_addr;
        bpf_probe_read_kernel(endpoint, MAX_ENDPOINT_LEN, ip);
        port = bpf_ntohs(addr_in.sin_port);
    }
    
    /* Emit network connection event */
    emit_event(ACTION_NETWORK_CONN, 0, NULL, endpoint, port);
    
    /* Update state */
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    update_agent_state(pid, 0, 0, 0, 1);
    
    return 0;
}

/* Trace: sys_execve */
SEC("tp/syscalls/sys_enter_execve")
int trace_sys_enter_execve(struct pt_regs *ctx)
{
    /* Check config */
    __u32 key = 0;
    struct aegis_config *cfg = bpf_map_lookup_elem(&aegis_config, &key);
    if (cfg && !cfg->enable_exec)
        return 0;
    
    /* Get executable path */
    const char __user *filename = (const char __user *)PT_REGS_PARM1(ctx);
    char path[MAX_PATH_LEN];
    read_user_string(path, filename, MAX_PATH_LEN);
    
    /* Skip common non-tool executables */
    if (bpf_strncmp(path, 5, "/proc") == 0 ||
        bpf_strncmp(path, 4, "/dev") == 0 ||
        bpf_strncmp(path, 7, "/sys/k") == 0)
        return 0;
    
    /* Emit tool invocation event */
    emit_event(ACTION_TOOL_INVOKE, 0, path, NULL, 0);
    
    return 0;
}

/* Trace: sys_read (to track actual bytes read) */
SEC("tp/syscalls/sys_enter_read")
int trace_sys_enter_read(struct pt_regs *ctx)
{
    /* Check config */
    __u32 key = 0;
    struct aegis_config *cfg = bpf_map_lookup_elem(&aegis_config, &key);
    if (cfg && !cfg->enable_file)
        return 0;
    
    /* Get read size */
    int fd = PT_REGS_PARM1(ctx);
    size_t count = PT_REGS_PARM3(ctx);
    
    if (count == 0 || count > (1 << 20))  /* Sanity check */
        return 0;
    
    /* Update read bytes in state */
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    update_agent_state(pid, count, 0, 0, 0);
    
    return 0;
}

/* Trace: sys_write (to track actual bytes written) */
SEC("tp/syscalls/sys_enter_write")
int trace_sys_enter_write(struct pt_regs *ctx)
{
    /* Check config */
    __u32 key = 0;
    struct aegis_config *cfg = bpf_map_lookup_elem(&aegis_config, &key);
    if (cfg && !cfg->enable_file)
        return 0;
    
    /* Get write size */
    int fd = PT_REGS_PARM1(ctx);
    size_t count = PT_REGS_PARM2(ctx);
    
    if (count == 0 || count > (1 << 20))  /* Sanity check */
        return 0;
    
    /* Update write bytes in state */
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    update_agent_state(pid, 0, count, 0, 0);
    
    return 0;
}

/* Trace: sys_sendto / sys_send (to track network egress) */
SEC("tp/syscalls/sys_enter_sendto")
int trace_sys_enter_sendto(struct pt_regs *ctx)
{
    /* Check config */
    __u32 key = 0;
    struct aegis_config *cfg = bpf_map_lookup_elem(&aegis_config, &key);
    if (cfg && !cfg->enable_network)
        return 0;
    
    /* Get send size */
    size_t len = PT_REGS_PARM2(ctx);
    
    if (len == 0 || len > (1 << 26))  /* Sanity check, max 64MB */
        return 0;
    
    /* Update network egress in state */
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    update_agent_state(pid, 0, 0, len, 0);
    
    return 0;
}

/* License - required for eBPF */
char _license[] SEC("license") = "GPL";