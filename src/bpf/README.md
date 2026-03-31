# eBPF Sources

`src/bpf/` contains the kernel-side monitoring path and the userspace workload used for direct overhead measurement.

## Files

- `aegis_probe.c`: syscall probe source
- `syscall_microbench.c`: paired workload for direct kernel/eBPF benchmarking

## Build

```bash
make bpfall
make bench
```

The build products are intentionally not committed.
