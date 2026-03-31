# Node Attestation

`src/attestation/` contains the node-side pieces that turn observed syscall activity into verifier-consumable evidence.

## Active Files

- `bpf_collector.py`: userspace collector for the eBPF probe, including Slurm job binding, evidence signing, submission, and spooling
- `job_registry.py`: file-backed registration interface used by Slurm Prolog and Epilog hooks
- `bpf_attach.py`: attach-only helper for direct kernel/eBPF overhead measurement

## Current Architecture

Cluster-wide correlation is owned by the centralized verifier in `src/framework/verifier.py`. There is no separate coordinator service in the current deployment path.
