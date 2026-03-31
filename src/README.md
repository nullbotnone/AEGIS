# AEGIS Source Tree

`src/` contains both the deployable AEGIS path and the simulation code kept for evaluation reproducibility.

## Deployable Path

- `framework/`: constraint manager, evidence model, verifier, containment mapping, and verifier-owned audit ledger
- `attestation/`: node-side collector and Slurm job registration
- `bpf/`: kernel probe and syscall microbenchmark
- `services/`: long-running verifier daemon wrapper
- `defense/slurm_integration.py`: enforcement bridge for Slurm actions

## Evaluation And Legacy Support

- `experiments/`: paper evaluation entry points
- `attacks/`: synthetic attack workloads used by the experiments
- `common/`: older simulation primitives still required by several experiment runners
- `defense/attestation.py`: older experiment-only detection engine kept for reproducibility
- `data/`: synthetic datasets for deterministic experiments

## Important Distinction

For a real cluster, the active entry points are:
- `python3 -m src.services.verifierd`
- `python3 -m src.attestation.bpf_collector`
- `make bpfall`

For the paper evaluation, the active entry points are under `src/experiments/`.

## Local READMEs

Use the local README in each major subdirectory for code-level orientation. The subdirectory docs call out whether a module is part of deployment, paper evaluation, or a legacy compatibility layer.
