# Defense Modules

`src/defense/` contains both the active Slurm enforcement path and older evaluation helpers.

## Active Deployment Path

- `slurm_integration.py`: Slurm-oriented containment actions for throttling, ACL isolation, suspension, termination, and credential cleanup

## Evaluation Compatibility Layer

- `attestation.py`: older experiment-only detection engine used by several synthetic runners
- `baseline_comparison.py`: comparative baseline logic for the paper evaluation

For deployment, prefer `src/framework/verifier.py` plus `src/services/verifierd.py`.
