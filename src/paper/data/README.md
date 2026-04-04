# Data Utilities

`src/paper/data/` contains dataset-generation helpers and the synthetic inputs consumed by the experiment runners.

## Contents

- `generate_datasets.py`: regenerate checked-in synthetic inputs
- `sample_datasets/`: deterministic stand-ins for shared HPC project data

These datasets exist for evaluation reproducibility. They are not needed to deploy the verifier or collector.
