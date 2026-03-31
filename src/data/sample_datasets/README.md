# Sample Datasets

`src/data/sample_datasets/` contains synthetic inputs for the evaluation workflows.

## Layout

- `shared/`: shared-storage traces used by filesystem-oriented attacks
- `genomics/`: benign genomics workflow inputs
- `finance/`: coordinated-exfiltration and policy-violation inputs
- `ml/`: benign ML workflow inputs
- `physics/`: benign simulation-steering inputs

## Regeneration

```bash
python3 -m src.data.generate_datasets
```

## Consumers

Common consumers include:
- `python3 -m src.experiments.simulated.run_all`
- `python3 -m src.experiments.simulated.run_false_positive`
- `python3 -m src.experiments.simulated.run_ablation`
