# Sample Datasets for AEGIS Experiments

These datasets are used by the AEGIS experimental evaluation to provide realistic data for attack demonstrations and defense evaluation.

## Directory Structure

```
sample_datasets/
├── shared/           # Shared project directory (Exp 1, Exp 3, Exp 4)
│   ├── dataset.h5    # HDF5-like binary dataset (80 KB)
│   └── secrets.txt   # Sensitive credentials file (406 B)
├── genomics/         # Genomics project (Exp 3, Benign workflow)
│   ├── sample_001.h5         # Whole genome sequencing sample (80 KB)
│   ├── reference.fasta.h5    # Reference genome (80 KB)
│   └── metadata.csv          # Sample metadata (100 rows)
├── finance/          # Finance project (Exp 4)
│   ├── quarterly_earnings.csv   # Quarterly earnings data (500 rows, 23 KB)
│   └── trading_positions.csv    # Trading positions (200 rows, 8.7 KB)
├── ml/               # ML project (Benign workflow)
│   ├── train_features.csv   # Training features (1000 rows, 42 KB)
│   └── model_config.yaml    # Model configuration
└── physics/          # Physics simulation (Benign workflow)
    ├── simulation_output.vtk.dat  # Simulation output (131 KB)
    └── sim_params.yaml            # Simulation parameters
```

## Dataset Details

### shared/dataset.h5
- **Used by:** Exp 1 (Filesystem Injection), Exp 3 (Supply Chain)
- **Format:** HDF5-like with header metadata and float64 binary data
- **Dimensions:** 5000 × 128
- **Contains:** Instrument measurement data (synthetic)

### shared/secrets.txt
- **Used by:** Exp 1 (Filesystem Injection)
- **Format:** Plain text with key-value pairs
- **Contains:** API keys, database credentials, service tokens (synthetic)

### genomics/sample_001.h5
- **Used by:** Exp 3 (Supply Chain), Benign workflow
- **Format:** HDF5-like binary
- **Dimensions:** 10000 × 64
- **Contains:** Whole genome sequencing data (synthetic)

### finance/quarterly_earnings.csv
- **Used by:** Exp 4 (Coordinated Exfiltration)
- **Format:** CSV with headers
- **Rows:** 500
- **Columns:** company_id, ticker, revenue, net_income, eps, report_date

## Reproducing Experiments

All experiments use these datasets. To reproduce:

```bash
# Generate datasets
cd AEGIS/src
python3 data/generate_datasets.py

# Run all attack experiments
python3 experiments/run_all.py

# Run baseline comparison
python3 experiments/run_baseline_comparison.py

# Run false positive analysis
python3 experiments/run_false_positive.py

# Run ablation study
python3 experiments/run_ablation_v2.py
```

## Data Provenance

All data is synthetically generated for research purposes. No real credentials, financial data, or personal information is included.
