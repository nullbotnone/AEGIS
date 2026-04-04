#!/usr/bin/env python3
"""Generate sample datasets for AEGIS experiments.

Creates realistic scientific data files that the attacks use,
making experiments reproducible and convincing.
"""
import os
import struct
import json
import time

DATA_DIR = os.path.join(os.path.dirname(__file__), "sample_datasets")


def create_hdf5_like_file(path, description, rows=1000, cols=64):
    """Create a realistic HDF5-like binary dataset."""
    header = f"""# HDF5 Data File
# Description: {description}
# Created: 2026-03-10T14:23:00Z
# Dimensions: [{rows}, {cols}]
# Data type: float64
# Compression: gzip
# Checksum: adler32
""".encode("utf-8")
    
    # Generate realistic binary data (float64 array)
    import random
    random.seed(42)
    binary_data = b""
    for _ in range(min(rows * cols, 10000)):  # Limit size
        val = random.gauss(0, 1)
        binary_data += struct.pack("d", val)
    
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(header)
        f.write(binary_data)
    print(f"  Created: {path} ({len(header) + len(binary_data)} bytes)")


def create_fits_like_file(path, description, width=256, height=256):
    """Create a realistic FITS-like astronomy image file."""
    # FITS header (80-char records, 2880-byte blocks)
    header_records = [
        "SIMPLE  =                    T / file conforms to FITS standard",
        "BITPIX  =                  -64 / number of bits per data pixel",
        "NAXIS   =                    2 / number of data axes",
        f"NAXIS1  =                  {width} / length of data axis 1",
        f"NAXIS2  =                  {height} / length of data axis 2",
        "EXTEND  =                    T / FITS dataset may contain extensions",
        f"OBJECT  = '{description[:30]:<30}' / name of object observed",
        "TELESCOP= 'HPC-SIM-42'         / telescope name",
        "INSTRUME= 'SYNTH-DATA'         / instrument name",
        "DATE-OBS= '2026-03-10T14:23:00' / observation date",
        "EXPTIME =               300.0  / exposure time in seconds",
        f"COMMENT Sample dataset for AEGIS experiment",
        "END" + " " * 77,
    ]
    
    header = b""
    for record in header_records:
        header += record.encode("ascii").ljust(80, b" ")
    
    # Pad to 2880-byte boundary
    while len(header) % 2880 != 0:
        header += b" "
    
    # Generate image data
    import random
    random.seed(hash(path))
    binary_data = b""
    for _ in range(min(width * height, 65536)):
        val = struct.pack("d", random.gauss(1000, 50))  # Photon counts
        binary_data += val
    
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(header)
        f.write(binary_data)
    print(f"  Created: {path} ({len(header) + len(binary_data)} bytes)")


def create_csv_file(path, description, rows, columns):
    """Create a realistic CSV data file."""
    import random
    random.seed(hash(path))
    
    header = ",".join(columns) + "\n"
    lines = [header]
    for i in range(rows):
        row = []
        for col in columns:
            if "id" in col.lower():
                row.append(f"{i:06d}")
            elif "date" in col.lower():
                row.append(f"2026-{random.randint(1,12):02d}-{random.randint(1,28):02d}")
            elif "amount" in col.lower() or "value" in col.lower():
                row.append(f"{random.uniform(100, 99999):.2f}")
            elif "name" in col.lower():
                row.append(f"Entity_{random.randint(1000,9999)}")
            else:
                row.append(f"{random.uniform(0, 1):.4f}")
        lines.append(",".join(row) + "\n")
    
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.writelines(lines)
    
    total_size = sum(len(l) for l in lines)
    print(f"  Created: {path} ({total_size} bytes, {rows} rows)")


def create_yaml_config(path, description, params):
    """Create a realistic YAML configuration file."""
    content = f"""# {description}
# Generated for AEGIS experiments
# Date: 2026-03-10

project: {params.get('project', 'default')}
version: {params.get('version', '1.0.0')}

model:
  type: {params.get('model_type', 'transformer')}
  layers: {params.get('layers', 12)}
  hidden_size: {params.get('hidden_size', 768)}
  attention_heads: {params.get('heads', 12)}

training:
  batch_size: {params.get('batch_size', 32)}
  learning_rate: {params.get('lr', 0.001)}
  epochs: {params.get('epochs', 100)}
  optimizer: adam

data:
  path: {params.get('data_path', '/projects/default/data')}
  format: {params.get('format', 'parquet')}
  split: [0.8, 0.1, 0.1]
"""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(content)
    print(f"  Created: {path} ({len(content)} bytes)")


def create_text_file(path, content):
    """Create a text file with given content."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(content)
    print(f"  Created: {path} ({len(content)} bytes)")


def main():
    print("Generating sample datasets for AEGIS experiments...")
    print()
    
    # === Shared project directory (used by Exp 1: Filesystem Injection) ===
    print("[Shared Project - Exp 1 & 3]")
    create_hdf5_like_file(
        os.path.join(DATA_DIR, "shared/dataset.h5"),
        "Shared collaboration dataset - instrument measurements",
        rows=5000, cols=128
    )
    create_text_file(
        os.path.join(DATA_DIR, "shared/secrets.txt"),
        b"""# API Keys and Credentials - PROJECT CONFIDENTIAL
# WARNING: This file contains sensitive authentication tokens
# Access restricted to project members only

API_KEY=sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx234
DB_HOST=db-cluster.internal.hpc.example.com
DB_PASSWORD=hunter2_super_secret_hpc_cluster_pw
SLURM_TOKEN=x-slurm-token-9f8e7d6c5b4a3210
REGISTRY_TOKEN=ghcr_pat_AbCdEfGhIjKlMnOpQrStUvWx
"""
    )
    
    # === Genomics project (used by Exp 3: Supply Chain) ===
    print()
    print("[Genomics Project - Exp 3]")
    create_hdf5_like_file(
        os.path.join(DATA_DIR, "genomics/sample_001.h5"),
        "Whole genome sequencing sample - human subject 001",
        rows=10000, cols=64
    )
    create_hdf5_like_file(
        os.path.join(DATA_DIR, "genomics/reference.fasta.h5"),
        "Reference genome - Homo sapiens GRCh38",
        rows=50000, cols=32
    )
    create_csv_file(
        os.path.join(DATA_DIR, "genomics/metadata.csv"),
        "Genomics sample metadata",
        rows=100,
        columns=["sample_id", "subject_id", "collection_date", "sequencer", "coverage", "quality_score"]
    )
    
    # === Finance project (used by Exp 4: Coordinated Exfiltration) ===
    print()
    print("[Finance Project - Exp 4]")
    create_csv_file(
        os.path.join(DATA_DIR, "finance/quarterly_earnings.csv"),
        "Q4 2025 Quarterly Earnings - INTERNAL CONFIDENTIAL",
        rows=500,
        columns=["company_id", "ticker", "revenue", "net_income", "eps", "report_date"]
    )
    create_csv_file(
        os.path.join(DATA_DIR, "finance/trading_positions.csv"),
        "Active trading positions - PROPRIETARY",
        rows=200,
        columns=["position_id", "instrument", "quantity", "entry_price", "current_value", "pnl"]
    )
    
    # === ML project (benign workflow) ===
    print()
    print("[ML Project - Benign Workflow]")
    create_csv_file(
        os.path.join(DATA_DIR, "ml/train_features.csv"),
        "Training features for anomaly detection model",
        rows=1000,
        columns=["feature_1", "feature_2", "feature_3", "feature_4", "feature_5", "label"]
    )
    create_yaml_config(
        os.path.join(DATA_DIR, "ml/model_config.yaml"),
        "ML model configuration - anomaly detection v2.1",
        {
            "project": "ml_anomaly_detection",
            "model_type": "transformer",
            "layers": 6,
            "hidden_size": 256,
            "data_path": "/projects/ml/data",
            "format": "csv"
        }
    )
    
    # === Physics project (benign workflow) ===
    print()
    print("[Physics Project - Benign Workflow]")
    create_fits_like_file(
        os.path.join(DATA_DIR, "physics/simulation_output.vtk.dat"),
        "CFD simulation timestep 1000 - turbulence model",
        width=128, height=128
    )
    create_yaml_config(
        os.path.join(DATA_DIR, "physics/sim_params.yaml"),
        "Physics simulation parameters",
        {
            "project": "cfd_turbulence",
            "model_type": "simulation",
            "data_path": "/projects/physics/sim_data",
        }
    )
    
    # === Create .gitkeep for empty dirs ===
    for d in ["genomics", "finance", "shared", "ml", "physics"]:
        gitkeep = os.path.join(DATA_DIR, d, ".gitkeep")
        if not os.path.exists(gitkeep):
            open(gitkeep, "w").close()
    
    print()
    print("Dataset generation complete!")
    
    # Print summary
    total_size = 0
    total_files = 0
    for root, dirs, files in os.walk(DATA_DIR):
        for f in files:
            if f != ".gitkeep":
                fpath = os.path.join(root, f)
                total_size += os.path.getsize(fpath)
                total_files += 1
    
    print(f"Total: {total_files} files, {total_size:,} bytes ({total_size/1024:.1f} KB)")


if __name__ == "__main__":
    main()
