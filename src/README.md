# AEGIS: Behavioral Attestation for AI Agents in HPC Environments

This codebase implements experimental demonstrations of four HPC-specific injection attack vectors against AI agents, along with a behavioral attestation defense mechanism.

## Project Structure

```
AEGIS/src/
├── README.md
├── requirements.txt
├── common/           # Core infrastructure (agent, filesystem, constraints, logging)
├── attacks/          # Four attack implementations
├── defense/          # Attestation engine
├── experiments/      # Experiment runners
└── data/             # Sample datasets
```

## Attacks Demonstrated

1. **Filesystem-Mediated Injection** — Adversarial content in shared filesystem hijacks agent behavior
2. **Multi-User Co-Location Injection** — Shared scratch spaces enable cross-agent attacks
3. **Supply Chain Injection** — Compromised agent tools/skills inject adversarial instructions
4. **Coordinated Multi-Agent Exfiltration** — Multiple hijacked agents form covert exfiltration networks

## Running Experiments

```bash
cd /home/artlands/.openclaw/workspace/AEGIS/src
python experiments/run_all.py
```

Or run individual experiments:
```bash
python experiments/run_attack1.py
python experiments/run_attack2.py
python experiments/run_attack3.py
python experiments/run_attack4.py
```

## Requirements

- Python 3.8+
- PyYAML

## Citation

This code accompanies the AEGIS paper on behavioral attestation for AI agents in HPC environments.
