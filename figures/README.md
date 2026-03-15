# AEGIS Paper Figures

Generated for the AEGIS research paper on AI agent security in HPC environments.

## Directory Structure

```
figures/
├── README.md                    # This file
├── paper_figures.ipynb          # Jupyter notebook for data visualizations
├── captions/                    # Figure caption text files
│   ├── aegis_architecture.txt
│   ├── threat_model.txt
│   ├── injection_surfaces.txt
│   ├── constraint_dimensions.txt
│   ├── baseline_comparison.txt
│   ├── ablation_heatmap.txt
│   ├── attack_results.txt
│   ├── performance_overhead.txt
│   └── detection_radar.txt
└── *.png                        # Figure images (300 DPI)
```

## Architecture & Threat Model Diagrams

### Figure 1: `aegis_architecture.png`
**AEGIS System Architecture.** The framework comprises four core components: (1) Attestation Engine, deployed on each compute node with eBPF probes for runtime monitoring; (2) Policy Verifier, a centralized component that evaluates evidence against security policies; (3) Containment Enforcer, which executes containment actions via the Slurm REST API; and (4) Constraint Manager, which maintains per-agent security constraints. The Audit Ledger provides an append-only, hash-chained log of all security events. Data flows from the Agent Runtime through eBPF probes to the Attestation Engine, which transmits evidence via gRPC to the Policy Verifier for verdict generation.

### Figure 2: `threat_model.png`
**Hijacked Agent Threat Model.** A legitimate AI agent possessing valid credentials—Kerberos ticket, SSH key, and RBAC badge—is targeted by four injection vectors: filesystem-mediated injection through shared storage, co-location attacks via shared compute nodes, supply chain compromise through trusted tools, and network-based injection. Once hijacked, the agent exfiltrates data through an encrypted LLM API channel that is opaque to traditional DLP and IDS systems.

### Figure 3: `injection_surfaces.png`
**HPC Injection Attack Surfaces.** Four attack vectors exploit HPC shared infrastructure: (1) Filesystem-mediated attack via poisoned HDF5 on shared Lustre/GPFS storage; (2) Co-location attack through shared /tmp directory; (3) Supply chain attack via compromised data_converter tool; (4) Coordinated multi-node attack writing to shared /.cache/ and exfiltrating via LLM API.

### Figure 4: `constraint_dimensions.png`
**AEGIS Constraint Dimensions.** Five orthogonal constraint dimensions: Data Access (paths, volumes), Network (endpoints, egress), Tool Invocation (allowed/denied), Execution (runtime, memory, nodes), and Data Flow (project boundaries, exfiltration budget). Each dimension is continuously monitored by the Attestation Engine and evaluated by the Policy Verifier.

## Data Visualization Plots

### Figure 5: `baseline_comparison.png`
**Baseline Defense Comparison.** Detection rates for HPC-specific attacks across five defense mechanisms (§5.2). Network DLP and per-agent analytics achieve 0% detection. Filesystem auditing and sandboxing provide partial coverage (50%). AEGIS achieves 100% detection across all attack vectors.

### Figure 6: `ablation_heatmap.png`
**Ablation Study Results.** Detection matrix showing the impact of removing individual AEGIS components (§5.4). Full AEGIS detects all attack types. Each removed component causes specific detection failures. The minimal configuration detects nothing, confirming all components are necessary.

### Figure 7: `attack_results.png`
**Attack Experiment Results.** Summary of four attack experiments (§5.1). Basic attacks exfiltrated 68 and 50 bytes with 1 detection each. Advanced attacks exfiltrated 519 and 521 bytes, triggering 7 detections each as multiple constraint violations were observed.

### Figure 8: `performance_overhead.png`
**Performance Overhead Analysis.** Overhead and attestation latency vs. interval (§5.3). At 1s intervals: 1.5% overhead with 500ms latency. The 1-second interval offers the best balance between detection timeliness and performance impact.

### Figure 9: `detection_radar.png`
**Defense Capability Radar Chart.** Comparative analysis across five attack categories. AEGIS provides comprehensive coverage across all dimensions while baseline defenses show significant gaps.

## Style Notes

- All PNG figures saved at 300 DPI for print quality
- Color palette: Green (#27ae60) for positive/effective, Red (#e74c3c) for threats/missed, Orange (#f39c12) for partial, Blue (#2980b9) and Teal (#16a085) for neutral/data
- Font: sans-serif, optimized for readability at small sizes
- Academic paper style suitable for IEEE/ACM publication

## Regenerating Figures

Architecture diagrams were generated using Gemini 3 Pro Image (nano-banana-pro):
```bash
uv run ~/.nvm/versions/node/v22.22.0/lib/node_modules/openclaw/skills/nano-banana-pro/scripts/generate_image.py --prompt "..." --filename "output.png" --resolution 2K --aspect-ratio 16:9
```

Data visualization plots were generated from `paper_figures.ipynb`:
```bash
jupyter nbconvert --to notebook --execute paper_figures.ipynb --output paper_figures.ipynb
```
