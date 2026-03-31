# Attack Modules

`src/attacks/` contains the synthetic attack workloads used by the evaluation.

These modules are not deployed on a cluster. They exist so the paper experiments can exercise:
- filesystem-mediated injection
- co-location attacks on shared storage
- supply-chain-style tool compromise
- coordinated cross-agent exfiltration
- ablation-specific detector isolation cases
