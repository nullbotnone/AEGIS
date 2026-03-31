# AEGIS Framework

`src/framework/` is the policy and verification core. It matches the current paper architecture, but it is not a full cluster deployment by itself.

## Modules

- `constraints.py`: behavioral constraint profiles, derivation modes, template support, signing, and Slurm job binding
- `attestation.py`: evidence bundle model and interval-based evidence generation semantics
- `verifier.py`: centralized verification, random challenges, cross-agent correlation, and the integrated tamper-evident audit ledger
- `containment.py`: framework-level mapping from verdicts to throttling, ACL isolation, suspension, and termination
- `policy_engine.py`: in-process orchestration used by tests and simulation-friendly workflows
- `agent_monitor.py`: bridge that converts simulated agent actions into framework events for measured framework-path experiments

## Relationship To Deployment

Real deployment wraps this package with:
- [bpf_collector.py](../attestation/bpf_collector.py)
- [verifierd.py](../services/verifierd.py)
- [slurm_integration.py](../defense/slurm_integration.py)

## Tests

```bash
python3 -m unittest discover -s src/framework/tests -v
```
