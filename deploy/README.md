# Deployment

`deploy/` contains the files needed to install AEGIS on a Slurm cluster.

## Files

- `systemd/aegis-verifier.service`: verifier host service unit
- `systemd/aegis-collector.service`: compute-node collector service unit
- `slurm/prolog/10-aegis-register.sh`: job-registration hook
- `slurm/epilog/10-aegis-cleanup.sh`: job-cleanup hook
- `config/verifier.example.json`: verifier configuration template
- `config/collector.example.env`: collector environment template

## Install Order

1. Build the probe with `make bpfall` and optionally `make bench`.
2. Install the verifier host service and config.
3. Install the collector service and probe object on every compute node.
4. Install the Slurm Prolog and Epilog hooks.
5. Register constraint profiles on the shared filesystem that both Slurm hooks and the verifier can read.

## Main Commands

Verifier host:

```bash
python3 -m src.services.verifierd --config /etc/aegis/verifier.json serve
```

Collector node:

```bash
sudo python3 -m src.attestation.bpf_collector --bpf /usr/share/aegis/aegis_probe.bpf.o --interval 1.0
```

Use [docs/REAL_CLUSTER_DEPLOYMENT.md](../docs/REAL_CLUSTER_DEPLOYMENT.md) for the full rollout procedure.
