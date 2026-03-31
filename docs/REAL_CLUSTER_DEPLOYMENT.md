# AEGIS Real Cluster Deployment

This guide describes the current deployable AEGIS path for a Slurm cluster.

## Architecture

AEGIS is deployed as four operational pieces:
- verifier daemon on a controller or management host
- node-local collector on each compute node
- eBPF probe attached by the collector
- Slurm Prolog and Epilog hooks that bind jobs to constraint profiles

The centralized verifier owns:
- constraint profile registration
- evidence verification
- random challenge issuance
- cluster-wide access graph correlation
- covert-channel detection
- audit logging
- Slurm containment decisions

## Required Files

Verifier side:
- `src/services/verifierd.py`
- `src/framework/constraints.py`
- `src/framework/verifier.py`
- `src/defense/slurm_integration.py`
- `deploy/systemd/aegis-verifier.service`
- `deploy/config/verifier.example.json`

Compute-node side:
- `src/attestation/bpf_collector.py`
- `src/attestation/job_registry.py`
- `src/bpf/aegis_probe.c`
- compiled `aegis_probe.bpf.o`
- `deploy/systemd/aegis-collector.service`
- `deploy/config/collector.example.env`

Slurm side:
- `deploy/slurm/prolog/10-aegis-register.sh`
- `deploy/slurm/epilog/10-aegis-cleanup.sh`

## Deployment Steps

### 1. Build

From the repository root:

```bash
make bpfall
make bench
```

### 2. Install the verifier host

1. Copy the repo to `/opt/aegis`.
2. Create the `aegis` service account.
3. Install `deploy/systemd/aegis-verifier.service` as `/etc/systemd/system/aegis-verifier.service`.
4. Copy `deploy/config/verifier.example.json` to `/etc/aegis/verifier.json`.
5. Set real values for:
   - `listen_host`
   - `listen_port`
   - `profiles_dir`
   - `audit_dir`
   - `slurm_url`
   - `profile_signing_key`
   - `evidence_signing_key`
6. Enable the service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now aegis-verifier.service
```

### 3. Install compute-node collectors

1. Copy the repo to `/opt/aegis` on each compute node.
2. Install the BPF object at `/usr/share/aegis/aegis_probe.bpf.o`.
3. Install `deploy/systemd/aegis-collector.service` as `/etc/systemd/system/aegis-collector.service`.
4. Copy `deploy/config/collector.example.env` to `/etc/aegis/collector.env`.
5. Set:
   - `AEGIS_COLLECTOR_KEY`
   - `AEGIS_VERIFIER_HOST`
   - `AEGIS_VERIFIER_PORT` or `AEGIS_VERIFIER_SOCKET`
   - optional spool directory and submission timeout
6. Enable the service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now aegis-collector.service
```

### 4. Install Slurm hooks

Install the supplied hook scripts:

```bash
sudo install -m 0755 deploy/slurm/prolog/10-aegis-register.sh /etc/slurm/prolog.d/10-aegis-register.sh
sudo install -m 0755 deploy/slurm/epilog/10-aegis-cleanup.sh /etc/slurm/epilog.d/10-aegis-cleanup.sh
```

Set the required environment or site defaults so the hooks can resolve:
- `AEGIS_ROOT`
- `AEGIS_VERIFIER_HOST`
- `AEGIS_VERIFIER_SOCKET`
- `AEGIS_PROFILE_ROOT`
- `AEGIS_REGISTRY_DIR`

## Constraint Profile Workflow

Each job should have a YAML constraint profile visible at the shared `AEGIS_PROFILE_ROOT`. The Prolog script:
- binds `SLURM_JOB_ID` to an agent/session registration for the collector
- registers the same profile with the verifier

The Epilog script removes local registration state and closes the verifier-side session.

## Runtime Flow

1. Slurm starts a job.
2. Prolog writes the collector registration and registers the profile with the verifier.
3. The collector attaches the probe, observes syscalls, binds PIDs to job registrations, and emits signed evidence bundles.
4. The verifier checks the evidence against the bound profile, updates the access graph, logs to the audit ledger, and triggers containment if required.
5. Epilog tears down the registration when the job exits.

## Smoke Checks

Verifier health:

```bash
python3 -m src.services.verifierd --config /etc/aegis/verifier.json health
```

Collector CLI:

```bash
python3 -m src.attestation.bpf_collector --help
```

Framework tests:

```bash
python3 -m unittest discover -s src/framework/tests -v
```

## Transport Note

`proto/aegis.proto` defines the intended gRPC contract. The current repo ships a dependency-light bootstrap transport using a Unix socket for admin calls and JSON/TCP for evidence submission. Replace that transport with mTLS gRPC when you move from bootstrap deployment to hardened production rollout.
