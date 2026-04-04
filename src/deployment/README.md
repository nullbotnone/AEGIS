# AEGIS Deployment Source

`src/deployment/` is the deployable AEGIS code path for real HPC clusters.

For the site-installation artifacts, also read:
- `deploy/README.md`
- `docs/REAL_CLUSTER_DEPLOYMENT.md`

## What Gets Deployed

AEGIS runs as four cooperating pieces:
- `control_plane/`: the centralized verifier daemon running on a management or controller host
- `collector/`: the node-local collector running on each compute node
- `bpf/`: the eBPF probe and syscall microbenchmark used by the collector
- `enforcement/`: the Slurm-backed containment path used by the verifier

The policy and verification logic shared by those components lives in:
- `core/`: constraint profiles, attestation models, verifier logic, containment mapping, and tests

## Package Map

- `core/`
  Purpose: the AEGIS policy engine and verification core.
  Main files:
  - `constraints.py`: profile schema, signing, compilation, YAML serialization
  - `attestation.py`: evidence bundle model and attestation semantics
  - `verifier.py`: verification logic, challenge handling, audit log, cross-agent correlation
  - `containment.py`: verdict-to-containment mapping
  - `tests/`: unit and integration coverage for the deployable core

- `control_plane/`
  Purpose: long-running verifier service.
  Main file:
  - `verifierd.py`: JSON-over-socket/TCP bootstrap daemon used by Slurm hooks and collectors

- `collector/`
  Purpose: node-side evidence collection.
  Main files:
  - `bpf_collector.py`: attaches the probe, reads events, binds them to Slurm jobs, emits evidence
  - `job_registry.py`: local registration store written by Slurm Prolog/Epilog
  - `bpf_attach.py`: attach-only helper used by low-level probe measurements

- `enforcement/`
  Purpose: containment actions against live Slurm jobs.
  Main file:
  - `slurm_integration.py`: Slurm REST and host-side containment helpers

- `bpf/`
  Purpose: kernel-side telemetry.
  Main files:
  - `aegis_probe.c`: eBPF probe source
  - `aegis_probe.bpf.o`: compiled probe object used by collectors
  - `syscall_microbench.c`: direct probe-overhead microbenchmark

## Deployment Topology

Verifier host:
- runs `python3 -m src.deployment.control_plane.verifierd`
- stores registered profiles and audit logs
- receives evidence from collectors
- issues containment decisions through `enforcement/slurm_integration.py`

Compute nodes:
- run `python3 -m src.deployment.collector.bpf_collector`
- load `bpf/aegis_probe.bpf.o`
- resolve PIDs to Slurm jobs through `collector/job_registry.py`
- submit evidence to the verifier

Slurm controller integration:
- Prolog registers a job/session/profile before work starts
- Epilog removes registration and closes the verifier-side session after the job exits

## Minimum Deployment Order

1. Build the eBPF artifacts from the repo root.
2. Install and start the verifier service on the management host.
3. Install the collector and probe on each compute node.
4. Install the Slurm Prolog/Epilog hooks.
5. Put per-job YAML constraint profiles on the shared profile path used by the hooks.
6. Run smoke checks before opening the deployment to users.

## Step-By-Step

### 1. Build the probe and benchmark

From the repository root:

```bash
make bpfall
make bench
```

Expected outputs:
- `src/deployment/bpf/aegis_probe.bpf.o`
- `src/deployment/bpf/syscall_microbench`

### 2. Install the verifier host

You need these source-side components:
- `src/deployment/control_plane/verifierd.py`
- `src/deployment/core/`
- `src/deployment/enforcement/slurm_integration.py`
- `deploy/systemd/aegis-verifier.service`
- `deploy/config/verifier.example.json`

Typical rollout:

```bash
python3 -m src.deployment.control_plane.verifierd --config /etc/aegis/verifier.json serve
```

The verifier config must point to real site values for:
- verifier listen address or socket
- profile storage directory
- audit log directory
- Slurm REST endpoint
- profile signing key
- evidence signing key

### 3. Install collectors on compute nodes

You need these source-side components:
- `src/deployment/collector/bpf_collector.py`
- `src/deployment/collector/job_registry.py`
- `src/deployment/bpf/aegis_probe.bpf.o`
- `deploy/systemd/aegis-collector.service`
- `deploy/config/collector.example.env`

Typical collector command:

```bash
sudo python3 -m src.deployment.collector.bpf_collector \
  --bpf /usr/share/aegis/aegis_probe.bpf.o \
  --interval 1.0 \
  --registry-dir /run/aegis/collector/registrations
```

Collector configuration must set:
- verifier host/port or verifier Unix socket
- evidence signing key
- registration directory
- optional spool directory when the verifier is unavailable

### 4. Install Slurm hooks

Hooks are the bridge between Slurm jobs and AEGIS sessions.

They must be able to find:
- `AEGIS_ROOT`: repo checkout or installed code root
- `AEGIS_VERIFIER_HOST` or `AEGIS_VERIFIER_SOCKET`
- `AEGIS_PROFILE_ROOT`: shared directory containing per-job YAML profiles
- `AEGIS_REGISTRY_DIR`: local collector registration directory

The supplied hooks are:
- `deploy/slurm/prolog/10-aegis-register.sh`
- `deploy/slurm/epilog/10-aegis-cleanup.sh`

Operationally:
- Prolog writes a local collector registration for the job
- Prolog registers the same profile with the verifier
- Epilog removes the local registration
- Epilog closes the verifier-side session

### 5. Prepare constraint profiles

Each protected job needs a YAML constraint profile readable from the shared `AEGIS_PROFILE_ROOT`. Start from `deploy/config/constraint_profile.example.yaml` and customize the job identity, paths, endpoints, tools, and budgets for your site.

The verifier consumes those profiles through `core/constraints.py`, which handles:
- profile parsing
- signing and signature verification
- binding profiles to job/session identity

If profile registration is broken, the collector may still emit evidence, but the verifier will not have the correct policy context to evaluate it correctly.

## Runtime Flow

1. Slurm starts a job.
2. Prolog registers the job locally on the compute node and centrally with the verifier.
3. The collector observes probe events, maps them to the registered job/session, and emits signed evidence.
4. The verifier evaluates the evidence against the bound profile.
5. If violations occur, the verifier uses `enforcement/slurm_integration.py` to contain the job.
6. Epilog removes the registration and closes the session.

## Commands You Will Actually Use

Verifier daemon:

```bash
python3 -m src.deployment.control_plane.verifierd --config /etc/aegis/verifier.json serve
```

Verifier health check:

```bash
python3 -m src.deployment.control_plane.verifierd --config /etc/aegis/verifier.json health
```

Collector help:

```bash
python3 -m src.deployment.collector.bpf_collector --help
```

Job registry helper:

```bash
python3 -m src.deployment.collector.job_registry --help
```

Attach-only probe helper:

```bash
python3 -m src.deployment.collector.bpf_attach --help
```

Deployment-core tests:

```bash
python3 -m unittest discover -s src/deployment/core/tests -v
```

## Recommended Validation Sequence

Before cluster rollout:
- run `make bpfall`
- run `python3 -m unittest discover -s src/deployment/core/tests -v`
- run `python3 -m src.deployment.control_plane.verifierd --help`
- run `python3 -m src.deployment.collector.bpf_collector --help`

After service installation:
- verify the verifier health endpoint or CLI health command
- verify that the collector can resolve its registry directory and BPF object path
- submit one test profile and one test job through the Slurm hook path
- confirm the verifier writes audit entries and sees the bound session/job

## If You Are Looking For Paper Experiments

Do not use `src/deployment/` for paper reproduction.
Use `src/paper/` instead.
