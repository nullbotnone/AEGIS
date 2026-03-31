# Documentation

The `docs/` directory is organized around the two supported repo goals:
- deploy AEGIS on a real Slurm cluster
- reproduce the SC26 evaluation

## Read This First

- [REAL_CLUSTER_DEPLOYMENT.md](REAL_CLUSTER_DEPLOYMENT.md): install and operate the verifier, collector, eBPF probe, and Slurm hooks on a real cluster
- [SC26_EVALUATION.md](SC26_EVALUATION.md): canonical evaluation matrix, exact commands, expected artifacts, and paper-facing result mapping
- [EPYC_TESTING_GUIDE.md](EPYC_TESTING_GUIDE.md): prepare an EPYC measurement host and validate the real measurement toolchain before running the full evaluation
- [eBPF_IMPLEMENTATION.md](eBPF_IMPLEMENTATION.md): current probe and collector implementation notes

## Which Guide To Use

Use [REAL_CLUSTER_DEPLOYMENT.md](REAL_CLUSTER_DEPLOYMENT.md) if you are installing services on cluster nodes.

Use [SC26_EVALUATION.md](SC26_EVALUATION.md) if you are generating artifacts for the paper.

Use [EPYC_TESTING_GUIDE.md](EPYC_TESTING_GUIDE.md) if you need to bring up a single measurement node or debug the real measurement path before a full campaign.
