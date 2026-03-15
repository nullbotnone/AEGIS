# AEGIS

**A**ttestation-based **E**nvironment for **G**uarding **I**njection-vulnerable **S**ystems

> Toward a Zero-Trust Architecture for HPC AI Agents

## Paper

**"Attestation is All You Need: Toward a Zero-Trust Architecture for HPC AI Agents"**
Target: **SC26** — International Conference for High Performance Computing, Networking, Storage and Analysis

## Overview

AEGIS investigates zero-trust security architectures tailored for AI agents operating in high-performance computing (HPC) environments. As AI agents gain autonomy in HPC workflows — scheduling jobs, accessing data, orchestrating simulations — the attack surface expands dramatically. Traditional perimeter-based security models are insufficient.

This project explores how **behavioral attestation** — continuous, constraint-based verification of agent actions — can contain the effects of injection attacks on AI agents in HPC environments. Even when agents are hijacked through filesystem injection, co-location attacks, or supply chain compromise, attestation detects and prevents constraint violations before data exfiltration occurs.

## Research Questions

1. **Behavioral Attestation** — How can we provably verify that an AI agent operates within its authorized constraints at runtime?
2. **Constraint Specification** — What are the right constraint dimensions (data access, network, tools, execution, data flow) for HPC agents?
3. **HPC-Specific Injection Surfaces** — What unique attack vectors do shared filesystems, multi-tenant nodes, and agent skill ecosystems create?
4. **Containment Mechanisms** — How should violations be contained (rate-limit, isolate, suspend, terminate) without disrupting legitimate workflows?
5. **Performance Trade-offs** — What is the overhead of continuous attestation on HPC-scale workloads?

## Project Structure

```
AEGIS/
├── README.md           ← This file
├── PROPOSAL.md         ← Research proposal / paper outline
├── notes.md            ← Ad-hoc research notes
├── literature.md       ← Literature survey & annotated bibliography
├── src/                ← Code / prototypes / experiments
├── docs/               ← Internal documentation
├── experiments/        ← Experiment configs, results, analysis
├── references/         ← Papers, articles, specs (PDFs, links)
├── figures/            └─ Diagrams, architecture sketches
└── LICENSE
```

## Key Concepts

- **Behavioral Attestation**: Continuous, constraint-based verification that an agent's actions conform to its authorized task — provable guarantees, not probabilistic detection
- **HPC AI Agents**: Autonomous or semi-autonomous software agents operating within HPC job schedulers (Slurm, PBS, etc.)
- **Injection-Vulnerable Systems**: Systems where agents process untrusted input (shared filesystems, co-located nodes, third-party tools) creating hijacking attack surfaces
- **Constraint-Based Security**: Whitelist-based policies defining what is allowed (not signatures of what is malicious) — evasion-resistant by construction

## License

TBD
