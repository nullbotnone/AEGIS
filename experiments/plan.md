# AEGIS — Experiment Design & Tracking

## Overview

Six experiments designed for the SC26 paper:
- **§5.1–5.4**: Empirical demonstration of HPC-specific injection attacks (novel contribution)
- **§5.5**: AEGIS defense evaluation (detects/mitigates the attacks)
- **§5.6**: Performance overhead (proves practicality)

---

## Experiment 1: Filesystem-Mediated Injection (§5.1)

**Threat:** Attacker places adversarial content in shared Lustre/GPFS → agent reads it → hijacked

| Item | Detail |
|------|--------|
| Status | 🔲 Not started |
| Infrastructure | Slurm cluster + shared Lustre |
| Users | User A (attacker), User B (victim), shared project dir |
| Agent | LLM-based (GPT-4o/Claude) processing HDF5/FITS/CSV |
| Payload | Hidden injection in metadata fields, column headers, comments |
| Metrics | Success rate, time to exfiltration, data volume, baseline detection |
| Hypothesis | >80% success rate, evades all baseline defenses |

**To-do:**
- [ ] Identify/create poisoned dataset examples (HDF5, FITS, CSV)
- [ ] Design injection payloads (metadata vs. data content)
- [ ] Set up agent workflow (dataset → LLM analysis → report)
- [ ] Implement baseline defenses for comparison

---

## Experiment 2: Multi-User Co-Location Injection (§5.2)

**Threat:** Co-located agents on shared node → /tmp side-channel → injection

| Item | Detail |
|------|--------|
| Status | 🔲 Not started |
| Infrastructure | Slurm cluster, shared /tmp and /var/tmp |
| Users | User A (attacker job), User B (victim job), same node |
| Monitoring | inotify, auditd, network monitoring |
| Payload | Adversarial content in shared scratch log/output files |
| Metrics | Co-location probability, injection success rate, detection comparison |
| Hypothesis | Scheduler co-location creates predictable injection surface |

**To-do:**
- [ ] Measure co-location probability on target cluster
- [ ] Design /tmp injection strategy (file naming, timing)
- [ ] Implement filesystem monitoring baseline
- [ ] Compare detection: FS monitoring vs. behavioral attestation

---

## Experiment 3: Supply Chain Injection via Agent Skills (§5.3)

**Threat:** Compromised skill/tool returns hidden instructions → agent trusts its own tools → hijacked

| Item | Detail |
|------|--------|
| Status | 🔲 Not started |
| Infrastructure | Agent framework (LangChain/OpenClaw/custom) + skill ecosystem |
| Attack vector | Adversarial skill returning hidden instructions in output |
| Comparison | Same payload via web-based injection vs. skill-mediated injection |
| Metrics | Success rate across frameworks, detection difficulty comparison |
| Hypothesis | Higher success rate than web-based (agent trusts its tools) |

**To-do:**
- [ ] Select agent framework(s) to test
- [ ] Build adversarial skill with hidden payload in output
- [ ] Design web-based injection baseline for comparison
- [ ] Test across multiple frameworks if possible

---

## Experiment 4: Coordinated Multi-Agent Exfiltration (§5.4)

**Threat:** Multiple hijacked agents form covert exfiltration network → per-agent detection fails

| Item | Detail |
|------|--------|
| Status | 🔲 Not started |
| Infrastructure | Slurm cluster, 4+ users, shared Lustre, per-node network monitoring |
| Attack setup | 2 hijacked agents (Users 1 & 3), 2 benign agents (Users 2 & 4) |
| Attack flow | Agent A reads data → encodes to shared FS → Agent B reads → exfiltrates via API |
| Metrics | Per-agent anomaly score, detection rate comparison, data volume distribution |
| Hypothesis | Per-agent monitoring misses the attack; only cross-agent correlation detects it |

**To-do:**
- [ ] Design encoding scheme for cross-agent data transfer
- [ ] Implement per-agent and cross-agent monitoring
- [ ] Define anomaly scoring methodology
- [ ] Design covert channel (shared FS location, timing, encoding)

---

## Experiment 5: AEGIS Defense Evaluation (§5.5)

**Goal:** Show AEGIS detects/mitigates all four attack types

| Item | Detail |
|------|--------|
| Status | 🔲 Not started |
| Infrastructure | Same as Exp 1–4 + AEGIS attestation layer |
| Metrics | True positive rate, false positive rate, time to detection, time to revocation |
| Baselines | No defense, DLP, filesystem monitoring, per-agent monitoring |

**To-do:**
- [ ] Implement AEGIS attestation protocol
- [ ] Define attestation policies per attack type
- [ ] Measure detection/revocation times
- [ ] Run false positive tests under normal workloads

---

## Experiment 6: Performance Overhead (§5.6)

**Goal:** Prove AEGIS is practical for HPC (<5% overhead)

| Item | Detail |
|------|--------|
| Status | 🔲 Not started |
| Infrastructure | Slurm cluster with AEGIS enabled |
| Workloads | HPCG, PyTorch ML training, HDF5 data pipeline |
| Metrics | Job submission latency, throughput overhead, attestation latency, scalability |
| Target | <5% overhead on representative workloads |

**To-do:**
- [ ] Baseline measurements (no AEGIS)
- [ ] AEGIS-enabled measurements
- [ ] Scalability sweep (10, 100, 1000 agents)
- [ ] Attestation protocol microbenchmarks

---

## Infrastructure Requirements

| Resource | Purpose |
|----------|---------|
| Slurm cluster (≥4 nodes) | Experiments 1, 2, 4, 5, 6 |
| Shared Lustre filesystem | Experiments 1, 4, 5 |
| LLM API access (GPT-4o/Claude) | All experiments |
| Agent framework (LangChain/OpenClaw) | Experiments 3, 5 |
| Scientific datasets (HDF5, FITS, CSV) | Experiment 1 |
| Network monitoring tools | Experiments 2, 4, 5 |
| Performance benchmark suite (HPCG) | Experiment 6 |

## Timeline

| Week | Activity |
|------|----------|
| 1–2 | Infrastructure setup, agent framework selection |
| 3–4 | Experiments 1 & 2 (filesystem + co-location injection) |
| 5–6 | Experiment 3 (supply chain injection) |
| 7–8 | Experiment 4 (coordinated exfiltration) |
| 9–12 | AEGIS prototype implementation |
| 13–14 | Experiments 5 & 6 (defense evaluation + performance) |
| 15–16 | Analysis, visualization, paper integration |
