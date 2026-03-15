# Figures Needed for AEGIS Paper

Based on current PROPOSAL.md content (7,200 words, 8 sections).

---

## Required Figures

### Figure 1: AEGIS Architecture (§4.1)
**Already in paper as ASCII diagram — needs proper rendering**

The ASCII diagram in §4.1 shows:
- Attestation Engine (per node) → evidence → Policy Verifier
- Policy Verifier → challenge → Attestation Engine
- Attestation Engine → eBPF probes → Agent Runtime
- Policy Verifier → verdict → Containment Enforcer → Slurm REST API
- Constraint Manager (profiles signed, bound to Slurm job ID)
- Audit Ledger (hash-chained, tamper-evident)

**Action:** Convert ASCII to proper diagram (Graphviz/TikZ/draw.io)

---

### Figure 2: Threat Model — The Hijacked Agent (§3.1)
**Referenced in text — needs illustration**

Show the attack flow:
1. Legitimate agent with valid credentials (Kerberos, SSH, RBAC)
2. Injection vector (filesystem, co-location, tool, coordinated)
3. Agent hijacked but still has valid credentials
4. Exfiltration via encrypted LLM API channel (invisible to DLP)

Include the four properties: (1) full credential inheritance, (2) cross-project FS access, (3) appearance of legitimacy, (4) LLM API exfiltration

---

### Figure 3: HPC-Specific Injection Attack Surfaces (§3.5)
**Referenced in text — needs illustration**

Four panels showing:
1. **Filesystem-mediated:** User A writes poisoned HDF5 → shared Lustre → User B's agent reads → hijacked
2. **Co-location:** Node with User A + User B jobs → shared /tmp → injection → hijacked
3. **Supply chain:** Compromised data_converter tool → hidden instructions in output → hijacked
4. **Coordinated:** Agent 1 (hijacked) reads data → writes to /.cache/ → Agent 3 (hijacked) reads → exfiltrates via LLM API

---

### Figure 4: Baseline Comparison (§5.2)
**Table exists — could benefit from visualization**

Bar chart showing detection rate comparison:
- Network DLP: 0%
- Filesystem Auditing: 50%
- Per-Agent Analytics: 0%
- Strict Sandboxing: 50%
- AEGIS: 100%

---

### Figure 5: Ablation Study Results (§5.4)
**Table exists — could benefit from visualization**

Heatmap or grouped bar chart:
- X-axis: 6 configurations (Full AEGIS, No Volume, No Sensitive, No Covert, No Injection, Minimal)
- Y-axis: Detection rate
- Color: green (detected), red (missed)
- Show the degradation from 100% → 75% → 0%

---

### Figure 6: Experimental Attack Results (§5.1)
**Data exists — needs visualization**

Table/figure showing per-experiment results:
- Attack name, data exfiltrated, detections, detection mechanism, detection time
- Summary: 4/4 attacks succeed, 4/4 detected, 1,158 bytes total, 16 detections

---

## Optional Figures

### Figure 7: Constraint Specification Example (§4.2)
Visual representation of the five constraint dimensions:
- Data access, Network, Tool invocation, Execution, Data flow
- Show how constraints map to detection mechanisms

### Figure 8: Attestation Protocol Flow (§4.3)
Sequence diagram:
1. Agent deploys with constraint profile
2. Continuous evidence bundles
3. Random challenges
4. Verification → verdict → containment

---

## Summary

| # | Figure | Section | Priority | Status |
|---|--------|---------|----------|--------|
| 1 | AEGIS Architecture | §4.1 | **Required** | ASCII exists, needs rendering |
| 2 | Hijacked Agent Threat | §3.1 | **Required** | Needs creation |
| 3 | HPC Injection Surfaces | §3.5 | **Required** | Needs creation |
| 4 | Baseline Comparison | §5.2 | Recommended | Data ready |
| 5 | Ablation Results | §5.4 | Recommended | Data ready |
| 6 | Attack Results | §5.1 | Recommended | Data ready |
| 7 | Constraint Dimensions | §4.2 | Optional | Needs creation |
| 8 | Attestation Protocol | §4.3 | Optional | Needs creation |
