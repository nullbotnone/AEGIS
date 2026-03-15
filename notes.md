# AEGIS — Research Notes

## 2026-03-14

- Project initialized
- Working title: **A**ttestation-based **E**nvironment for **G**uarding **I**njection-vulnerable **S**ystems
- Core idea: apply zero-trust principles to AI agents running in HPC environments
- Initial project structure and proposal outline created
- **Paper title locked in**: *"Attestation is All You Need: Toward a Zero-Trust Architecture for HPC AI Agents"*
- **Target venue**: SC26
- Key angle: **attestation** as the central mechanism — continuous hardware-rooted verification of agent identity, execution integrity, and behavioral conformance
- SC26 deadlines TBD (typically abstract ~April, paper ~April/May) — need to check once announced

## 2026-03-14 (literature review)

- Conducted initial literature review across five topic areas
- Found ~20 relevant papers/documents — all verified from arXiv, NIST, CSA, etc.
- **Key finding**: No existing work addresses *continuous attestation of AI agents* in HPC specifically — this is AEGIS's positioning
- Closest work: Alam et al. (2024) Isambard ZTA for HPC (IAM focus, not attestation); AgentBound (2025) agent access control (MCP, not HPC); arXiv:2505.19301 agentic AI identity (enterprise, not HPC)
- Reading queue: IETF RATS, Keylime, SPIFFE/SPIRE, EAT framework, NIST AI RMF

## 2026-03-14 (threat model)

- Defined the core threat: **hijacked authorized agents** via prompt injection
- Four key properties: full credential inheritance, cross-project FS access, appearance of legitimacy, exfiltration via LLM API channel
- The API channel exfiltration vector is the critical novel angle — invisible to DLP, encrypted, whitelisted, high-bandwidth
- Four attack scenarios: data file injection, tool output poisoning, collaborative channel attack, supply chain compromise
- Key claim: every existing defense (auth, authz, IDS, DLP, UBA, sandboxing) fails against this threat
- Attestation is the answer — verify behavioral conformance, not just identity validity
- **§3.5 added**: Four unique HPC-specific injection properties:
  1. Filesystem-mediated injection (Lustre/GPFS as injection surface; exploits trust in shared storage)
  2. Multi-user co-location injection (side-channels via /tmp, /var/tmp on shared compute nodes)
  3. Supply chain injection via agent skills (OpenClaw, LangChain, MCP tools as injection vector)
  4. Coordinated multi-agent injection (covert exfiltration networks across nodes/users)
- Key insight: attack surface = entire shared infrastructure, not just agent input

## 2026-03-14 (experimental plan)

- Designed 6 experiments for the paper:
  - **Exp 1**: Filesystem-mediated injection (Lustre shared dir → agent hijack)
  - **Exp 2**: Multi-user co-location injection (/tmp side-channel on shared node)
  - **Exp 3**: Supply chain injection via agent skills (compromised tool output)
  - **Exp 4**: Coordinated multi-agent exfiltration (cross-node covert network)
  - **Exp 5**: AEGIS defense evaluation (detection rate, false positives, time to detection/revocation)
  - **Exp 6**: Performance overhead (<5% target on HPCG, ML training, data pipelines)
- Paper structure: §5 is now entirely experimental — threat demonstration (5.1-5.4) + defense evaluation (5.5-5.6)
- Need: Slurm test cluster, agent framework, LLM API access, representative scientific datasets

## 2026-03-14 (behavioral attestation architecture)

- Defined **behavioral attestation** as the core AEGIS mechanism
- Three key distinctions from prior work:
  1. Attestation (provable) vs. detection (probabilistic)
  2. Constraint-based (whitelist) vs. signature-based (blacklist)
  3. Runtime (prevent) vs. post-hoc (alert after damage)
- **Key insight**: Can't prevent all injection attacks → detect and contain effects via behavioral constraints
- Shifts question from "Is agent compromised?" (unknowable) to "Is agent within constraints?" (verifiable)
- Five constraint dimensions: data access, network, tool invocation, execution, data flow
- Attestation protocol: continuous evidence → verification → containment
- Four containment levels: rate-limit → isolate → suspend → terminate
- Relationship to TEEs: complementary (TEE = code integrity, behavioral = behavior conformance)
- Comparison table: behavioral attestation beats input sanitization, ML detection, sandboxing, RBAC on all dimensions

## 2026-03-14 (introduction + abstract)

- Wrote full introduction (~1 page) opening with: "While attention gave agents the power to reason, attestation gives the system the power to trust them."
- Introduction structure: hook → problem (hijacked authorized agent) → why HPC is unique → why existing defenses fail → behavioral attestation (3 distinctions) → 4 contributions → paper roadmap
- Abstract rewritten to match: hijacked agent threat → behavioral attestation (3 axes) → AEGIS → results claim
- Both capture the title's homage ("attention is all you need" → "attestation is all you need")

## 2026-03-14 (background + related work)

- Wrote full Background section (§2) with four subsections:
  - §2.1 Zero-Trust Architecture — NIST SP 800-207, HPC ZTA efforts (Alam, Duckworth, Macauley), positioning AEGIS as behavioral extension
  - §2.2 AI Agents in HPC — Academy, RHAPSODY, AgentBound; four HPC characteristics (shared FS, multi-tenant, data-intensive, API-driven)
  - §2.3 Security in HPC — Kerberos/SSH/RBAC/POSIX, four gaps, why they become critical with agents
  - §2.4 Prompt Injection and Agent Security — injection fundamentals, why web-based defenses fail in HPC
- Wrote full Related Work section (§7) with five subsections:
  - §7.1 Zero-Trust in HPC — Alam, Duckworth, Macauley, Gambo SLR
  - §7.2 Attestation and TEEs — Ménétrey, Chen, Kocaoğullar, IETF RATS, Keylime
  - §7.3 AI Agent Security — He et al., AgentBound, DID/VC identity framework, CSA Agentic Trust
  - §7.4 Prompt Injection Defenses — input sanitization, instruction hierarchy, output filtering
  - §7.5 Differentiation — comparison table (7 works × 6 dimensions), AEGIS is unique
- Created docs/references.md with 20 citations tracked, 3 TBD
- Paper now has substantive content for §1, §2, §3, §4, §5, §6

## 2026-03-14 (paper restructure)

- Merged Implementation into §4 as §4.8 (constraint manager, attestation engine, policy verifier, containment enforcer, agent integration, audit/forensics)
- Removed §6 Implementation placeholder
- Renumbered: §7 → §6 (Related Work), §8 → §7 (Discussion), §9 → §8 (Conclusion)
- Updated introduction roadmap
- Paper now 553 lines, 8 main sections, clean flow: Intro → Background → Threat → Architecture+Implementation → Experiments → Related Work → Discussion → Conclusion

## 2026-03-14 (discussion + conclusion)

- Wrote Discussion (§7) with five subsections:
  - §7.1 Limitations — constraint completeness, injection within constraints, attestation interval, single-node focus, software attestation without TEEs
  - §7.2 Integration with HPC Resource Managers — Slurm integration, scheduling factor, fair-share accounting
  - §7.3 Federated Zero-Trust Across Sites — constraint portability, cross-site attestation, trust federation
  - §7.4 Formal Verification of Constraint Policies — completeness, consistency, minimality via TLA+/Coq
  - §7.5 Broader Applications — cloud-native agents, edge computing, robotics, financial systems
- Wrote Conclusion (§8) — recap of threat, key insight, contributions, closing callback to the attention/attestation opening
- Paper is now 611 lines, fully written from abstract through conclusion

## 2026-03-14 (full draft pass)

- Did complete pass through 611-line draft
- Fixed: "co-creation" → "co-location" typo (§2.2)
- Fixed: removed "100%" specific claim from abstract (hedged to "in real time")
- Fixed: removed [9] citation, merged into [8] (NIST SP 800-223 covers HPC security gaps)
- Fixed: "Table X" → "Table 1" in §6.5 differentiation table
- Noted: [12] needs specific paper (prompt injection instruction hierarchy evasion)
- Overall assessment: paper is solid, all sections written, flow is clean, ready for refinement once experiments produce data

---

## Ideas & Scratchpad

_(Dump raw thoughts here — organize into proper docs later)_

