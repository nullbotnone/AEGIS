# Figures Needed

## For the Paper

1. **Threat Model Overview** — Diagram showing the hijacked agent threat: legitimate agent → injection → hijacked agent → exfiltration via LLM API channel

2. **HPC Injection Attack Surfaces** — Illustration of the four unique injection vectors:
   - Filesystem-mediated (shared Lustre/GPFS)
   - Co-location (shared /tmp on compute node)
   - Supply chain (compromised skill/tool)
   - Coordinated (multi-agent exfiltration network)

3. **LLM API Exfiltration Channel** — Diagram showing why traditional DLP fails: encrypted, whitelisted, high-bandwidth channel

4. **AEGIS Architecture** — High-level system diagram: Identity Layer → Policy Engine → Execution Guard → Audit

5. **Attestation Protocol** — Sequence diagram: agent → attestation challenge → behavioral evidence → verification → decision (allow/contain)

6. **Experimental Results** — Bar charts / tables for each experiment (to be generated from data)

## For Presentations

- Attack scenario walkthrough (animated)
- Before/after: without AEGIS vs. with AEGIS
