# Literature Survey — AEGIS

*Last updated: 2026-03-14*

---

## 1. Zero-Trust Architecture

| Paper | Authors | Year | Venue / Source | Key Contribution |
|---|---|---|---|---|
| SP 800-207: Zero Trust Architecture | Rose, Borchert, Mitchell, Connelly | 2020 | NIST Special Publication | Foundational ZTA framework; "never trust, always verify" |
| Zero Trust Architecture: A Systematic Literature Review | Gambo et al. | 2025 | arXiv:2503.11659 (J Netw Syst Manage, 2026) | PRISMA-based SLR of 10 years of ZTA research (2016–2025); taxonomy of application domains, enabling technologies, challenges |
| Federated Single Sign-On and Zero Trust Co-design for AI and HPC Digital Research Infrastructures | Alam, Woods, Williams, Moore, Prior, Williams, Price, Womack, McIntosh-Smith, Yang-Turner, Pryor, Livenson | 2024 | arXiv:2410.18411 | Federated IAM + ZTA co-design for Isambard-AI/HPC DRIs; SSO + MFA + time-limited RBAC for UK national HPC resources |
| A Path to Zero Trust Architecture in HPC and AI Using SPIFFE and SPIRE | Duckworth et al. | 2023 | CLSAC 2023 | Applies SPIFFE/SPIRE service identity framework to HPC/AI for zero-trust workload authentication |
| Challenges and Tradeoffs of Zero Trust Architecture in High Performance Computing | Macauley, Bhasker (SealingTech) | 2025 | SC25 (expected) | Measures ZTA implementation effort in HPC using CISA ZTMM maturity levels; explores security vs. performance/cost tradeoffs |

## 2. Attestation & Trusted Execution

| Paper | Authors | Year | Venue / Source | Key Contribution |
|---|---|---|---|---|
| An Exploratory Study of Attestation Mechanisms for Trusted Execution Environments | Ménétrey et al. | 2022 | SysTEX'22 (co-located with ASPLOS'22), arXiv:2204.06790 | Comprehensive comparison of remote attestation across Intel SGX, Arm TrustZone, AMD SEV, and RISC-V TEEs |
| A Confidential Computing Transparency Framework for a Comprehensive Trust Chain | Kocaoğullar et al. | 2024 | arXiv:2409.03720 | Three-level transparency framework for confidential computing; empirical study (800+ participants) on trust and attestation |
| Confidential High-Performance Computing in the Public Cloud | Chen | 2022 | IEEE Internet Computing, arXiv:2212.02378 | Threat models, challenges, and solutions for TEE-based confidential HPC in cloud; identifies significant gaps |
| SP 800-223: High-Performance Computing Security | NIST | 2024 | NIST Special Publication | HPC security standards; foundational reference for HPC security posture |
| TPM-Based Combined Remote Attestation Method for Confidential Computing | (CNCF) | 2025 | CNCF Blog / whitepaper | Proposes hybrid TPM + TEE-native attestation to mitigate vendor lock-in from hardware-controlled roots of trust |

## 3. AI Agents in HPC

| Paper | Authors | Year | Venue / Source | Key Contribution |
|---|---|---|---|---|
| Empowering Scientific Workflows with Federated Agents (Academy) | Pauloski et al. | 2025 | IPDPS'26, arXiv:2505.05428 | Modular middleware for deploying autonomous agents across federated HPC; async execution, heterogeneous resources, high-throughput data |
| Securing AI Agent Execution (AgentBound) | Bühler et al. | 2025 | arXiv:2510.21236 | First access control framework for MCP servers; declarative policies + enforcement engine for agent tool access |
| Security of AI Agents | He et al. | 2024 | arXiv:2406.08689 | System security analysis of AI agent vulnerabilities (confidentiality, integrity, availability); component-level defense mechanisms |
| RHAPSODY | (HPC-AI middleware) | 2025 | arXiv:2512.20795 | Multi-runtime middleware for concurrent heterogeneous AI-HPC workloads; agent-driven control on leadership-class platforms |

## 4. AI Agent Identity & Zero Trust

| Paper | Authors | Year | Venue / Source | Key Contribution |
|---|---|---|---|---|
| A Novel Zero-Trust Identity Framework for Agentic AI: Decentralized Authentication and Fine-Grained Access Control | (Multiple authors) | 2025 | arXiv:2505.19301 | Agent identities via DIDs + VCs; Agent Naming Service; dynamic ABAC; ZKPs for privacy-preserving attribute disclosure |
| Agentic Trust Framework: Zero Trust for AI Agents | Cloud Security Alliance | 2026 | CSA whitepaper | Core elements for agent identity in ZTA; verified, auditable identity before resource access |
| AI Agent Identity & Zero-Trust: The 2026 Playbook | (Industry) | 2025 | Industry whitepaper | Extending ZTA from human users to AI agents; addressing agent identity ownership gaps |
| NIST Concept Paper: Identity and Authorization Controls for AI Agents | NIST | 2026 | NIST draft | How organizations should identify, authenticate, and control software/AI agents; trace actions back to responsible human authority |

## 5. HPC Security

| Paper | Authors | Year | Venue / Source | Key Contribution |
|---|---|---|---|---|
| Zero Trust Architecture in HPC and AI Environments | (UBC / CSA) | 2025 | Presentation/paper | Application of ZTA principles to HPCI; suggests "Traditional" ZTMM maturity level for HPC |
| Confidential Computing Across Edge-to-Cloud Machine Learning: Survey | (Multiple) | 2024 | PAR / NSF | Survey of confidential computing for ML across edge-to-cloud; relevant to HPC AI agent scenarios |

## 6. Agent Safety & Alignment

| Paper | Authors | Year | Venue / Source | Key Contribution |
|---|---|---|---|---|
| (Reading queue — to be populated) | | | | |

---

## Reading Queue

- [ ] IETF RATS Architecture (Remote Attestation Procedures) — standardization of attestation evidence creation, conveyance, verification
- [ ] Keylime — open-source TPM-based scalable trust management framework
- [ ] SPIFFE/SPIRE — workload identity framework (referenced in CLSAC 2023 Duckworth paper)
- [ ] NIST AI Risk Management Framework (AI RMF)
- [ ] OWASP Agentic Security Initiative
- [ ] Entity Attestation Token (EAT) — IETF draft-messous-eat-ai-00

---

## Notes

- **Key gap identified**: No existing work specifically addresses continuous attestation of AI *agents* (not just TEE workloads) in HPC environments — this is AEGIS's niche
- The Alam et al. (2024) Isambard paper is the closest to HPC + ZTA but focuses on IAM/SSO, not agent attestation
- AgentBound (2025) addresses agent tool access control but for MCP servers, not HPC contexts
- The agentic AI identity work (arXiv:2505.19301) is relevant but enterprise/cloud-focused, not HPC-specific
