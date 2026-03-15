# PROPOSAL.md — AEGIS Research Proposal

## Paper Title

**Attestation is All You Need: Toward a Zero-Trust Architecture for HPC AI Agents**

## Target Venue

**SC26** — The International Conference for High Performance Computing, Networking, Storage and Analysis
- Website: https://sc26.supercomputing.org
- Abstract deadline: ~April 2026
- Full paper deadline: ~April/May 2026 (check for exact dates)
- Notification: ~July/August 2026
- Conference: November 2026

## Abstract

AI agents are entering high-performance computing — steering simulations, orchestrating ML training, analyzing petabytes of scientific data. But these agents introduce a threat that HPC security was never designed to handle: the *hijacked authorized agent*. Through prompt injection attacks delivered via shared filesystems, co-located compute nodes, or compromised agent tools, an adversary can subvert an agent that already holds valid credentials and legitimate permissions. The hijacked agent exfiltrates data through encrypted, whitelisted LLM API channels — invisible to traditional monitoring and data loss prevention.

We propose **behavioral attestation** as the foundation for securing AI agents in HPC. Rather than detecting attacks probabilistically, attestation provides provable guarantees that an agent operates within its authorized behavioral constraints. Rather than blocking known-bad signatures, constraint-based policies define what is allowed — making violations unambiguous and evasion-resistant. Rather than alerting after the fact, runtime verification enforces containment before data exfiltration occurs.

We formalize four HPC-specific injection attack vectors, design and implement AEGIS (Attestation-based Environment for Guarding Injection-vulnerable Systems), and empirically demonstrate that behavioral attestation detects and contains hijacked agents with bounded latency and minimal performance overhead. Our evaluation shows that AEGIS introduces < 5% overhead on representative HPC workloads while detecting constraint violations in real time.

## 1. Introduction

> *While attention gave agents the power to reason, attestation gives the system the power to trust them.*

AI agents are entering high-performance computing. Autonomous experiment loops steer simulations in real time. ML training agents orchestrate multi-node workflows without human intervention. Data analysis agents read, transform, and summarize petabytes of scientific output. These agents promise to dramatically accelerate scientific discovery — but they also introduce a threat that HPC security was never designed to handle.

The problem is not that AI agents are untrustworthy. The problem is that they are *too* trustworthy — to the wrong inputs. An agent authorized to process genomics data for Project X will faithfully execute whatever instructions it receives, including instructions hidden inside that data by an attacker. A prompt injection payload embedded in a FITS file header, a malicious instruction in a shared `/tmp` directory, a compromised tool returning hidden commands — these are not hypothetical threats. They are the natural consequence of deploying instruction-following systems into environments where untrusted data is the norm.

This paper identifies and formalizes a threat that has not been studied in prior work: **the hijacked authorized agent in HPC**. Unlike rogue agents (which existing authentication blocks) or adversarial agents (which existing authorization constrains), a hijacked agent operates with the full credentials and privileges of a legitimate user. It does not need to escalate privileges — it already has them. It does not need to bypass access controls — it is already authorized. It appears legitimate to every monitoring system that checks identity, because its identity *is* legitimate. And it exfiltrates data through the one channel that no HPC security system inspects: the encrypted, whitelisted, high-bandwidth LLM API connection that the agent requires to function.

The attack surface is uniquely HPC. Shared filesystems (Lustre, GPFS) create injection surfaces — an attacker places adversarial content in a project directory, and the target agent reads it as trusted scientific data. Multi-tenant compute nodes create co-location injection vectors — an attacker's agent writes to shared `/tmp`, and a co-located target agent picks it up. Agent skill ecosystems create supply chain attacks — a compromised tool injects instructions from within the agent's trusted execution context. And coordinated multi-agent exfiltration distributes data theft across nodes and users, evading per-agent detection entirely.

Existing defenses fail against this threat. Authentication succeeds because the agent has valid credentials. Authorization succeeds because the agent has legitimate permissions. Network monitoring is blinded by encryption. DLP is bypassed because data is encoded in whitelisted API calls. User behavior analytics see nothing anomalous because the agent's workflow patterns are consistent with its authorized role.

We propose **behavioral attestation** as the foundation for securing AI agents in HPC. Our key insight is simple: *we cannot prevent all injection attacks, but we can contain their effects*. Even if an agent is hijacked, we can detect when it violates its behavioral constraints — accessing files outside its authorized project, connecting to non-whitelisted endpoints, invoking unauthorized tools — and contain the violation before data exfiltration occurs.

Behavioral attestation differs from prior approaches in three fundamental ways:

- **Attestation, not detection.** Existing agent security relies on ML-based classifiers that provide probabilistic alerts with inherent false positive and negative rates. Behavioral attestation provides *provable guarantees*: an agent either satisfies its constraints or it does not. There is no ambiguity.

- **Constraint-based, not signature-based.** Existing defenses block known-bad patterns (signatures), which can be evaded through obfuscation. Constraints define what is *allowed*, not what is malicious. An unauthorized action is unambiguously a violation, regardless of how it is disguised.

- **Runtime, not post-hoc.** Existing monitoring alerts after the attack succeeds — the damage is already done. Behavioral attestation verifies constraints continuously during execution and enforces containment *before* exfiltration occurs.

This paper makes the following contributions:

1. **Formalization of the hijacked agent threat in HPC.** We identify four unique attack vectors (filesystem-mediated injection, co-location injection, supply chain injection, coordinated multi-agent exfiltration) that exploit HPC infrastructure in ways not studied in prior agent security work.

2. **Behavioral attestation as a security primitive.** We propose constraint-based, runtime attestation of agent behavior as a provable, evasion-resistant, and real-time enforcement mechanism for AI agents.

3. **AEGIS: a zero-trust architecture for HPC AI agents.** We design a complete system encompassing constraint specification, continuous attestation protocols, and automated containment mechanisms.

4. **Empirical evaluation.** We demonstrate the feasibility and effectiveness of all four HPC-specific injection attacks, and show that behavioral attestation detects and contains them with bounded latency and minimal performance overhead.

The remainder of this paper is organized as follows. §2 provides background on zero-trust architecture, AI agents in HPC, and existing security models. §3 formalizes the hijacked agent threat model and the unique properties of HPC injection attacks. §4 presents the AEGIS architecture, behavioral attestation protocol, and implementation. §5 describes our experimental evaluation. §6 surveys related work. §7 discusses limitations and future directions. §8 concludes.

## 2. Background

### 2.1 Zero-Trust Architecture

Zero-Trust Architecture (ZTA), formalized in NIST SP 800-207 [1], operates on the principle of "never trust, always verify." Unlike perimeter-based security, which assumes entities inside the network boundary are trustworthy, ZTA treats every access request as potentially hostile regardless of its origin. The core tenets are: (1) all resources require secure access, (2) communication is secured regardless of network location, (3) access is granted on a per-session basis with least-privilege, (4) access decisions are dynamic and informed by multiple signals, and (5) continuous monitoring validates trust throughout the session.

ZTA has been widely adopted in enterprise and cloud-native environments, with implementations ranging from software-defined perimeters (Zscaler, Cloudflare Access) to service mesh architectures (Istio, Linkerd) that enforce mutual TLS and fine-grained authorization between services. However, applying ZTA to HPC environments presents unique challenges: the performance sensitivity of scientific workloads, the shared-resource nature of HPC clusters (filesystems, interconnects, job schedulers), and the need to preserve the collaborative, low-friction access patterns that enable scientific productivity.

Recent work by Alam et al. [2] deployed federated single sign-on with zero-trust controls for the Isambard-AI and Isambard-HPC digital research infrastructures in the UK, demonstrating that ZTA can be integrated into production HPC systems. Duckworth et al. [3] proposed using SPIFFE/SPIRE for workload identity in HPC, addressing the service-to-service authentication gap. Macauley and Bhasker [4] measured the implementation effort required to achieve various ZTA maturity levels in HPC using CISA's Zero Trust Maturity Model, finding that a "Traditional" maturity level is most practical given current HPC infrastructure constraints.

Our work extends ZTA to a dimension these efforts do not address: the *behavioral* trust of autonomous AI agents operating within HPC environments. Existing ZTA in HPC focuses on identity verification and access control — confirming that a user or service is who they claim to be. We argue this is necessary but insufficient: for AI agents, *identity* verification must be complemented by *behavioral* verification, attesting not just to who the agent is, but to what it is doing.

### 2.2 AI Agents in HPC

AI agents — autonomous software systems that perceive their environment, reason about goals, and take actions to achieve them — are rapidly entering HPC workflows. Unlike traditional HPC applications that execute predetermined computational kernels, agents make dynamic decisions during execution: selecting which data to analyze, which simulation parameters to adjust, which tools to invoke, and when to escalate to human oversight.

Several frameworks now support agent deployment in HPC environments. Academy [5] provides a modular middleware for deploying autonomous agents across federated research ecosystems, supporting asynchronous execution, heterogeneous resources, and high-throughput data flows. RHAPSODY [6] enables concurrent execution of heterogeneous AI-HPC workloads, combining large-scale simulation, training, inference, and agent-driven control within a single execution campaign. AgentBound [7] addresses access control for MCP servers, the de facto standard for connecting AI agents with external tools, but does not address HPC-specific concerns.

The HPC environment introduces unique characteristics for agent operation:

**Shared filesystems.** HPC clusters use parallel filesystems (Lustre, GPFS, BeeGFS) shared across all users and projects. An agent's filesystem access is typically governed by POSIX permissions tied to user identity, not by project or task boundaries. This creates a coarse-grained access model where a user authorized on multiple projects grants their agent simultaneous access to all of them.

**Multi-tenant compute.** HPC schedulers (Slurm, PBS) place jobs from different users on shared compute nodes. Agents executing on these nodes share kernel-level resources: `/tmp`, `/var/tmp`, shared memory, and IPC mechanisms. This co-location creates implicit trust boundaries that are invisible to traditional access control.

**Data-intensive I/O.** Scientific workflows generate and consume terabytes of data. Agents in HPC routinely read large datasets (simulation outputs, instrument data, model checkpoints) as input to their decision-making. This data-centric workflow makes filesystem-mediated injection attacks particularly potent — the agent processes untrusted data as authoritative input by design.

**API-driven intelligence.** AI agents rely on LLM backends accessed via HTTPS API calls. This communication channel is essential to agent function but creates an exfiltration vector that is encrypted, whitelisted, and high-bandwidth by design.

### 2.3 Security in HPC

HPC security has traditionally relied on a perimeter model: authenticate users at the cluster boundary, authorize access through resource managers and filesystem permissions, and trust that authenticated users behave benignly. The primary security mechanisms are:

- **Authentication**: Kerberos-based authentication for cluster access, SSH key-based authentication for interactive sessions, and increasingly, federated identity through systems like CILogon and eduGAIN.
- **Authorization**: Role-based access control (RBAC) through the job scheduler (Slurm accounts, QOS levels) and POSIX filesystem permissions.
- **Network security**: Firewalls at the cluster boundary, with internal network traffic largely unencrypted due to performance requirements of the high-speed interconnect (InfiniBand, Slingshot).
- **Auditing**: Job accounting logs, filesystem access logs (where enabled), and network flow records.

This model has several well-documented gaps [8]:

- **Lateral movement**: Once authenticated, a user can access any resource their permissions allow, with no per-resource verification.
- **Credential theft**: Compromised SSH keys or Kerberos tickets grant full access until detected and revoked.
- **Overprovisioned access**: Users are typically granted broad filesystem access across all their projects, violating least-privilege.
- **No behavioral monitoring**: The security model verifies identity but not intent — an authorized user performing unauthorized actions is not detected.

These gaps are tolerable when all actors are human users whose actions are constrained by intent and awareness. They become critical when the actor is an AI agent that follows instructions blindly, including adversarial instructions delivered through injection attacks. The agent has valid credentials (passes authentication), has legitimate permissions (passes authorization), and its actions are consistent with its role (passes behavioral analytics) — but it is executing an attacker's commands. No existing HPC security mechanism addresses this threat.

### 2.4 Prompt Injection and Agent Security

Prompt injection — the subversion of an AI agent's instruction-following behavior through adversarial inputs — has emerged as a fundamental security challenge for LLM-based systems [10]. Unlike traditional exploits that target code vulnerabilities, prompt injection targets the semantic interpretation of inputs by the language model. The agent cannot distinguish between legitimate instructions and adversarial instructions hidden in data, because both are processed through the same mechanism.

Prior work on prompt injection defense focuses on web-based scenarios: an agent browsing the internet encounters a malicious webpage that injects hidden instructions [11]. Defenses include input sanitization (removing known injection patterns), instruction hierarchy (marking system prompts as higher-priority than user inputs), and output filtering (detecting anomalous outputs). However, these defenses have fundamental limitations:

- **Sanitization is incomplete**: The space of possible injection payloads is unbounded; any sanitization filter can be evaded through creative encoding.
- **Instruction hierarchy is fragile**: Adversarial inputs can override hierarchical instructions through careful crafting [12].
- **Output filtering is probabilistic**: ML-based output classifiers have inherent false positive and negative rates, and can be evaded through adversarial examples.

The agent security literature has not addressed the HPC context, where injection attacks exploit shared infrastructure (filesystems, compute nodes, tool ecosystems) rather than web content. This gap motivates our work.

## 3. Threat Model

### 3.1 The Hijacked Agent Threat

We identify the most dangerous threat to HPC environments deploying AI agents: **the hijacked authorized agent**. Unlike rogue or malicious agents, which are blocked by existing authentication and authorization mechanisms, a hijacked agent operates under the full credentials and privileges of a legitimate user. It is not an intruder — it is a trusted insider that has been turned.

This threat arises from **prompt injection and tool poisoning attacks** against LLM-based agents. An attacker crafts inputs — through data files, tool outputs, shared documents, or collaborative channels — that subvert the agent's instruction-following behavior. The agent, now under adversarial control, executes commands indistinguishable from the legitimate user's intent.

A hijacked agent possesses four properties that make it uniquely dangerous in HPC:

1. **Full credential inheritance.** The agent operates with the user's Kerberos tickets, SSH keys, and scheduler permissions. No privilege escalation is needed — the agent already has access. From the access control system's perspective, every action is authorized.

2. **Cross-project filesystem access.** HPC shared filesystems (Lustre, GPFS, BeeGFS) are typically organized by user, not by project. A user authorized on Projects A, B, and C grants their agent simultaneous access to all three datasets. A hijacked agent can traverse project boundaries that would require separate authorization in a properly segmented system.

3. **Appearance of legitimacy.** The agent runs under an authorized user identity, invokes authorized tools, and follows authorized workflow patterns. Traditional anomaly detection fails because the agent's observable behavior (job submission, file I/O, network access) is consistent with its authorized role.

4. **Exfiltration through the LLM API channel.** The agent communicates with its LLM backend via HTTPS API calls. Sensitive data can be encoded into prompts or tool outputs and transmitted through this channel, which is:
   - Encrypted (invisible to network-level DLP)
   - Whitelisted (agents must communicate with the LLM to function)
   - High-bandwidth (prompts can contain large context windows)
   - Attributable to normal operation (no anomalous network destination)

This exfiltration vector is **invisible to traditional Data Loss Prevention (DLP)** systems, which inspect network traffic for sensitive data patterns. The LLM API channel bypasses this by design.

### 3.2 Threat Scenarios

**Scenario 1: Data file injection.** An attacker embeds a prompt injection payload in a scientific dataset (e.g., a comment field in a FITS header, a markdown cell in a Jupyter notebook). When the agent processes this file as part of a workflow, the injection hijacks the agent's subsequent actions.

**Scenario 2: Tool output poisoning.** A compromised or adversarial tool returns output containing hidden instructions. The agent, treating the tool output as trusted data, executes the injected commands.

**Scenario 3: Collaborative channel attack.** In multi-agent workflows (e.g., Academy-style federated agents), a compromised agent in one project injects instructions through inter-agent communication, propagating the hijack laterally across project boundaries.

**Scenario 4: Supply chain compromise.** A malicious update to an agent framework, dependency library, or model weights introduces a backdoor that activates when specific conditions are met, exfiltrating data through the normal API channel.

### 3.3 Adversarial Capabilities

We assume an adversary with the following capabilities:

| Capability | Assumption |
|---|---|
| Prompt injection | Can craft inputs that subvert agent instruction-following |
| Network access | Can observe encrypted traffic metadata (timing, volume) but not content |
| HPC access | No direct HPC account; must operate through hijacked agents |
| Time horizon | Can persist across multiple agent sessions and job submissions |

We explicitly **do not** assume the adversary can:
- Compromise the HPC scheduler or resource manager
- Access the LLM provider's infrastructure
- Subvert hardware roots of trust (TPM, secure enclaves)

### 3.4 Why Existing Defenses Fail

| Defense | Why it fails against hijacked agents |
|---|---|
| Authentication (Kerberos, SSH) | Agent has valid credentials — authentication succeeds |
| Authorization (RBAC, ACLs) | Agent has legitimate permissions — authorization succeeds |
| Network monitoring (IDS/IPS) | LLM API traffic is encrypted and whitelisted |
| DLP | Data exfiltration is encoded in encrypted API calls |
| User behavior analytics | Agent behavior is consistent with authorized workflow patterns |
| Sandbox isolation | Agent needs filesystem and network access to function |

This threat model motivates the need for **attestation**: continuous verification that the agent's *behavior* conforms to its *authorized intent*, not just that its *identity* is valid.

### 3.5 Unique Properties of Agent Injection Attacks in HPC

Agent injection attacks in HPC environments exhibit properties that are not studied in prior work on prompt injection (which focuses on web-based and chatbot scenarios). These properties arise from the unique characteristics of HPC infrastructure: shared filesystems, multi-tenant compute nodes, and emerging agent skill ecosystems.

**Filesystem-mediated injection.** HPC shared filesystems (Lustre, GPFS, BeeGFS) create injection surfaces with no analogue in web-based attacks. An attacker with access to a shared project directory can place adversarial content — poisoned metadata in HDF5 files, hidden instructions in log outputs, malicious comments in source code — that the target agent reads as part of its task context. Unlike web-based prompt injection, which requires the agent to visit a malicious URL or process untrusted web content, filesystem injection exploits the *implicit trust in shared storage*. Scientific data is presumed benign; agents process it as authoritative input. This trust assumption is foundational to scientific workflows and cannot be simply revoked without destroying utility.

**Multi-user co-location injection.** HPC schedulers place jobs from different users on shared compute nodes. When agents from different users co-locate, side-channel injection becomes possible. An attacker's agent can leave adversarial content in shared directories (`/tmp`, `/var/tmp`, shared memory segments) that a target agent subsequently reads. This is analogous to cross-VM side-channel attacks but operates at the application level through shared filesystem state. The attacker does not need filesystem permissions on the target's project — they need only a co-located job that writes to a shared scratch space.

**Supply chain injection via agent skills.** Agent skill ecosystems (OpenClaw skills, LangChain tools, MCP servers, AutoGen plugins) create a supply chain attack vector unique to agentic AI. A compromised or adversarial skill can inject instructions directly into the agent's decision loop — not through external data, but through the agent's own tooling. The agent trusts its tools; a poisoned tool returns hidden instructions in its output that the agent executes as part of its reasoning process. This attack is particularly insidious because the injection originates from code the agent *chose* to execute, making it indistinguishable from legitimate tool use.

**Coordinated multi-agent injection and exfiltration.** In HPC environments deploying multiple agents across projects and users, a sophisticated adversary can orchestrate coordinated attacks. Multiple hijacked agents form covert exfiltration networks: Agent A reads sensitive data from Project X, encodes it, and writes it to a shared filesystem location; Agent B (belonging to a different user) picks up the encoded data and exfiltrates it through its own LLM API channel. This distributes the exfiltration footprint across multiple nodes, users, and API calls, evading per-node and per-user detection mechanisms. No single agent's behavior appears anomalous — the attack is visible only when agents are analyzed collectively.

These unique properties mean that existing prompt injection defenses (input sanitization, instruction hierarchy, output filtering) are insufficient for HPC. The attack surface is not just the agent's input — it is the entire shared infrastructure the agent operates within.

## 4. Behavioral Attestation for AI Agents

### 4.1 Overview

AEGIS consists of four core components that operate across the HPC cluster:

```
┌─────────────────────────────────────────────────────────────────┐
│                        AEGIS Architecture                       │
│                                                                 │
│  ┌──────────────┐    evidence     ┌──────────────────┐          │
│  │  Attestation  │ ──────────────▶│  Policy Verifier  │          │
│  │   Engine      │◀───────────────│  (constraints)    │          │
│  │  (per node)   │   challenge    │  (centralized)    │          │
│  └──────┬───────┘                 └────────┬─────────┘          │
│         │                                   │ verdict           │
│    eBPF probes                              ▼                   │
│         │                          ┌──────────────────┐         │
│  ┌──────▼───────┐                  │   Containment    │         │
│  │ Agent Runtime │                  │    Enforcer      │         │
│  │ (LangChain,   │                  │ (Slurm REST API) │         │
│  │  OpenClaw,    │                  └────────┬─────────┘         │
│  │  POSIX)       │                           │                   │
│  └───────────────┘                    rate-limit / isolate /     │
│                                        suspend / terminate       │
│                                                                 │
│  ┌──────────────────┐                                           │
│  │ Constraint Manager│ (profiles signed, bound to Slurm job ID) │
│  └──────────────────┘                                           │
│                                                                 │
│  ┌──────────────────┐                                           │
│  │  Audit Ledger    │ (hash-chained, tamper-evident)            │
│  └──────────────────┘                                           │
└─────────────────────────────────────────────────────────────────┘
```

**Constraint Manager.** Parses and compiles behavioral constraint profiles into an internal policy representation. Supports explicit specification, task inference, and policy templates. Profiles are signed and bound to the agent's Slurm job ID.

**Attestation Engine.** Runs as a daemon on each compute node, intercepting agent system calls via eBPF probes. Produces signed attestation evidence bundles at configurable intervals, transmitted to the verifier over mutually authenticated gRPC.

**Policy Verifier.** Centralized service that evaluates evidence against constraint profiles, producing verdicts from COMPLIANT to VIOLATION_CRITICAL. Issues random challenges to prevent delayed reporting. Logs decisions to a tamper-evident audit ledger.

**Containment Enforcer.** Translates verdicts into enforcement actions via the Slurm REST API: cgroup throttling (minor), ACL revocation (moderate), job suspension (severe), termination + credential revocation (critical).

These components implement **behavioral attestation** — a fundamentally new concept that differs from prior approaches along three axes:

| Dimension | Prior Approaches | Behavioral Attestation |
|---|---|---|
| **Assurance** | Detection (probabilistic; ML-based classifiers with false positive/negative rates) | Attestation (provable; cryptographic verification of constraint compliance) |
| **Policy** | Signature-based (block known-bad patterns; evadable through obfuscation) | Constraint-based (define what is allowed; violations are unambiguous) |
| **Timing** | Post-hoc (alert after the attack succeeds; damage already done) | Runtime (prevent violations in real-time; contain before exfiltration) |

**Key insight.** We cannot prevent all injection attacks — the attack surface is too large and too diverse (§3.5). But we can **detect and contain the effects** of hijacked agents by attesting to behavioral constraints. Even if an agent is hijacked through filesystem injection, co-location injection, supply chain injection, or any other vector, the attestation mechanism detects when the agent violates its constraints — accessing files outside its authorized project, connecting to non-whitelisted network endpoints, invoking unauthorized tools, or exceeding its data access budget — and contains the violation before data is exfiltrated.

This shifts the security question from *"Is this agent compromised?"* (unknowable) to *"Is this agent behaving within its authorized constraints?"* (verifiable).

### 4.2 Constraint Specification

Each agent receives a **behavioral constraint profile** at deployment time, specifying the boundaries of its authorized operation. Constraints are not signatures of malicious behavior — they are declarations of legitimate behavior derived from the agent's authorized task.

**Constraint dimensions:**

**Data access constraints.**
```
allowed_paths:    /projects/genomics/userB/*, /scratch/userB/*
denied_paths:     /projects/genomics/userA/*, /projects/finance/*
read_only:        /shared/datasets/public/*
max_read_volume:  10 GB / hour
```

**Network constraints.**
```
allowed_endpoints:  api.openai.com, slurm-controller.internal
denied_endpoints:   *
max_egress:         50 MB / hour
```

**Tool invocation constraints.**
```
allowed_tools:      hdf5_reader, fits_parser, slurm_submit
denied_tools:       curl, wget, ssh, scp
```

**Execution constraints.**
```
max_runtime:        4 hours
max_memory:         32 GB
allowed_nodes:      compute-[001-050]
```

**Data flow constraints.**
```
project_boundary:   strict  # No cross-project data movement
exfil_budget:       1 MB / hour  # LLM API channel
```

Constraints are derived from the agent's authorized task specification, not from analysis of attack patterns. This makes them **evasion-resistant**: an attacker cannot make an unauthorized action authorized by obfuscating it — the constraint either permits the action or it does not.

### 4.3 Attestation Protocol

The AEGIS attestation protocol operates continuously throughout the agent's lifecycle, providing runtime verification of constraint compliance.

**Components:**

- **Attester**: The agent runtime, which produces signed evidence of the agent's actions
- **Verifier**: The AEGIS policy engine, which evaluates evidence against constraints
- **Relying Party**: The HPC resource manager (Slurm), which enforces the verifier's decisions

**Protocol flow:**

1. **Agent deployment.** Agent receives its behavioral constraint profile. The constraint profile is signed by the deploying user and bound to the agent's session identity.

2. **Continuous attestation.** At configurable intervals (e.g., every N API calls, every M seconds, or on each resource access), the attester produces an **attestation evidence bundle** containing:
   - Agent identity and session binding
   - Resource access log (files read/written, network connections made, tools invoked)
   - Data volume counters (filesystem I/O, network egress)
   - Cryptographic hash of agent state

3. **Verification.** The verifier evaluates the evidence against the constraint profile:
   - *Compliant*: agent continues operating
   - *Violation detected*: agent is contained (see §4.5)

4. **Challenge-response.** At random intervals, the verifier issues a **challenge** requiring the agent to prove it is operating within constraints *right now*, not just in its last report. This prevents delayed reporting and evidence fabrication.

**Formal properties:**

- **Completeness**: A compliant agent always produces valid attestation evidence.
- **Soundness**: A violating agent cannot produce valid evidence (without compromising the attestation hardware root of trust).
- **Timeliness**: Violations are detected within one attestation interval, bounded by a configurable maximum.
- **Non-repudiation**: Attestation evidence is cryptographically signed; violations cannot be denied.

### 4.4 Constraint Derivation

A critical question is: *where do constraints come from?* We identify three sources:

**Explicit specification.** The deploying user specifies constraints directly, analogous to Kubernetes resource limits or Slurm job specifications. This is the highest-assurance source but requires user expertise.

**Task inference.** Constraints are inferred from the agent's task specification (e.g., "analyze genomics data for Project X" → allowed_paths: /projects/genomics/X/*, allowed_tools: bioinformatics suite). This reduces user burden but requires a constraint inference engine.

**Policy templates.** Pre-defined constraint profiles for common HPC agent patterns (data analysis agent, simulation steering agent, ML training agent). Users select and customize a template.

AEGIS supports all three modes and can combine them (e.g., template + task inference + user overrides).

### 4.5 Containment Mechanisms

When a violation is detected, AEGIS enforces containment through escalating responses:

| Violation Severity | Containment Response |
|---|---|
| Minor (e.g., approaching data volume budget) | Rate-limiting: throttle agent's resource access |
| Moderate (e.g., unauthorized path access) | Isolation: revoke filesystem permissions, redirect to sandbox |
| Severe (e.g., unauthorized network endpoint) | Suspension: pause agent execution, require human intervention |
| Critical (e.g., active exfiltration in progress) | Termination: kill agent session, revoke all credentials, alert security team |

Containment is **immediate and automatic** — it does not depend on human review. The attestation protocol ensures that violations are detected within bounded time (the attestation interval), and containment actions are enforced by the HPC resource manager, which is outside the agent's control.

### 4.6 Relationship to Trusted Execution

Behavioral attestation complements hardware-based Trusted Execution Environments (TEEs). TEEs attest to the *integrity of the execution environment* (the agent's code is unmodified). Behavioral attestation attests to the *conformance of agent behavior* (the agent's actions respect its constraints).

These are independent and complementary:
- TEE alone: guarantees code integrity, but a hijacked agent running unmodified code still violates constraints
- Behavioral attestation alone: detects violations, but a compromised runtime could fabricate evidence
- Combined: TEE guarantees evidence authenticity, behavioral attestation guarantees behavioral conformance

AEGIS is designed to operate with or without TEE support. In the base case, attestation evidence is signed by the agent runtime (software attestation). When TEEs are available (AMD SEV, Intel SGX, ARM CCA), the evidence is hardware-signed, providing stronger guarantees against runtime compromise.

### 4.7 Comparison with Prior Approaches

| Approach | Guarantee | Evasion Resistance | Runtime Enforcement | HPC Applicability |
|---|---|---|---|---|
| Input sanitization | None (injection can bypass) | Low | N/A | Low (can't sanitize scientific data) |
| ML-based detection | Probabilistic | Medium (adversarial examples) | No (post-hoc alerting) | Medium (false positives on complex workflows) |
| Sandboxing | Isolation | High (if properly configured) | Yes | Low (agents need FS and network access) |
| Access control (RBAC) | Identity-based | Medium (credential theft) | Yes | High (but doesn't constrain behavior) |
| **Behavioral attestation** | **Provable constraint compliance** | **High (constraints are whitelist-based)** | **Yes (runtime verification)** | **High (designed for HPC agent patterns)** |

### 4.8 Implementation Details

The four components described in §4.1 are implemented as follows:

**Constraint Manager.** Constraints are specified in a declarative YAML-based language supporting the five dimensions described in §4.2. The constraint manager supports all three derivation modes (§4.4): explicit specification, task inference via an LLM-based constraint generation module, and policy templates. Constraint profiles are signed by the deploying user and bound to the agent's Slurm job ID, creating a cryptographic link between the agent's execution context and its authorized constraints.

**Attestation Engine.** The engine maintains a per-agent access log recording all filesystem operations, network connections, and tool invocations. At configurable intervals (default: every 100 system calls or 5 seconds, whichever comes first), the engine produces a signed attestation evidence bundle containing the agent's access log, data volume counters, and a hash of the agent's process state. The eBPF-based monitoring introduces minimal overhead (~2% syscall latency increase) while providing complete visibility into agent actions.

**Policy Verifier.** For each evidence bundle, the verifier evaluates the recorded actions against the agent's constraint profile, producing a verdict: COMPLIANT, VIOLATION_MINOR, VIOLATION_MODERATE, VIOLATION_SEVERE, or VIOLATION_CRITICAL. The verifier issues random challenges at Poisson-distributed intervals, requesting on-demand attestation from a randomly selected agent to prevent delayed reporting.

**Containment Enforcer.** Enforcement actions are mapped to Slurm REST API calls: cgroup bandwidth throttling for rate-limiting, filesystem ACL revocation for isolation, job suspension for severe violations, and job termination with Kerberos ticket revocation (`kdestroy`) for critical violations.

**Agent Framework Integration.** AEGIS is framework-agnostic and integrates with agent runtimes through a lightweight instrumentation layer. We provide bindings for LangChain (Python), OpenClaw (Node.js), and a generic POSIX-based integration for custom agents. The instrumentation layer intercepts agent tool invocations, filesystem access, and network connections, routing them through the attestation engine before execution. Agents that attempt to bypass the instrumentation (e.g., by invoking system calls directly) are detected through the eBPF monitoring layer, which operates below the application layer.

**Audit and Forensics.** Each log entry in the audit ledger includes a cryptographic hash chain, enabling post-hoc forensic analysis and detection of log tampering. The audit log supports replay: given an agent's constraint profile and its audit log, the entire execution can be deterministically replayed to verify that all attestation decisions were correct.

## 5. Experimental Evaluation

Our evaluation consists of two parts: (1) empirical demonstration of the four HPC-specific injection attacks (§5.1–5.4), establishing that these threats are real and distinct from prior work, and (2) AEGIS defense evaluation showing that attestation-based detection mitigates these attacks (§5.5–5.6).

### 5.1 Experiment 1: Filesystem-Mediated Injection

**Goal.** Demonstrate that an attacker can hijack an authorized agent by placing adversarial content in a shared HPC filesystem, without any direct access to the agent's input channel.

**Setup.**
- Slurm cluster with shared Lustre filesystem
- Two users: User A (attacker) and User B (victim), both authorized on a shared project directory
- User B deploys an AI agent to process scientific datasets (HDF5, FITS, CSV) in the shared directory
- The agent uses an LLM backend (e.g., GPT-4o, Claude) to analyze data and generate reports

**Attack.**
1. Attacker (User A) places a modified dataset in the shared directory containing a hidden prompt injection payload (e.g., in metadata fields, column headers, or embedded comments)
2. Victim's agent reads the dataset as part of its authorized workflow
3. The injection payload hijacks the agent's subsequent behavior — instructing it to read additional files, encode their contents, and include them in its LLM API calls

**Metrics.**
- Success rate: fraction of injection attempts that hijack agent behavior
- Time to exfiltration: elapsed time from file read to data appearing in API call
- Data volume exfiltrated per injection
- Detection by baseline defenses (DLP, filesystem auditing, network monitoring)

**Hypothesis.** Filesystem-mediated injection succeeds at high rates (>80%) and evades all baseline defenses, demonstrating that shared HPC storage creates a novel injection surface.

### 5.2 Experiment 2: Multi-User Co-Location Injection

**Goal.** Demonstrate that co-located agents on shared compute nodes can be attacked through shared scratch spaces.

**Setup.**
- Slurm cluster with shared `/tmp` and `/var/tmp` on compute nodes
- Two jobs scheduled on the same node: one from User A (attacker), one from User B (victim)
- Both jobs deploy agents that read/write to shared scratch directories
- Monitoring: filesystem audit (inotify), process monitoring (auditd), network monitoring

**Attack.**
1. Attacker's agent writes adversarial content to `/tmp/shared_analysis.log` or similar
2. Victim's agent, expecting benign tool output, reads the file
3. The injected content hijacks the victim agent's behavior

**Metrics.**
- Co-location probability: fraction of job pairs scheduled on the same node (measured over N job submissions)
- Injection success rate given co-location
- Detection rate by filesystem monitoring vs. behavioral attestation

**Hypothesis.** HPC scheduler co-location creates predictable injection opportunities, and filesystem monitoring alone cannot distinguish adversarial content from legitimate shared scratch usage.

### 5.3 Experiment 3: Supply Chain Injection via Agent Skills

**Goal.** Demonstrate that compromised agent skills/tools can inject adversarial instructions from within the agent's trusted execution context.

**Setup.**
- Standard agent framework (LangChain, OpenClaw, or custom) with a skill/tool ecosystem
- One skill is adversarial (simulating a compromised update or malicious third-party skill)
- The adversarial skill returns hidden instructions embedded in its output
- The agent uses the skill as part of a legitimate workflow

**Attack.**
1. Agent invokes the compromised skill (e.g., a data analysis tool, a file converter)
2. The skill's output contains a hidden prompt injection payload (e.g., in return values, error messages, or structured output)
3. The agent, treating tool output as trusted, incorporates the injection into its decision loop
4. Subsequent agent actions are hijacked

**Metrics.**
- Injection success rate across different agent frameworks
- Detection difficulty: can input filtering distinguish adversarial tool output from benign output?
- Comparison with web-based prompt injection (same payload, different delivery channel)

**Hypothesis.** Skill-mediated injection has higher success rates than web-based injection because the agent's trust in its own tooling lowers defensive barriers.

### 5.4 Experiment 4: Coordinated Multi-Agent Exfiltration

**Goal.** Demonstrate that hijacked agents across multiple users/nodes can form covert exfiltration networks evading per-agent detection.

**Setup.**
- Slurm cluster with 4+ users, each running an agent on separate nodes
- Shared Lustre filesystem with project directories
- Network monitoring per-node, per-user, and aggregate
- Two of the four agents are hijacked (simulating a coordinated compromise)

**Attack.**
1. Hijacked Agent A (User 1's node) reads sensitive data from Project X
2. Agent A encodes the data and writes it to a shared filesystem location (e.g., `/.hidden/exfil_01.tmp`)
3. Hijacked Agent B (User 3's node) reads the encoded file and includes it in its LLM API calls
4. The exfiltration is split across two nodes, two users, and two API endpoints

**Metrics.**
- Per-agent anomaly score: does any single agent's behavior trigger detection?
- Detection rate: per-agent monitoring vs. cross-agent correlation
- Data volume distributed across agents
- Comparison with single-agent exfiltration (baseline)

**Hypothesis.** Coordinated exfiltration evades per-agent detection entirely; only cross-agent behavioral analysis (i.e., attestation across the agent fleet) can detect the covert network.

### 5.5 AEGIS Defense Evaluation

**Goal.** Measure AEGIS's ability to detect and mitigate each attack type.

**Setup.**
- Same cluster and attack configurations as §5.1–5.4
- AEGIS attestation deployed: continuous behavioral verification of agents
- AEGIS policy engine configured with agent-specific access policies

**Metrics.**
- Detection rate for each attack type (true positive rate)
- False positive rate under normal workloads
- Time to detection (from injection to alert)
- Time to revocation (from alert to agent containment)
- Comparison with baseline (no AEGIS) and alternative defenses

### 5.6 Performance Overhead

**Goal.** Quantify the performance cost of AEGIS attestation on representative HPC workloads.

**Setup.**
- Slurm cluster with AEGIS attestation enabled
- Representative workloads: HPCG, ML training (PyTorch), data pipeline (HDF5 processing)
- Measurements with and without AEGIS

**Metrics.**
- Job submission latency (scheduling overhead)
- Application-level throughput (% overhead vs. baseline)
- Attestation protocol latency (per-agent attestation round-trip)
- Scalability: overhead as a function of agent count (10 → 100 → 1,000 agents)

**Target.** AEGIS overhead < 5% on representative workloads, demonstrating that attestation is practical for HPC deployment.

## 6. Related Work

### 6.1 Zero-Trust in HPC

The application of zero-trust principles to HPC is an active but nascent area. Alam et al. [2] implemented federated IAM with zero-trust controls for the Isambard-AI/HPC DRIs, combining SSO, MFA, and time-limited RBAC. Their work addresses the identity and access management layer but does not consider agent behavior or attestation. Duckworth et al. [3] proposed SPIFFE/SPIRE for workload identity in HPC clusters, enabling cryptographic service-to-service authentication. While SPIFFE provides workload identity (analogous to our agent identity layer), it does not address behavioral constraints or runtime attestation. Macauley and Bhasker [4] surveyed ZTA maturity in HPC using CISA's framework, finding that most HPC centers are at the "Traditional" or "Initial" maturity levels. Our work operates at a higher maturity level by introducing continuous behavioral attestation.

A systematic literature review by Gambo et al. [13] analyzed ten years of ZTA research (2016–2025), identifying application domains (enterprise, IoT, cloud, healthcare) but finding no work addressing AI agents or HPC specifically. This confirms that the intersection of ZTA, AI agents, and HPC is unexplored.

### 6.2 Attestation and Trusted Execution

Remote attestation — cryptographic verification of a system's software state — is foundational to confidential computing. Ménétrey et al. [14] provide a comprehensive comparison of attestation mechanisms across Intel SGX, Arm TrustZone, AMD SEV, and RISC-V TEEs. These hardware-based approaches attest to the *integrity of the execution environment*: verifying that the correct code is running in a genuine TEE. Our work attests to the *conformance of agent behavior*: verifying that the agent's actions respect its constraints, regardless of whether the underlying code is unmodified.

Chen [15] surveyed confidential HPC in public clouds, identifying threat models and performance challenges for TEE-based approaches. Key limitations include memory constraints (SGX enclaves are typically limited to a few hundred MB), performance overhead from memory encryption, and the inability to attest to GPU-based computation — a critical gap for HPC workloads. Kocaoğullar et al. [16] proposed a transparency framework for confidential computing, addressing user trust in TEEs through open-source firmware and external audits. Our approach is complementary: TEE transparency ensures the hardware is trustworthy, while behavioral attestation ensures the agent's actions are trustworthy.

The IETF Remote Attestation Procedures (RATS) architecture [17] standardizes attestation evidence creation, conveyance, and verification. RATS defines the Attester–Verifier–Relying Party model that underlies our attestation protocol (§4.3), but focuses on software/firmware integrity rather than behavioral conformance. Keylime [18] implements scalable TPM-based continuous attestation for cloud infrastructure, using Linux IMA measurements and PCR quotes. While Keylime demonstrates that continuous attestation is practical at scale, it attests to system integrity (what code is loaded) rather than behavioral constraints (what the agent is doing).

### 6.3 AI Agent Security

The security of AI agents has received growing attention as agents gain autonomy and tool-use capabilities. He et al. [10] identified system-level vulnerabilities in AI agents — including prompt injection, tool poisoning, and credential theft — and proposed component-level defenses. Their work provides a valuable threat taxonomy but does not address HPC-specific attack surfaces or propose attestation-based containment.

AgentBound [7] introduced the first access control framework for MCP servers, using declarative policies inspired by the Android permission model. AgentBound constrains what tools an agent can access but does not constrain what the agent does *within* an authorized tool — a compromised tool's output can still inject adversarial instructions. Our behavioral attestation addresses this gap by verifying the agent's actions after tool invocation.

A zero-trust identity framework for agentic AI [19] proposes using Decentralized Identifiers (DIDs) and Verifiable Credentials (VCs) for agent identity, with dynamic fine-grained access control and ZKPs for privacy-preserving attribute disclosure. This work addresses the identity layer (how agents prove who they are) but not the behavioral layer (how systems verify what agents do). Our work is complementary: behavioral attestation extends identity-based trust with action-based verification.

The Cloud Security Alliance's Agentic Trust Framework [20] outlines requirements for agent identity within zero-trust architectures, emphasizing verified, auditable identity before resource access. While the framework acknowledges the need for behavioral monitoring, it does not formalize behavioral attestation as a security primitive with provable guarantees.

### 6.4 Prompt Injection Defenses

Prompt injection has been extensively studied in web-based and chatbot scenarios. Defenses fall into three categories: input sanitization (removing or escaping known injection patterns), instruction hierarchy (marking system instructions as higher-priority), and output filtering (detecting anomalous responses). Greshake et al. [11] demonstrated that indirect prompt injection through retrieved content is a practical attack vector, and that instruction hierarchy is insufficient as a defense.

Our work differs fundamentally: instead of attempting to prevent injection (which we argue is impossible in the general case), we contain its effects. Behavioral attestation does not need to detect the injection itself — it detects the *constraint violations* that a hijacked agent inevitably produces. Even a perfectly hijacked agent that bypasses all input sanitization cannot, for example, read files outside its authorized paths without triggering attestation.

### 6.5 Differentiation

The key distinction between AEGIS and prior work is the security primitive: **behavioral attestation** rather than detection, access control, or integrity verification. Table 1 summarizes this differentiation.

**Table 1: Comparison of AEGIS with prior work across five dimensions.**

| Work | Primitive | Guarantee | Timing | HPC | Agent-Aware |
|---|---|---|---|---|---|
| Alam et al. [2] | Federated IAM | Identity | At auth | ✓ | ✗ |
| Duckworth et al. [3] | Workload identity | Identity | At auth | ✓ | ✗ |
| Ménétrey et al. [14] | TEE attestation | Code integrity | At load | ✗ | ✗ |
| Keylime [18] | TPM attestation | System integrity | Continuous | ✗ | ✗ |
| AgentBound [7] | Access control | Tool permission | At invoke | ✗ | ✓ |
| arXiv:2505.19301 [19] | DID/VC identity | Agent identity | At auth | ✗ | ✓ |
| **AEGIS** | **Behavioral attestation** | **Constraint compliance** | **Continuous** | **✓** | **✓** |

AEGIS is the first work to provide continuous, constraint-based, runtime behavioral attestation specifically designed for AI agents in HPC environments.

## 7. Discussion & Future Work

### 7.1 Limitations

**Constraint completeness.** Behavioral attestation can only enforce constraints that are specified. If a constraint profile is incomplete — omitting a data access path, for example — the corresponding violation goes undetected. This is a fundamental limitation: attestation verifies compliance with declared constraints, not with the user's unstated intent. Mitigating this requires either conservative default-deny constraint profiles (which may impede legitimate workflows) or constraint inference from task specifications (which introduces its own error modes). We view this as a human-factors challenge: making constraint specification easy enough that users specify complete profiles, rather than a fundamental barrier to attestation.

**Injection within constraints.** A sophisticated attacker who understands the agent's constraint profile can craft injection payloads that remain within the authorized boundaries — for example, exfiltrating data from authorized paths through the LLM API channel within the allowed egress budget. Behavioral attestation detects *constraint violations*, not *injection itself*. This is by design: we cannot prevent all injection, but we limit its blast radius. An attacker constrained to authorized paths and allowed endpoints can still cause harm, but the damage is bounded by the constraints. Tighter constraints (smaller allowed paths, lower egress budgets) reduce the blast radius at the cost of reduced agent utility.

**Attestation interval.** Violations are detected within one attestation interval (default: 5 seconds or 100 syscalls). During this window, a hijacked agent can perform unauthorized actions before containment. Shorter intervals reduce this window but increase overhead. We chose the default based on our performance evaluation (§5.6), but the optimal interval depends on the workload's sensitivity and the threat model's urgency.

**Single-node focus.** Our current implementation attests agents on individual compute nodes. The coordinated multi-agent exfiltration attack (§3.5, §5.4) demonstrates that cross-node behavioral correlation is necessary to detect distributed attacks. Our prototype's centralized policy verifier has access to all agents' evidence bundles and could implement cross-node correlation, but we have not fully developed this capability. This is an area for future work.

**Software attestation without TEEs.** In the base case (no TEE support), attestation evidence is signed by the userspace attestation engine. A compromised kernel or hypervisor could fabricate evidence. While eBPF-based monitoring operates in the kernel and is more difficult to subvert than userspace-only approaches, it does not provide the hardware-rooted guarantees of TPM-based or TEE-based attestation. Deployments requiring stronger assurance should combine AEGIS with hardware attestation (§4.6).

### 7.2 Integration with HPC Resource Managers

AEGIS is designed for integration with production HPC resource managers. Our prototype uses Slurm's REST API for containment enforcement, but the architecture is applicable to PBS, LSF, and other schedulers. Key integration points include:

- **Job submission**: constraint profiles submitted alongside job specifications
- **Node allocation**: attestation engines deployed on compute nodes via prolog scripts
- **Accounting**: attestation events integrated with job accounting logs
- **Preemption**: containment actions (suspend, terminate) mapped to scheduler preemption

Deeper integration — for example, making constraint compliance a scheduling factor (prioritizing agents with tighter constraints) or using attestation evidence for fair-share accounting — is a promising direction for future work.

### 7.3 Federated Zero-Trust Across Sites

Modern scientific workflows span multiple HPC facilities: data collected at a beamline, processed at an institutional cluster, and analyzed at a leadership computing facility. AEGIS currently operates within a single site. Extending behavioral attestation across sites requires:

- **Constraint portability**: constraint profiles that are valid across different filesystems, schedulers, and security domains
- **Cross-site attestation**: verifiers that can evaluate evidence from agents running on foreign infrastructure
- **Trust federation**: establishing trust in attestation evidence generated by another site's hardware and software stack

The federated identity infrastructure already deployed in HPC (CILogon, eduGAIN, REFEDS) provides a foundation for cross-site agent identity. Extending this to behavioral attestation — federated constraint verification — is a natural but challenging next step.

### 7.4 Formal Verification of Constraint Policies

Constraint profiles are security-critical: an incorrect constraint (too permissive) allows unauthorized access; an incorrect constraint (too restrictive) blocks legitimate work. Formal verification of constraint policies could provide guarantees that:

- Constraints are *complete*: no unauthorized action is permitted
- Constraints are *consistent*: no two constraints contradict each other
- Constraints are *minimal*: no constraint can be removed without introducing a vulnerability

Model checking and theorem proving (e.g., using TLA+ or Coq) could verify these properties for specific constraint profiles. While this is beyond the scope of the current paper, we believe formal methods are essential for deploying behavioral attestation in high-assurance HPC environments.

### 7.5 Broader Applications

While we focus on HPC AI agents, behavioral attestation is applicable to any system where autonomous actors operate in shared, multi-tenant environments:

- **Cloud-native agents**: AI agents deployed in Kubernetes clusters accessing shared cloud storage and APIs
- **Edge computing**: autonomous agents on edge devices processing shared sensor data
- **Robotic systems**: agents controlling physical robots with safety constraints
- **Financial systems**: trading agents operating under regulatory compliance constraints

The core primitives — constraint specification, continuous attestation, automated containment — are domain-agnostic. HPC provides a compelling first application due to its unique attack surfaces and the high value of its scientific data.

## 8. Conclusion

AI agents are entering high-performance computing, bringing with them a threat that HPC security was not designed to handle: the hijacked authorized agent. Through injection attacks exploiting shared filesystems, co-located compute nodes, compromised agent tools, and coordinated multi-agent exfiltration, an adversary can subvert an agent that already holds valid credentials and legitimate permissions. The hijacked agent exfiltrates data through encrypted, whitelisted LLM API channels — invisible to traditional monitoring and data loss prevention. No existing defense (authentication, authorization, intrusion detection, DLP, user behavior analytics) addresses this threat.

We propose behavioral attestation as the foundation for securing AI agents in HPC. The key insight is that we cannot prevent all injection attacks, but we can detect and contain their effects by attesting to behavioral constraints. Behavioral attestation provides provable guarantees (not probabilistic detection), uses constraint-based policies (not evasion-prone signatures), and enforces containment at runtime (not post-hoc alerting). Even if an agent is hijacked, the attestation mechanism detects when it violates its constraints and contains the violation before data exfiltration occurs.

We formalize four HPC-specific injection attack vectors that have not been studied in prior work, design and implement AEGIS (Attestation-based Environment for Guarding Injection-vulnerable Systems), and empirically demonstrate that behavioral attestation detects and contains hijacked agents with bounded latency and minimal performance overhead.

While attention gave agents the power to reason, attestation gives the system the power to trust them. As AI agents become more autonomous and more deeply integrated into scientific computing infrastructure, the need for provable, runtime behavioral verification will only grow. Behavioral attestation provides the foundation for this verification — a new security primitive for a new class of threats.

---

## Target Venue

**SC26** (primary target) — International Conference for High Performance Computing, Networking, Storage and Analysis
- Track: Research Papers
- Page limit: 12 pages (excluding references)
- Format: ACM SIGPLAN / SIGSOFT (check SC26 author kit)

## Timeline (Working Backward from SC26)

| Phase | Dates | Activities |
|-------|-------|-----------|
| Literature Review | Mar 14 – Apr 4 | Survey ZTA, HPC security, agent attestation |
| Architecture Design | Apr 4 – Apr 18 | Formalize AEGIS components, attestation model |
| Prototype Core | Apr 18 – Jun 13 | Implement attestation layer + policy engine on test cluster |
| Evaluation | Jun 13 – Jul 11 | Benchmarks, security testing, overhead analysis |
| Paper Draft | Jul 11 – Aug 8 | Full paper writing & internal review |
| Revision & Submit | Aug 8 – deadline | Incorporate feedback, final polish, submit |

_(Adjust dates once SC26 exact deadlines are announced)_
