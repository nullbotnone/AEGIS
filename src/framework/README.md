# AEGIS Framework

**Adaptive Enforcement for Guarding Intelligence Systems**

AEGIS is a behavioral attestation framework for AI agents operating in High-Performance Computing (HPC) environments. It provides continuous runtime monitoring, constraint verification, and automated containment of hijacked or compromised agents.

## Architecture

AEGIS consists of five core components:

### 1. Constraint Manager (`constraints.py`)

Defines and manages constraint profiles that specify what an agent is allowed to do:

- **Data Access Constraints** — filesystem path allow/deny lists with glob patterns, read-only enforcement, volume limits
- **Network Constraints** — endpoint allow/deny lists, egress bandwidth budgets
- **Tool Constraints** — allowed/denied tool invocations
- **Execution Constraints** — runtime limits, memory limits, node restrictions
- **Data Flow Constraints** — project boundary enforcement, exfiltration budgets

Constraint profiles are YAML-parseable and support cryptographic signing for tamper resistance.

### 2. Attestation Engine (`attestation.py`)

Simulates the eBPF-based syscall interception layer that runs on compute nodes. The engine:

- Monitors agent actions (file I/O, network, tool invocations, LLM API calls)
- Maintains per-agent action buffers and volume counters
- Generates signed evidence bundles at configurable intervals
- Supports random challenge-response for spot attestation

### 3. Policy Verifier (`verifier.py`)

Evaluates attestation evidence against constraint profiles:

- Checks each recorded action against applicable constraints
- Evaluates volume-based constraints (data budgets, egress rates)
- Produces verdicts: `COMPLIANT`, `VIOLATION_MINOR`, `VIOLATION_MODERATE`, `VIOLATION_SEVERE`, `VIOLATION_CRITICAL`
- Maintains verification history for audit

### 4. Containment Enforcer (`containment.py`)

Translates verification verdicts into enforcement actions:

| Verdict | Action |
|---------|--------|
| COMPLIANT | None |
| VIOLATION_MINOR | Rate-limit (cgroup throttling) |
| VIOLATION_MODERATE | Isolate (revoke ACLs, sandbox) |
| VIOLATION_SEVERE | Suspend (pause job, require human review) |
| VIOLATION_CRITICAL | Terminate (kill session, revoke creds, alert security) |

### 5. Audit Ledger (`audit.py`)

Tamper-evident, append-only ledger with hash-chain integrity:

- Every attestation, verification, and containment event is logged
- Each entry includes a SHA-256 hash chain for integrity verification
- Supports deterministic replay of agent execution history
- `verify_integrity()` validates the entire chain

## Usage

```python
from src.framework import PolicyEngine, ConstraintProfile, DataAccessConstraints, NetworkConstraints

# Create constraint profile
constraints = ConstraintProfile(
    agent_id="my_agent",
    user_id="researcher1",
    project_id="genomics",
    session_id="sess_001",
    data_access=DataAccessConstraints(
        allowed_paths={"/projects/genomics/*"},
        denied_paths={"/projects/finance/*"},
    ),
    network=NetworkConstraints(
        allowed_endpoints={"api.openai.com"},
    ),
)

# Initialize AEGIS
engine = PolicyEngine(attestation_interval=5)
monitor = engine.register_agent("my_agent", "researcher1", "genomics", constraints)
engine.start()

# Agent actions are recorded through the monitor
monitor.on_file_read("/projects/genomics/data.h5", size_mb=100)
monitor.on_llm_api_call("api.openai.com", prompt_size_kb=5)

# Check agent status
status = engine.get_agent_status("my_agent")
print(status)

# Verify audit ledger integrity
is_valid, _ = engine.audit.verify_integrity()

# Stop attestation loop
engine.stop()
```

## Testing

```bash
cd AEGIS
python -m unittest discover -s src/framework/tests -v
```

## Production Integration

In production, AEGIS integrates with:

- **eBPF probes** for syscall interception (replaces `AgentMonitor` method calls)
- **Slurm REST API** for job containment (replaces simulated enforcement)
- **Kerberos** for credential management on termination
- **SIEM** for security alert forwarding

## License

Research software for the AEGIS paper.
