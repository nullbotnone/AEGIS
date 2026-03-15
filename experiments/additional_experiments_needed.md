# Additional Experiments Needed for Comprehensive Evaluation

## Current Coverage (Done)
- ✓ 4 attack demonstrations (threat is real)
- ✓ Basic attestation detection (defense works)

## Missing for SC Paper

### 1. Baseline Comparison (§5.5)
Compare AEGIS against alternative defenses to show it catches what they miss:
- **DLP (network-level)**: Can't see encrypted LLM API calls
- **Filesystem auditing (auditd/inotify)**: Sees file access but not intent/context
- **Per-agent behavioral analytics**: Misses coordinated multi-agent attacks
- **Sandboxing**: Too restrictive for HPC agents that need FS/network access

### 2. False Positive Rate
Run benign workloads and measure false alarms:
- Normal scientific data analysis workflows
- Multi-step ML training pipelines
- Collaborative multi-agent workflows (all benign)

### 3. Performance Overhead (§5.6)
Measure AEGIS overhead on representative workloads:
- Filesystem I/O intensive (HDF5 processing)
- Network intensive (ML training with data transfer)
- Compute intensive (HPCG-like)
- Varying attestation intervals (1s, 5s, 10s, 30s)

### 4. Scalability
How does overhead scale with agent count?
- 1, 10, 50, 100, 500 agents

### 5. Ablation Study
What happens when individual components are removed?
- No covert channel detection
- No volume limits
- No cross-agent correlation
- No challenge-response

### 6. Detection Latency vs. Attestation Interval
Trade-off between detection speed and overhead:
- Intervals: 0.1s, 0.5s, 1s, 5s, 10s, 30s, 60s
- Measure: detection time, overhead, missed violations (if any)
