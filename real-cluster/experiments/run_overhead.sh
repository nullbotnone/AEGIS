#!/bin/bash
# =============================================================================
# AEGIS Overhead Measurement Framework
# =============================================================================
#
# Measures AEGIS overhead on real HPC workloads:
# 1. HPCG (compute-bound)
# 2. IOR (I/O-bound)  
# 3. ML training (mixed)
# 4. Custom agent workflow (AEGIS-relevant)
#
# Each workload runs with and without AEGIS monitoring enabled.
# Results are collected and compared.
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
RESULTS_DIR="/projects/shared/aegis/overhead-results"
mkdir -p "${RESULTS_DIR}"

echo "============================================"
echo "AEGIS Overhead Measurement"
echo "Date: $(date)"
echo "============================================"

# --- Workload 1: HPCG (Compute-Bound) ---
run_hpcg_benchmark() {
    local monitor_enabled=$1
    local label=$2
    
    echo "[HPCG] Running with monitor=${monitor_enabled}..."
    
    if [ "$monitor_enabled" = "true" ]; then
        # Start AEGIS monitor
        sudo python3 "${PROJECT_DIR}/monitor/ebpf_monitor.py" \
            --agent-id "hpcg-${label}" \
            --output "${RESULTS_DIR}/hpcg-monitor-${label}.jsonl" &
        MONITOR_PID=$!
    fi
    
    # Run HPCG (if installed)
    if command -v xhpcg &> /dev/null; then
        mpirun -np 4 xhpcg 2>&1 | tee "${RESULTS_DIR}/hpcg-${label}.log"
    else
        # Fallback: CPU-bound synthetic benchmark
        echo "[HPCG] HPCG not found, using sysbench..."
        sysbench cpu --cpu-max-prime=20000 --threads=4 run 2>&1 | tee "${RESULTS_DIR}/hpcg-${label}.log"
    fi
    
    if [ -n "${MONITOR_PID:-}" ]; then
        sudo kill ${MONITOR_PID} 2>/dev/null || true
        unset MONITOR_PID
    fi
}

# --- Workload 2: IOR (I/O-Bound) ---
run_ior_benchmark() {
    local monitor_enabled=$1
    local label=$2
    
    echo "[IOR] Running with monitor=${monitor_enabled}..."
    
    if [ "$monitor_enabled" = "true" ]; then
        sudo python3 "${PROJECT_DIR}/monitor/ebpf_monitor.py" \
            --agent-id "ior-${label}" \
            --output "${RESULTS_DIR}/ior-monitor-${label}.jsonl" &
        MONITOR_PID=$!
    fi
    
    # Run IOR (if installed)
    if command -v ior &> /dev/null; then
        ior -a POSIX -b 1G -t 1M -s 100 -o "${RESULTS_DIR}/ior-test" 2>&1 | tee "${RESULTS_DIR}/ior-${label}.log"
    else
        # Fallback: dd benchmark
        echo "[IOR] IOR not found, using dd..."
        dd if=/dev/zero of="${RESULTS_DIR}/dd-test-${label}" bs=1M count=1024 conv=fdatasync 2>&1 | tee "${RESULTS_DIR}/ior-${label}.log"
    fi
    
    if [ -n "${MONITOR_PID:-}" ]; then
        sudo kill ${MONITOR_PID} 2>/dev/null || true
        unset MONITOR_PID
    fi
}

# --- Workload 3: Agent Workflow ---
run_agent_workflow() {
    local monitor_enabled=$1
    local label=$2
    
    echo "[Agent] Running workflow with monitor=${monitor_enabled}..."
    
    if [ "$monitor_enabled" = "true" ]; then
        sudo python3 "${PROJECT_DIR}/monitor/ebpf_monitor.py" \
            --agent-id "agent-${label}" \
            --output "${RESULTS_DIR}/agent-monitor-${label}.jsonl" &
        MONITOR_PID=$!
    fi
    
    # Run agent workflow using a Python helper script
    AGENT_START=$(date +%s.%N)
    
    python3 "${PROJECT_DIR}/scripts/run_agent_workflow.py" \
        --results-dir "${RESULTS_DIR}" \
        --label "${label}" \
        --api-key "${OPENAI_API_KEY:-}" 2>&1 | tee "${RESULTS_DIR}/agent-workflow-${label}.log"
    
    AGENT_END=$(date +%s.%N)
    ELAPSED=$(echo "$AGENT_END - $AGENT_START" | bc 2>/dev/null || echo "N/A")
    echo "Total time: ${ELAPSED}s" | tee -a "${RESULTS_DIR}/agent-workflow-${label}.log"
    
    if [ -n "${MONITOR_PID:-}" ]; then
        sudo kill ${MONITOR_PID} 2>/dev/null || true
        unset MONITOR_PID
    fi
}

# --- Main: Run all workloads ---
echo ""
echo "=== Phase 1: Baseline (no monitoring) ==="
run_hpcg_benchmark false "baseline"
run_ior_benchmark false "baseline"
run_agent_workflow false "baseline"

echo ""
echo "=== Phase 2: With AEGIS monitoring ==="
run_hpcg_benchmark true "aegis"
run_ior_benchmark true "aegis"
run_agent_workflow true "aegis"

echo ""
echo "=== Analyzing Results ==="
python3 "${PROJECT_DIR}/scripts/analyze_overhead.py" \
    --results-dir "${RESULTS_DIR}" \
    --output "${RESULTS_DIR}/overhead-report.json"

echo ""
echo "=== Overhead Measurement Complete ==="
cat "${RESULTS_DIR}/overhead-report.json" 2>/dev/null || echo "Report not generated"
