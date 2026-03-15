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
        sudo python3 ../monitor/ebpf_monitor.py \
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
        sudo python3 ../monitor/ebpf_monitor.py \
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
        sudo python3 ../monitor/ebpf_monitor.py \
            --agent-id "agent-${label}" \
            --output "${RESULTS_DIR}/agent-monitor-${label}.jsonl" &
        MONITOR_PID=$!
    fi
    
    # Run a realistic agent workflow:
    # 1. Read several HDF5 files
    # 2. Process with Python
    # 3. Make LLM API call
    # 4. Write results
    
    START=$(date +%s.%N)
    
    python3 -c "
import time, os, json
import numpy as np

# Simulate reading HDF5 files
print('Reading data files...')
data = []
for i in range(5):
    fname = f'/projects/shared/aegis/data/sample_{i}.hdf5'
    if os.path.exists(fname):
        # Real file read
        with open(fname, 'rb') as f:
            content = f.read()
        data.append(len(content))
    else:
        # Synthetic data
        data.append(np.random.randn(1000, 64))
    time.sleep(0.1)  # Simulate I/O wait

# Simulate processing
print('Processing...')
result = np.mean([np.mean(d) if isinstance(d, np.ndarray) else d for d in data])
time.sleep(0.5)  # Simulate compute

# Make real LLM API call
print('Calling LLM...')
import urllib.request
api_key = os.environ.get('OPENAI_API_KEY', '')
if api_key:
    req = urllib.request.Request(
        'https://api.openai.com/v1/chat/completions',
        data=json.dumps({
            'model': 'gpt-4o-mini',
            'messages': [{'role': 'user', 'content': f'Summarize: mean={result:.2f}'}],
            'max_tokens': 100
        }).encode(),
        headers={
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {api_key}'
        }
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            response = json.loads(resp.read())
        print(f'LLM response received: {len(json.dumps(response))} bytes')
    except Exception as e:
        print(f'LLM call failed: {e}')
else:
    print('No API key, simulating LLM call...')
    time.sleep(1.0)

# Write results
print('Writing results...')
with open('${RESULTS_DIR}/agent-results-${label}.json', 'w') as f:
    json.dump({'mean': float(result), 'samples': len(data)}, f)

print('Done.')
" 2>&1 | tee "${RESULTS_DIR}/agent-workflow-${label}.log"
    
    END=$(date +%s.%N)
    ELAPSED=$(echo "$END - $START" | bc)
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
python3 ../scripts/analyze_overhead.py \
    --results-dir "${RESULTS_DIR}" \
    --output "${RESULTS_DIR}/overhead-report.json"

echo ""
echo "=== Overhead Measurement Complete ==="
cat "${RESULTS_DIR}/overhead-report.json" 2>/dev/null || echo "Report not generated"
