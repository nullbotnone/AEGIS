#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/run_sc26_eval.sh [options]

Run the documented SC26 evaluation workflow and write all artifacts into one
campaign directory under results/.

Options:
  --mode <smoke|core|all|real|simulated>
                               Which campaign tier to run. Default: all
                               smoke: quick environment validation
                               core: main-paper artifact set
                               all: core + appendix/extended studies
  --output-dir <path>          Campaign output directory. Default: results/sc26_run_<timestamp>
  --skip-build                 Skip make bpfall and make bench
  --with-exec                  Include the optional execve microbenchmark in real-mode runs
  --collect-logs               Collect journalctl logs for aegis services when available
  --collect-configs            Copy /etc/aegis configs when available
  --help                       Show this help text

Environment:
  SUDO=<command>               Override sudo command when not running as root
EOF
}

MODE="all"
OUTPUT_DIR=""
SKIP_BUILD=0
WITH_EXEC=0
COLLECT_LOGS=0
COLLECT_CONFIGS=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode)
      MODE="$2"
      shift 2
      ;;
    --output-dir)
      OUTPUT_DIR="$2"
      shift 2
      ;;
    --skip-build)
      SKIP_BUILD=1
      shift
      ;;
    --with-exec)
      WITH_EXEC=1
      shift
      ;;
    --collect-logs)
      COLLECT_LOGS=1
      shift
      ;;
    --collect-configs)
      COLLECT_CONFIGS=1
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

case "$MODE" in
  smoke|core|all|real|simulated) ;;
  *)
    echo "Invalid mode: $MODE" >&2
    exit 1
    ;;
esac

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
if [[ -z "$OUTPUT_DIR" ]]; then
  OUTPUT_DIR="results/sc26_run_${TIMESTAMP}"
fi
mkdir -p "$OUTPUT_DIR"

if [[ ${EUID:-$(id -u)} -eq 0 ]]; then
  SUDO_PREFIX=()
else
  SUDO_BIN="${SUDO:-sudo}"
  SUDO_PREFIX=("$SUDO_BIN")
fi

run_cmd() {
  echo
  echo "+ $*"
  "$@"
}

run_microbenchmark() {
  local mode="$1"
  local iters="$2"
  local repeats="$3"
  local output="$4"
  shift 4

  run_cmd "${SUDO_PREFIX[@]}" python3 -m src.paper.experiments.real.run_bpf_microbenchmark     --mode "$mode"     --iters "$iters"     --repeats "$repeats"     --skip-build     "$@"     --output "$output"
}

run_real_smoke() {
  run_microbenchmark openat 50000 3 "$OUTPUT_DIR/smoke_bpf_microbenchmark_openat.json"

  run_cmd python3 -m src.paper.experiments.real.run_real_latency_capture     --attack filesystem     --interval 1.0     --repeats 1     --output "$OUTPUT_DIR/smoke_real_latency_filesystem.json"
}

run_real_core() {
  run_microbenchmark openat 200000 9 "$OUTPUT_DIR/bpf_microbenchmark_openat.json"
  run_microbenchmark read 200000 9 "$OUTPUT_DIR/bpf_microbenchmark_read.json" --size 4096 --probe-scope file
  run_microbenchmark connect 100000 9 "$OUTPUT_DIR/bpf_microbenchmark_connect.json" --probe-scope network

  if [[ $WITH_EXEC -eq 1 ]]; then
    run_microbenchmark execve 100000 9 "$OUTPUT_DIR/bpf_microbenchmark_execve.json" --probe-scope exec
  fi

  run_cmd python3 -m src.paper.experiments.real.run_latency_sweep     --repeats 3     --max-interval 10.0     --output "$OUTPUT_DIR/real_latency_sweep.json"

  for attack in filesystem colocation supply_chain coordinated; do
    run_cmd python3 -m src.paper.experiments.real.run_real_latency_capture       --attack "$attack"       --interval 1.0       --repeats 3       --output "$OUTPUT_DIR/real_latency_${attack}.json"
  done

  run_cmd python3 -m src.paper.experiments.real.run_ablation     --interval 1.0     --repeats 3     --output "$OUTPUT_DIR/real_ablation.json"
}

run_simulated_smoke() {
  run_cmd python3 -m src.paper.experiments.simulated.run_all     --output "$OUTPUT_DIR/smoke_simulated_all_attacks.json"

  run_cmd python3 -m src.paper.experiments.simulated.run_false_positive     --output "$OUTPUT_DIR/smoke_simulated_false_positive.json"
}

run_simulated_core() {
  run_cmd python3 -m src.paper.experiments.simulated.run_all     --output "$OUTPUT_DIR/simulated_all_attacks.json"

  run_cmd python3 -m src.paper.experiments.simulated.run_ablation     --output "$OUTPUT_DIR/simulated_ablation.json"

  run_cmd python3 -m src.paper.experiments.simulated.run_false_positive     --output "$OUTPUT_DIR/simulated_false_positive.json"

  run_cmd python3 -m src.paper.experiments.simulated.run_baseline_comparison     --output "$OUTPUT_DIR/baseline_comparison.md"
}

run_simulated_extended() {
  run_cmd python3 -m src.paper.experiments.simulated.run_performance     --output "$OUTPUT_DIR/simulated_performance.json"
}

if [[ $SKIP_BUILD -eq 0 ]]; then
  run_cmd make bpfall
  run_cmd make bench
fi

case "$MODE" in
  smoke)
    run_real_smoke
    run_simulated_smoke
    ;;
  core)
    run_real_core
    run_simulated_core
    ;;
  all)
    run_real_core
    run_simulated_core
    run_simulated_extended
    ;;
  real)
    run_real_core
    ;;
  simulated)
    run_simulated_core
    run_simulated_extended
    ;;
esac

if GIT_HEAD="$(git rev-parse HEAD 2>/dev/null)"; then
  printf '%s
' "$GIT_HEAD" > "$OUTPUT_DIR/commit.txt"
else
  printf '%s
' "unavailable" > "$OUTPUT_DIR/commit.txt"
fi

if [[ $COLLECT_CONFIGS -eq 1 ]]; then
  cp /etc/aegis/verifier.json "$OUTPUT_DIR/" 2>/dev/null || true
  cp /etc/aegis/collector.env "$OUTPUT_DIR/" 2>/dev/null || true
fi

if [[ $COLLECT_LOGS -eq 1 ]]; then
  if command -v journalctl >/dev/null 2>&1; then
    journalctl -u aegis-verifier.service > "$OUTPUT_DIR/verifier.log" 2>/dev/null || true
    journalctl -u aegis-collector.service > "$OUTPUT_DIR/collector.log" 2>/dev/null || true
  fi
fi

echo
echo "SC26 evaluation artifacts written to: $OUTPUT_DIR"
