#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/run_sc26_eval.sh [options]

Run the documented SC26 evaluation workflow and write all artifacts into one
campaign directory under results/.

Options:
  --mode <all|real|simulated>   Which stages to run. Default: all
  --output-dir <path>           Campaign output directory. Default: results/sc26_run_<timestamp>
  --skip-build                  Skip make bpfall and make bench
  --with-exec                   Include the optional execve microbenchmark
  --collect-logs                Collect journalctl logs for aegis services when available
  --collect-configs             Copy /etc/aegis configs when available
  --help                        Show this help text

Environment:
  SUDO=<command>                Override sudo command when not running as root
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
  all|real|simulated) ;;
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

run_real() {
  run_cmd "${SUDO_PREFIX[@]}" python3 -m src.experiments.real.run_bpf_microbenchmark     --mode openat     --iters 200000     --repeats 9     --output "$OUTPUT_DIR/bpf_microbenchmark_openat.json"

  run_cmd "${SUDO_PREFIX[@]}" python3 -m src.experiments.real.run_bpf_microbenchmark     --mode read     --iters 200000     --size 4096     --probe-scope file     --output "$OUTPUT_DIR/bpf_microbenchmark_read.json"

  run_cmd "${SUDO_PREFIX[@]}" python3 -m src.experiments.real.run_bpf_microbenchmark     --mode connect     --iters 100000     --probe-scope network     --output "$OUTPUT_DIR/bpf_microbenchmark_connect.json"

  if [[ $WITH_EXEC -eq 1 ]]; then
    run_cmd "${SUDO_PREFIX[@]}" python3 -m src.experiments.real.run_bpf_microbenchmark       --mode execve       --iters 100000       --probe-scope exec       --output "$OUTPUT_DIR/bpf_microbenchmark_execve.json"
  fi

  run_cmd python3 -m src.experiments.real.run_latency_sweep     --repeats 3     --max-interval 10.0     --output "$OUTPUT_DIR/real_latency_sweep.json"

  for attack in filesystem colocation supply_chain coordinated; do
    run_cmd python3 -m src.experiments.real.run_real_latency_capture       --attack "$attack"       --interval 1.0       --repeats 3       --output "$OUTPUT_DIR/real_latency_${attack}.json"
  done

  run_cmd python3 -m src.experiments.real.run_ablation     --interval 1.0     --repeats 3     --output "$OUTPUT_DIR/real_ablation.json"
}

run_simulated() {
  run_cmd python3 -m src.experiments.simulated.run_all     --output "$OUTPUT_DIR/simulated_all_attacks.json"

  run_cmd python3 -m src.experiments.simulated.run_ablation     --output "$OUTPUT_DIR/simulated_ablation.json"

  run_cmd python3 -m src.experiments.simulated.run_false_positive     --output "$OUTPUT_DIR/simulated_false_positive.json"

  run_cmd python3 -m src.experiments.simulated.run_performance     --output "$OUTPUT_DIR/simulated_performance.json"

  run_cmd python3 -m src.experiments.simulated.run_baseline_comparison     --output "$OUTPUT_DIR/baseline_comparison.md"
}

if [[ $SKIP_BUILD -eq 0 ]]; then
  run_cmd make bpfall
  run_cmd make bench
fi

case "$MODE" in
  all)
    run_real
    run_simulated
    ;;
  real)
    run_real
    ;;
  simulated)
    run_simulated
    ;;
esac

run_cmd git rev-parse HEAD
GIT_HEAD="$(git rev-parse HEAD)"
printf '%s
' "$GIT_HEAD" > "$OUTPUT_DIR/commit.txt"

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
