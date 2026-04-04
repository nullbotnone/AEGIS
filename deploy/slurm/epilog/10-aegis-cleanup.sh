#!/usr/bin/env bash
set -euo pipefail

AEGIS_ROOT="${AEGIS_ROOT:-/opt/aegis}"
AEGIS_REGISTRY_DIR="${AEGIS_REGISTRY_DIR:-/run/aegis/collector/registrations}"
AEGIS_VERIFIER_HOST="${AEGIS_VERIFIER_HOST:-aegis-controller}"
AEGIS_VERIFIER_SOCKET="${AEGIS_VERIFIER_SOCKET:-/run/aegis/verifier.sock}"
JOB_ID="${SLURM_JOB_ID:?missing SLURM_JOB_ID}"
AGENT_ID="${AEGIS_AGENT_ID:-job-${JOB_ID}}"
SESSION_ID="${AEGIS_SESSION_ID:-}"

cd "${AEGIS_ROOT}"
python3 -m src.deployment.collector.job_registry unregister   --registry-dir "${AEGIS_REGISTRY_DIR}"   --job-id "${JOB_ID}"

ssh -o BatchMode=yes "${AEGIS_VERIFIER_HOST}"   "cd '${AEGIS_ROOT}' && python3 -m src.deployment.control_plane.verifierd --config /etc/aegis/verifier.json close-session --socket '${AEGIS_VERIFIER_SOCKET}' --job-id '${JOB_ID}' ${AGENT_ID:+--agent-id '${AGENT_ID}'} ${SESSION_ID:+--session-id '${SESSION_ID}'}"
