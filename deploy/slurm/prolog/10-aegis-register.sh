#!/usr/bin/env bash
set -euo pipefail

AEGIS_ROOT="${AEGIS_ROOT:-/opt/aegis}"
AEGIS_REGISTRY_DIR="${AEGIS_REGISTRY_DIR:-/run/aegis/collector/registrations}"
AEGIS_VERIFIER_HOST="${AEGIS_VERIFIER_HOST:-aegis-controller}"
AEGIS_VERIFIER_SOCKET="${AEGIS_VERIFIER_SOCKET:-/run/aegis/verifier.sock}"
AEGIS_PROFILE_ROOT="${AEGIS_PROFILE_ROOT:-/shared/aegis/profiles}"
JOB_ID="${SLURM_JOB_ID:?missing SLURM_JOB_ID}"
JOB_USER="${SLURM_JOB_USER:?missing SLURM_JOB_USER}"
JOB_UID="${SLURM_JOB_UID:-$(id -u "${JOB_USER}")}"
AGENT_ID="${AEGIS_AGENT_ID:-job-${JOB_ID}}"
SESSION_ID="${AEGIS_SESSION_ID:-${JOB_ID}-$(date +%s)}"
PROFILE_PATH="${AEGIS_PROFILE_PATH:-${AEGIS_PROFILE_ROOT}/${JOB_ID}.yaml}"
CGROUP_PATH="${AEGIS_CGROUP_PATH:-/sys/fs/cgroup/slurm/job_${JOB_ID}}"
NODE_NAME="$(hostname -s)"
METADATA_JSON="$(printf '{"node":"%s","slurm_user":"%s"}' "${NODE_NAME}" "${JOB_USER}")"

cd "${AEGIS_ROOT}"
python3 -m src.deployment.collector.job_registry register   --registry-dir "${AEGIS_REGISTRY_DIR}"   --job-id "${JOB_ID}"   --agent-id "${AGENT_ID}"   --session-id "${SESSION_ID}"   --uid "${JOB_UID}"   --cgroup-path "${CGROUP_PATH}"   --profile-path "${PROFILE_PATH}"   --metadata-json "${METADATA_JSON}"

if [[ -f "${PROFILE_PATH}" ]]; then
  ssh -o BatchMode=yes "${AEGIS_VERIFIER_HOST}"     "cd '${AEGIS_ROOT}' && python3 -m src.deployment.control_plane.verifierd --config /etc/aegis/verifier.json register-profile --socket '${AEGIS_VERIFIER_SOCKET}' --profile '${PROFILE_PATH}'"
fi
