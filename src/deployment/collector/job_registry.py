"""File-backed job registration for the node-local AEGIS collector.

Slurm Prolog/Epilog hooks can write registrations into this directory without
having to talk to a long-running collector process over a custom IPC channel.
The collector resolves PID -> Slurm job identity by inspecting cgroups and then
looking up the registration here.
"""

from __future__ import annotations

import argparse
import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional


@dataclass
class JobRegistration:
    """A registered Slurm job bound to an AEGIS agent session."""

    job_id: str
    agent_id: str
    session_id: str
    uid: Optional[int] = None
    cgroup_path: Optional[str] = None
    profile_path: Optional[str] = None
    created_at: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "JobRegistration":
        return cls(
            job_id=str(data["job_id"]),
            agent_id=str(data["agent_id"]),
            session_id=str(data["session_id"]),
            uid=data.get("uid"),
            cgroup_path=data.get("cgroup_path"),
            profile_path=data.get("profile_path"),
            created_at=float(data.get("created_at", time.time())),
            metadata=dict(data.get("metadata", {})),
        )


class JobRegistry:
    """Filesystem-backed registration store for node collectors."""

    def __init__(self, registry_dir: str = "/run/aegis/collector/registrations"):
        self.registry_dir = Path(registry_dir)
        self.registry_dir.mkdir(parents=True, exist_ok=True)

    def _path(self, job_id: str) -> Path:
        return self.registry_dir / f"{job_id}.json"

    def register(self, registration: JobRegistration) -> Path:
        path = self._path(registration.job_id)
        path.write_text(
            json.dumps(registration.to_dict(), sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )
        return path

    def unregister(self, job_id: str) -> bool:
        path = self._path(job_id)
        if not path.exists():
            return False
        path.unlink()
        return True

    def get(self, job_id: str) -> Optional[JobRegistration]:
        path = self._path(job_id)
        if not path.exists():
            return None
        return JobRegistration.from_dict(json.loads(path.read_text(encoding="utf-8")))

    def list(self) -> Dict[str, JobRegistration]:
        registrations: Dict[str, JobRegistration] = {}
        for path in sorted(self.registry_dir.glob("*.json")):
            registration = JobRegistration.from_dict(json.loads(path.read_text(encoding="utf-8")))
            registrations[registration.job_id] = registration
        return registrations


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="AEGIS collector job registry")
    parser.add_argument("--registry-dir", default="/run/aegis/collector/registrations")
    subparsers = parser.add_subparsers(dest="command", required=True)

    register = subparsers.add_parser("register", help="Register a Slurm job")
    register.add_argument("--job-id", required=True)
    register.add_argument("--agent-id", required=True)
    register.add_argument("--session-id", required=True)
    register.add_argument("--uid", type=int)
    register.add_argument("--cgroup-path")
    register.add_argument("--profile-path")
    register.add_argument("--metadata-json", default="{}")

    unregister = subparsers.add_parser("unregister", help="Remove a registration")
    unregister.add_argument("--job-id", required=True)

    show = subparsers.add_parser("show", help="Show a registration")
    show.add_argument("--job-id", required=True)

    subparsers.add_parser("list", help="List all registrations")
    return parser


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()
    registry = JobRegistry(args.registry_dir)

    if args.command == "register":
        registration = JobRegistration(
            job_id=args.job_id,
            agent_id=args.agent_id,
            session_id=args.session_id,
            uid=args.uid,
            cgroup_path=args.cgroup_path,
            profile_path=args.profile_path,
            metadata=json.loads(args.metadata_json),
        )
        path = registry.register(registration)
        print(json.dumps({"status": "registered", "path": str(path)}))
        return

    if args.command == "unregister":
        removed = registry.unregister(args.job_id)
        print(json.dumps({"status": "removed" if removed else "missing", "job_id": args.job_id}))
        return

    if args.command == "show":
        registration = registry.get(args.job_id)
        if registration is None:
            raise SystemExit(f"registration not found for job {args.job_id}")
        print(json.dumps(registration.to_dict(), indent=2, sort_keys=True))
        return

    print(
        json.dumps(
            {job_id: registration.to_dict() for job_id, registration in registry.list().items()},
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
