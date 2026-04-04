"""Constraint specification and management for AEGIS.

Defines behavioral constraint profiles, derivation modes, and a constraint
manager that compiles signed profiles into the internal representation used by
verification and containment.
"""

from __future__ import annotations

import fnmatch
import hashlib
import hmac
import json
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Union

try:
    import yaml  # type: ignore[import-not-found]
except ModuleNotFoundError:
    yaml = None


def _parse_yaml_scalar(value: str) -> Any:
    """Parse a scalar value from a simple YAML subset."""
    lowered = value.lower()
    if lowered in {"true", "false"}:
        return lowered == "true"
    if lowered in {"null", "none", "~"}:
        return None
    if value.startswith(("'", '"')) and value.endswith(("'", '"')):
        return value[1:-1]
    try:
        return int(value)
    except ValueError:
        pass
    try:
        return float(value)
    except ValueError:
        pass
    return value


def _parse_yaml_block(lines: List[str], start: int, indent: int) -> tuple[Any, int]:
    """Parse a constrained indentation-based YAML mapping or list."""
    index = start
    while index < len(lines) and not lines[index].strip():
        index += 1

    if index >= len(lines):
        return {}, index

    stripped = lines[index].lstrip()
    if stripped.startswith("- "):
        items: List[Any] = []
        while index < len(lines):
            line = lines[index]
            if not line.strip():
                index += 1
                continue
            current_indent = len(line) - len(line.lstrip(" "))
            if current_indent < indent:
                break
            if current_indent != indent:
                raise ValueError(f"Invalid YAML indentation at line: {line!r}")
            item_text = line.strip()[2:].strip()
            if item_text:
                items.append(_parse_yaml_scalar(item_text))
                index += 1
                continue
            item_value, index = _parse_yaml_block(lines, index + 1, indent + 2)
            items.append(item_value)
        return items, index

    mapping: Dict[str, Any] = {}
    while index < len(lines):
        line = lines[index]
        if not line.strip():
            index += 1
            continue
        current_indent = len(line) - len(line.lstrip(" "))
        if current_indent < indent:
            break
        if current_indent != indent:
            raise ValueError(f"Invalid YAML indentation at line: {line!r}")
        key, separator, raw_value = line.strip().partition(":")
        if not separator:
            raise ValueError(f"Invalid YAML mapping entry: {line!r}")
        value = raw_value.strip()
        if value:
            mapping[key] = _parse_yaml_scalar(value)
            index += 1
            continue
        nested_value, index = _parse_yaml_block(lines, index + 1, indent + 2)
        mapping[key] = nested_value
    return mapping, index


def _yaml_safe_load(content: str) -> Dict[str, Any]:
    """Load YAML, falling back to a constrained built-in parser."""
    if yaml is not None:
        data = yaml.safe_load(content)
        return data or {}

    lines = [
        line.rstrip()
        for line in content.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    if not lines:
        return {}
    data, next_index = _parse_yaml_block(lines, 0, 0)
    if next_index != len(lines):
        raise ValueError("Unexpected trailing YAML content")
    if not isinstance(data, dict):
        raise ValueError("Constraint profiles must be YAML mappings")
    return data


def _yaml_format_scalar(value: Any) -> str:
    """Format a scalar value for YAML output."""
    if value is True:
        return "true"
    if value is False:
        return "false"
    if value is None:
        return "null"
    return str(value)


def _yaml_dump_lines(value: Any, indent: int = 0) -> List[str]:
    """Serialize a simple dict/list structure to YAML lines."""
    prefix = " " * indent
    if isinstance(value, dict):
        lines: List[str] = []
        for key, item in value.items():
            if isinstance(item, (dict, list)):
                lines.append(f"{prefix}{key}:")
                lines.extend(_yaml_dump_lines(item, indent + 2))
            else:
                lines.append(f"{prefix}{key}: {_yaml_format_scalar(item)}")
        return lines
    if isinstance(value, list):
        lines = []
        for item in value:
            if isinstance(item, (dict, list)):
                lines.append(f"{prefix}-")
                lines.extend(_yaml_dump_lines(item, indent + 2))
            else:
                lines.append(f"{prefix}- {_yaml_format_scalar(item)}")
        return lines
    return [f"{prefix}{_yaml_format_scalar(value)}"]


class ConstraintType(Enum):
    """Types of constraints enforced by behavioral attestation."""

    DATA_ACCESS = "data_access"
    NETWORK = "network"
    TOOL_INVOCATION = "tool_invocation"
    EXECUTION = "execution"
    DATA_FLOW = "data_flow"
    SIGNATURE = "signature"
    SYSTEM = "system"


class DerivationMode(Enum):
    """How a behavioral constraint profile was derived."""

    EXPLICIT = "explicit"
    TASK_INFERENCE = "task_inference"
    TEMPLATE = "template"


class PolicyTemplate(Enum):
    """Pre-built policy templates for common HPC agent patterns."""

    DATA_ANALYSIS = "data_analysis"
    SIMULATION_STEERING = "simulation_steering"
    ML_TRAINING = "ml_training"


@dataclass
class SignatureRule:
    """Optional signature rule used to augment constraint-based verification."""

    rule_id: str
    match_substrings: List[str] = field(default_factory=list)
    action_types: Set[str] = field(default_factory=set)
    severity: str = "violation_critical"
    description: str = "Known malicious pattern detected"

    def matches(self, action_type: str, payload: str) -> bool:
        if self.action_types and action_type not in self.action_types:
            return False
        if not self.match_substrings:
            return False
        lowered_payload = payload.lower()
        return any(fragment.lower() in lowered_payload for fragment in self.match_substrings)

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "match_substrings": list(self.match_substrings),
            "action_types": sorted(self.action_types),
            "severity": self.severity,
            "description": self.description,
        }

    @classmethod
    def from_dict(cls, data: dict) -> SignatureRule:
        return cls(
            rule_id=data["rule_id"],
            match_substrings=list(data.get("match_substrings", [])),
            action_types=set(data.get("action_types", [])),
            severity=data.get("severity", "violation_critical"),
            description=data.get("description", "Known malicious pattern detected"),
        )


@dataclass
class DataAccessConstraints:
    """Filesystem access constraints for an agent."""

    allowed_paths: Set[str] = field(default_factory=set)
    denied_paths: Set[str] = field(default_factory=set)
    read_only_paths: Set[str] = field(default_factory=set)
    max_read_volume_mb: Optional[float] = None
    max_write_volume_mb: Optional[float] = None

    def check_access(self, path: str, operation: str) -> tuple[bool, str]:
        for denied in self.denied_paths:
            if fnmatch.fnmatch(path, denied):
                return False, f"Path {path} matches denied pattern {denied}"

        if operation == "write":
            for read_only in self.read_only_paths:
                if fnmatch.fnmatch(path, read_only):
                    return False, f"Path {path} is read-only"

        if self.allowed_paths:
            if any(fnmatch.fnmatch(path, allowed) for allowed in self.allowed_paths):
                return True, "Access allowed"
            return False, f"Path {path} not in allowed paths"

        return True, "Access allowed (no path restrictions)"

    def to_dict(self) -> dict:
        return {
            "allowed_paths": sorted(self.allowed_paths),
            "denied_paths": sorted(self.denied_paths),
            "read_only_paths": sorted(self.read_only_paths),
            "max_read_volume_mb": self.max_read_volume_mb,
            "max_write_volume_mb": self.max_write_volume_mb,
        }

    @classmethod
    def from_dict(cls, data: dict) -> DataAccessConstraints:
        return cls(
            allowed_paths=set(data.get("allowed_paths", [])),
            denied_paths=set(data.get("denied_paths", [])),
            read_only_paths=set(data.get("read_only_paths", [])),
            max_read_volume_mb=data.get("max_read_volume_mb"),
            max_write_volume_mb=data.get("max_write_volume_mb"),
        )


@dataclass
class NetworkConstraints:
    """Network access constraints for an agent."""

    allowed_endpoints: Set[str] = field(default_factory=set)
    denied_endpoints: Set[str] = field(default_factory=set)
    max_egress_mb_per_hour: Optional[float] = None

    def check_connection(self, endpoint: str, data_size_mb: float = 0) -> tuple[bool, str]:
        for denied in self.denied_endpoints:
            if denied == "*" or fnmatch.fnmatch(endpoint, denied):
                if any(fnmatch.fnmatch(endpoint, allowed) for allowed in self.allowed_endpoints):
                    break
                return False, f"Endpoint {endpoint} is denied"

        if self.allowed_endpoints:
            if any(fnmatch.fnmatch(endpoint, allowed) for allowed in self.allowed_endpoints):
                return True, "Connection allowed"
            return False, f"Endpoint {endpoint} not in allowed endpoints"

        return True, "Connection allowed (no endpoint restrictions)"

    def to_dict(self) -> dict:
        return {
            "allowed_endpoints": sorted(self.allowed_endpoints),
            "denied_endpoints": sorted(self.denied_endpoints),
            "max_egress_mb_per_hour": self.max_egress_mb_per_hour,
        }

    @classmethod
    def from_dict(cls, data: dict) -> NetworkConstraints:
        return cls(
            allowed_endpoints=set(data.get("allowed_endpoints", [])),
            denied_endpoints=set(data.get("denied_endpoints", [])),
            max_egress_mb_per_hour=data.get("max_egress_mb_per_hour"),
        )


@dataclass
class ToolConstraints:
    """Tool invocation constraints for an agent."""

    allowed_tools: Set[str] = field(default_factory=set)
    denied_tools: Set[str] = field(default_factory=set)

    def check_invocation(self, tool_name: str) -> tuple[bool, str]:
        if tool_name in self.denied_tools:
            return False, f"Tool {tool_name} is denied"
        if self.allowed_tools and tool_name not in self.allowed_tools:
            return False, f"Tool {tool_name} not in allowed tools"
        return True, "Tool invocation allowed"

    def to_dict(self) -> dict:
        return {
            "allowed_tools": sorted(self.allowed_tools),
            "denied_tools": sorted(self.denied_tools),
        }

    @classmethod
    def from_dict(cls, data: dict) -> ToolConstraints:
        return cls(
            allowed_tools=set(data.get("allowed_tools", [])),
            denied_tools=set(data.get("denied_tools", [])),
        )


@dataclass
class ExecutionConstraints:
    """Execution and placement constraints for an agent."""

    max_runtime_seconds: Optional[int] = None
    max_memory_mb: Optional[int] = None
    allowed_nodes: Set[str] = field(default_factory=set)

    def to_dict(self) -> dict:
        return {
            "max_runtime_seconds": self.max_runtime_seconds,
            "max_memory_mb": self.max_memory_mb,
            "allowed_nodes": sorted(self.allowed_nodes),
        }

    @classmethod
    def from_dict(cls, data: dict) -> ExecutionConstraints:
        return cls(
            max_runtime_seconds=data.get("max_runtime_seconds"),
            max_memory_mb=data.get("max_memory_mb"),
            allowed_nodes=set(data.get("allowed_nodes", [])),
        )


@dataclass
class DataFlowConstraints:
    """Data-flow and cross-agent isolation constraints."""

    project_boundary_strict: bool = False
    cross_project_transfer: bool = False
    max_exfil_budget_mb_per_hour: Optional[float] = None
    allow_agent_data_sharing: bool = False
    allow_co_located_agent_reads: bool = False
    allow_inter_agent_communication: bool = False
    correlation_window_seconds: int = 30
    correlation_threshold: int = 1

    def to_dict(self) -> dict:
        return {
            "project_boundary_strict": self.project_boundary_strict,
            "cross_project_transfer": self.cross_project_transfer,
            "max_exfil_budget_mb_per_hour": self.max_exfil_budget_mb_per_hour,
            "allow_agent_data_sharing": self.allow_agent_data_sharing,
            "allow_co_located_agent_reads": self.allow_co_located_agent_reads,
            "allow_inter_agent_communication": self.allow_inter_agent_communication,
            "correlation_window_seconds": self.correlation_window_seconds,
            "correlation_threshold": self.correlation_threshold,
        }

    @classmethod
    def from_dict(cls, data: dict) -> DataFlowConstraints:
        return cls(
            project_boundary_strict=data.get("project_boundary_strict", False),
            cross_project_transfer=data.get("cross_project_transfer", False),
            max_exfil_budget_mb_per_hour=data.get("max_exfil_budget_mb_per_hour"),
            allow_agent_data_sharing=data.get("allow_agent_data_sharing", False),
            allow_co_located_agent_reads=data.get("allow_co_located_agent_reads", False),
            allow_inter_agent_communication=data.get("allow_inter_agent_communication", False),
            correlation_window_seconds=data.get("correlation_window_seconds", 30),
            correlation_threshold=data.get("correlation_threshold", 1),
        )


@dataclass
class ConstraintProfile:
    """Complete behavioral constraint profile for an agent session."""

    agent_id: str
    user_id: str
    project_id: str
    session_id: str
    slurm_job_id: str = ""
    derivation_mode: DerivationMode = DerivationMode.EXPLICIT
    template_name: Optional[str] = None
    task_description: Optional[str] = None
    inferred_rationale: List[str] = field(default_factory=list)

    data_access: DataAccessConstraints = field(default_factory=DataAccessConstraints)
    network: NetworkConstraints = field(default_factory=NetworkConstraints)
    tools: ToolConstraints = field(default_factory=ToolConstraints)
    execution: ExecutionConstraints = field(default_factory=ExecutionConstraints)
    data_flow: DataFlowConstraints = field(default_factory=DataFlowConstraints)
    signature_rules: List[SignatureRule] = field(default_factory=list)

    created_at: float = 0
    expires_at: Optional[float] = None
    compiled_policy: Dict[str, Any] = field(default_factory=dict)
    signature: Optional[str] = None

    def canonical_payload(self) -> dict:
        payload = {
            "agent_id": self.agent_id,
            "user_id": self.user_id,
            "project_id": self.project_id,
            "session_id": self.session_id,
            "slurm_job_id": self.slurm_job_id,
            "derivation_mode": self.derivation_mode.value,
            "template_name": self.template_name,
            "task_description": self.task_description,
            "inferred_rationale": list(self.inferred_rationale),
            "data_access": self.data_access.to_dict(),
            "network": self.network.to_dict(),
            "tools": self.tools.to_dict(),
            "execution": self.execution.to_dict(),
            "data_flow": self.data_flow.to_dict(),
            "signature_rules": [rule.to_dict() for rule in self.signature_rules],
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "compiled_policy": self.compiled_policy,
        }
        return payload

    def compile_policy(self) -> Dict[str, Any]:
        self.compiled_policy = {
            "binding": {
                "agent_id": self.agent_id,
                "session_id": self.session_id,
                "slurm_job_id": self.slurm_job_id,
                "project_id": self.project_id,
            },
            "derivation_mode": self.derivation_mode.value,
            "template_name": self.template_name,
            "data_access": {
                "allow": sorted(self.data_access.allowed_paths),
                "deny": sorted(self.data_access.denied_paths),
                "read_only": sorted(self.data_access.read_only_paths),
                "budgets": {
                    "read_mb": self.data_access.max_read_volume_mb,
                    "write_mb": self.data_access.max_write_volume_mb,
                },
            },
            "network": {
                "allow": sorted(self.network.allowed_endpoints),
                "deny": sorted(self.network.denied_endpoints),
                "egress_budget_mb_per_hour": self.network.max_egress_mb_per_hour,
            },
            "tools": {
                "allow": sorted(self.tools.allowed_tools),
                "deny": sorted(self.tools.denied_tools),
            },
            "execution": self.execution.to_dict(),
            "data_flow": self.data_flow.to_dict(),
            "signature_rules": [rule.to_dict() for rule in self.signature_rules],
        }
        return self.compiled_policy

    def bind_to_job(self, slurm_job_id: str) -> None:
        self.slurm_job_id = slurm_job_id
        self.compile_policy()

    def profile_hash(self) -> str:
        payload = json.dumps(self.canonical_payload(), sort_keys=True)
        return hashlib.sha256(payload.encode()).hexdigest()

    def sign(self, signing_key: str) -> str:
        payload = json.dumps(self.canonical_payload(), sort_keys=True)
        self.signature = hmac.new(
            signing_key.encode(),
            payload.encode(),
            hashlib.sha256,
        ).hexdigest()
        return self.signature

    def verify_signature(self, signing_key: str) -> bool:
        if not self.signature:
            return False
        payload = json.dumps(self.canonical_payload(), sort_keys=True)
        expected = hmac.new(
            signing_key.encode(),
            payload.encode(),
            hashlib.sha256,
        ).hexdigest()
        return hmac.compare_digest(expected, self.signature)

    def verify_binding(self, slurm_job_id: str) -> bool:
        return bool(self.slurm_job_id) and self.slurm_job_id == slurm_job_id

    def to_dict(self) -> dict:
        data = self.canonical_payload()
        data["signature"] = self.signature
        return data

    @classmethod
    def from_dict(cls, data: dict) -> ConstraintProfile:
        derivation_mode = data.get("derivation_mode", DerivationMode.EXPLICIT.value)
        return cls(
            agent_id=data["agent_id"],
            user_id=data["user_id"],
            project_id=data["project_id"],
            session_id=data["session_id"],
            slurm_job_id=data.get("slurm_job_id", ""),
            derivation_mode=DerivationMode(derivation_mode),
            template_name=data.get("template_name"),
            task_description=data.get("task_description"),
            inferred_rationale=list(data.get("inferred_rationale", [])),
            data_access=DataAccessConstraints.from_dict(data.get("data_access", {})),
            network=NetworkConstraints.from_dict(data.get("network", {})),
            tools=ToolConstraints.from_dict(data.get("tools", {})),
            execution=ExecutionConstraints.from_dict(data.get("execution", {})),
            data_flow=DataFlowConstraints.from_dict(data.get("data_flow", {})),
            signature_rules=[
                SignatureRule.from_dict(rule)
                for rule in data.get("signature_rules", [])
            ],
            created_at=data.get("created_at", 0),
            expires_at=data.get("expires_at"),
            compiled_policy=dict(data.get("compiled_policy", {})),
            signature=data.get("signature"),
        )

    @classmethod
    def from_yaml(cls, yaml_content: str) -> ConstraintProfile:
        return cls.from_dict(_yaml_safe_load(yaml_content))

    def to_yaml(self) -> str:
        if yaml is not None:
            return yaml.dump(self.to_dict(), default_flow_style=False, sort_keys=False)
        return "\n".join(_yaml_dump_lines(self.to_dict())) + "\n"


class ConstraintManager:
    """Parses, derives, compiles, and signs behavioral constraint profiles."""

    def __init__(self, signing_key: str = "constraint-manager"):
        self.signing_key = signing_key

    def compile_profile(self, profile: ConstraintProfile) -> ConstraintProfile:
        if not profile.created_at:
            profile.created_at = time.time()
        profile.compile_policy()
        return profile

    def sign_profile(self, profile: ConstraintProfile) -> ConstraintProfile:
        self.compile_profile(profile)
        profile.sign(self.signing_key)
        return profile

    def from_yaml(self, yaml_content: str, sign: bool = True) -> ConstraintProfile:
        profile = ConstraintProfile.from_yaml(yaml_content)
        self.compile_profile(profile)
        if sign:
            self.sign_profile(profile)
        return profile

    def from_template(
        self,
        template: Union[PolicyTemplate, str],
        *,
        agent_id: str,
        user_id: str,
        project_id: str,
        session_id: str,
        slurm_job_id: str,
        task_description: Optional[str] = None,
    ) -> ConstraintProfile:
        template_enum = template if isinstance(template, PolicyTemplate) else PolicyTemplate(template)
        project_root = f"/projects/{project_id}/*"
        scratch_root = f"/scratch/{user_id}/*"

        if template_enum == PolicyTemplate.DATA_ANALYSIS:
            profile = ConstraintProfile(
                agent_id=agent_id,
                user_id=user_id,
                project_id=project_id,
                session_id=session_id,
                slurm_job_id=slurm_job_id,
                derivation_mode=DerivationMode.TEMPLATE,
                template_name=template_enum.value,
                task_description=task_description,
                data_access=DataAccessConstraints(
                    allowed_paths={project_root, scratch_root},
                    read_only_paths={project_root},
                ),
                network=NetworkConstraints(allowed_endpoints={"api.openai.com"}),
                tools=ToolConstraints(allowed_tools={"python", "jupyter", "hdf5_reader"}),
                data_flow=DataFlowConstraints(project_boundary_strict=True),
            )
        elif template_enum == PolicyTemplate.SIMULATION_STEERING:
            profile = ConstraintProfile(
                agent_id=agent_id,
                user_id=user_id,
                project_id=project_id,
                session_id=session_id,
                slurm_job_id=slurm_job_id,
                derivation_mode=DerivationMode.TEMPLATE,
                template_name=template_enum.value,
                task_description=task_description,
                data_access=DataAccessConstraints(
                    allowed_paths={project_root, scratch_root, "/opt/simulations/*"},
                    read_only_paths={"/opt/simulations/*"},
                ),
                network=NetworkConstraints(allowed_endpoints={"slurmrestd.cluster.local"}),
                tools=ToolConstraints(allowed_tools={"sbatch", "squeue", "scancel", "python"}),
                data_flow=DataFlowConstraints(project_boundary_strict=True),
            )
        else:
            profile = ConstraintProfile(
                agent_id=agent_id,
                user_id=user_id,
                project_id=project_id,
                session_id=session_id,
                slurm_job_id=slurm_job_id,
                derivation_mode=DerivationMode.TEMPLATE,
                template_name=template_enum.value,
                task_description=task_description,
                data_access=DataAccessConstraints(
                    allowed_paths={project_root, scratch_root, f"/checkpoints/{project_id}/*"},
                ),
                network=NetworkConstraints(allowed_endpoints={"artifact-cache.cluster.local"}),
                tools=ToolConstraints(allowed_tools={"python", "torchrun", "nvidia-smi"}),
                data_flow=DataFlowConstraints(project_boundary_strict=True),
            )

        return self.sign_profile(profile)

    def infer_from_task(
        self,
        *,
        agent_id: str,
        user_id: str,
        project_id: str,
        session_id: str,
        slurm_job_id: str,
        task_description: str,
        llm_infer: Optional[Callable[[str], Dict[str, Any]]] = None,
    ) -> ConstraintProfile:
        if llm_infer is not None:
            inferred = llm_infer(task_description)
            profile = ConstraintProfile.from_dict({
                "agent_id": agent_id,
                "user_id": user_id,
                "project_id": project_id,
                "session_id": session_id,
                "slurm_job_id": slurm_job_id,
                "derivation_mode": DerivationMode.TASK_INFERENCE.value,
                "task_description": task_description,
                **inferred,
            })
            profile.derivation_mode = DerivationMode.TASK_INFERENCE
            return self.sign_profile(profile)

        description = task_description.lower()
        rationale: List[str] = []
        if any(keyword in description for keyword in ["train", "checkpoint", "gpu", "fine-tune"]):
            template = PolicyTemplate.ML_TRAINING
            rationale.append("Detected model training language, so the ML training template was selected.")
        elif any(keyword in description for keyword in ["simulate", "slurm", "queue", "mesh", "solver"]):
            template = PolicyTemplate.SIMULATION_STEERING
            rationale.append("Detected scheduler or simulation terms, so the simulation steering template was selected.")
        else:
            template = PolicyTemplate.DATA_ANALYSIS
            rationale.append("Defaulted to the data analysis template for read-heavy project workflows.")

        profile = self.from_template(
            template,
            agent_id=agent_id,
            user_id=user_id,
            project_id=project_id,
            session_id=session_id,
            slurm_job_id=slurm_job_id,
            task_description=task_description,
        )
        profile.derivation_mode = DerivationMode.TASK_INFERENCE
        profile.inferred_rationale = rationale
        self.compile_profile(profile)
        profile.sign(self.signing_key)
        return profile
