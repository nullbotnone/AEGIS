"""Logging infrastructure for tracking agent actions."""
import time
import json
from dataclasses import dataclass, field, asdict
from typing import List, Optional
from enum import Enum


class ActionType(Enum):
    FILE_READ = "file_read"
    FILE_WRITE = "file_write"
    LLM_CALL = "llm_call"
    TOOL_INVOCATION = "tool_invocation"
    NETWORK_CALL = "network_call"


@dataclass
class Action:
    timestamp: float
    action_type: ActionType
    agent_id: str
    details: dict
    violation: Optional[str] = None

    def to_dict(self):
        d = asdict(self)
        d["action_type"] = self.action_type.value
        return d


class ActionLogger:
    """Centralized logger for all agent actions. Used by attestation engine."""

    def __init__(self):
        self.actions: List[Action] = []
        self.violations: List[Action] = []

    def log(self, action_type: ActionType, agent_id: str, details: dict,
            violation: Optional[str] = None):
        action = Action(
            timestamp=time.time(),
            action_type=action_type,
            agent_id=agent_id,
            details=details,
            violation=violation
        )
        self.actions.append(action)
        if violation:
            self.violations.append(action)
        return action

    def get_agent_actions(self, agent_id: str) -> List[Action]:
        return [a for a in self.actions if a.agent_id == agent_id]

    def get_violations(self) -> List[Action]:
        return self.violations

    def get_action_count(self, agent_id: str, action_type: ActionType) -> int:
        return sum(1 for a in self.actions
                   if a.agent_id == agent_id and a.action_type == action_type)

    def clear(self):
        self.actions.clear()
        self.violations.clear()

    def summary(self) -> str:
        lines = [f"=== Action Log Summary ({len(self.actions)} actions) ==="]
        for action in self.actions:
            v = f" ⚠ VIOLATION: {action.violation}" if action.violation else ""
            lines.append(
                f"  [{action.timestamp:.4f}] {action.agent_id} "
                f"{action.action_type.value}: {action.details}{v}"
            )
        return "\n".join(lines)
