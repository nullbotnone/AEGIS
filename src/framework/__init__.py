"""AEGIS - Adaptive Enforcement for Guarding Intelligence Systems.

Behavioral attestation framework for AI agents in HPC environments.
Detects and contains hijacked agents through continuous constraint verification.
"""

from .constraints import (
    ConstraintType,
    DataAccessConstraints,
    NetworkConstraints,
    ToolConstraints,
    ExecutionConstraints,
    DataFlowConstraints,
    ConstraintProfile,
)
from .attestation import ActionType, AgentAction, AttestationEvidence, AttestationEngine
from .verifier import Verdict, ConstraintViolation, VerificationResult, PolicyVerifier
from .containment import ContainmentAction, ContainmentDecision, ContainmentEnforcer
from .audit import AuditEntry, AuditLedger
from .agent_monitor import AgentMonitor
from .policy_engine import PolicyEngine

__all__ = [
    "ConstraintType",
    "DataAccessConstraints",
    "NetworkConstraints",
    "ToolConstraints",
    "ExecutionConstraints",
    "DataFlowConstraints",
    "ConstraintProfile",
    "ActionType",
    "AgentAction",
    "AttestationEvidence",
    "AttestationEngine",
    "Verdict",
    "ConstraintViolation",
    "VerificationResult",
    "PolicyVerifier",
    "ContainmentAction",
    "ContainmentDecision",
    "ContainmentEnforcer",
    "AuditEntry",
    "AuditLedger",
    "AgentMonitor",
    "PolicyEngine",
]
