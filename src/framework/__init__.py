"""AEGIS - Adaptive Enforcement for Guarding Intelligence Systems.

Behavioral attestation framework for AI agents in HPC environments.
Detects and contains hijacked agents through continuous constraint verification.
"""

from framework.constraints import (
    ConstraintType,
    DataAccessConstraints,
    NetworkConstraints,
    ToolConstraints,
    ExecutionConstraints,
    DataFlowConstraints,
    ConstraintProfile,
)
from framework.attestation import ActionType, AgentAction, AttestationEvidence, AttestationEngine
from framework.verifier import Verdict, ConstraintViolation, VerificationResult, PolicyVerifier
from framework.containment import ContainmentAction, ContainmentDecision, ContainmentEnforcer
from framework.audit import AuditEntry, AuditLedger
from framework.agent_monitor import AgentMonitor
from framework.policy_engine import PolicyEngine

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
