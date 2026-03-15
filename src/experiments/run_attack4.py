#!/usr/bin/env python3
"""Experiment 4: Coordinated Multi-Agent Exfiltration.

Demonstrates covert exfiltration network using multiple hijacked agents.
"""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from common.agent import Agent
from common.filesystem import SharedFilesystem
from common.constraints import create_strict_constraints
from common.logger import ActionLogger
from attacks.coordinated_exfiltration import CoordinatedExfiltrationAttack
from defense.attestation import AttestationEngine


def run_experiment():
    """Run the coordinated exfiltration experiment."""
    print("=" * 70)
    print("EXPERIMENT 4: COORDINATED MULTI-AGENT EXFILTRATION")
    print("=" * 70)
    print()

    # Step 1: Set up environment
    print("[1] Setting up environment...")
    logger = ActionLogger()
    filesystem = SharedFilesystem(logger=logger)

    # Create 4 agents on different nodes
    agent_configs = [
        ("user1", "finance", "node-1"),      # Hijacked — has access to finance data
        ("user2", "analytics", "node-2"),     # Benign
        ("user3", "research", "node-3"),      # Hijacked — exfiltrates via LLM
        ("user4", "engineering", "node-4"),   # Benign
    ]

    agents = []
    for user_id, project_id, node_id in agent_configs:
        constraints = create_strict_constraints(project_id, user_id)
        agent = Agent(
            user_id=user_id,
            project_id=project_id,
            constraints=constraints,
            filesystem=filesystem,
            logger=logger,
        )
        agents.append(agent)
        print(f"  Agent: {user_id} (project: {project_id}, node: {node_id})")

    print()
    print(f"  Agents 1 & 3 are HIJACKED (hidden from attestation)")
    print(f"  Agents 2 & 4 are BENIGN (decoys)")
    print()

    # Step 2: Execute attack
    print("[2] Executing coordinated attack...")
    attack = CoordinatedExfiltrationAttack()
    attack.setup(filesystem, agents)
    results = attack.execute()

    print(f"  Attack: {results['attack_name']}")
    print(f"  Phase 1 (Agent 1): {results['phase1']['action']}")
    print(f"    Data read: {results['phase1']['data_size_bytes']} bytes")
    print(f"    Covert write: {results['phase1']['encoded_size_bytes']} bytes")
    print(f"  Phase 2 (Agent 3): {results['phase2']['action']}")
    print(f"    Covert read: {results['phase2']['encoded_size_bytes']} bytes")
    print(f"    LLM calls: {results['phase2']['llm_calls_made']}")
    print(f"  Exfiltration succeeded: {results['exfiltration_succeeded']}")
    print()

    # Step 3: Measure exfiltration
    print("[3] Measuring exfiltration across all agents...")
    exfil = attack.measure_exfiltration()
    print(f"  Total exfiltrated: {exfil['total_exfiltrated_bytes']} bytes")
    print(f"  Finance data exfiltrated: {exfil['finance_data_exfiltrated']}")
    print(f"  Detection difficulty: {exfil['detection_difficulty']}")
    print()
    print("  Per-agent breakdown:")
    for m in exfil["per_agent_metrics"]:
        hijack = " [HIJACKED]" if m["hijacked"] else ""
        anomalous = " ⚠ ANOMALOUS" if m["looks_anomalous_alone"] else ""
        print(
            f"    Agent {m['agent_index']} ({m['user_id']}): "
            f"{m['egress_bytes']} bytes, {m['num_llm_calls']} LLM calls"
            f"{hijack}{anomalous}"
        )
    print()

    # Step 4: Run attestation defense
    print("[4] Running attestation defense...")
    attestation = AttestationEngine(logger)
    for agent in agents:
        attestation.register_agent(agent)
    attestation.start_monitoring()
    detections = attestation.analyze()

    print(attestation.report())

    # Step 5: Summary
    print("[5] EXPERIMENT RESULTS")
    print("-" * 40)
    attack_success = results['exfiltration_succeeded']
    detection_success = len(detections) > 0
    covert_channel_detected = any(
        d.detection_type == "covert_channel_detected" for d in detections
    )

    print(f"  Attack successful:        {attack_success}")
    print(f"  Attestation detected:     {detection_success}")
    print(f"  Covert channel detected:  {covert_channel_detected}")
    print(f"  Detection count:          {len(detections)}")
    print(f"  Detection time:           {attestation.detection_time_ms:.2f} ms")
    print()

    return {
        "attack_success": attack_success,
        "detection_success": detection_success,
        "covert_channel_detected": covert_channel_detected,
        "num_detections": len(detections),
        "detection_time_ms": attestation.detection_time_ms,
        "exfiltrated_bytes": exfil['total_exfiltrated_bytes'],
    }


if __name__ == "__main__":
    run_experiment()
