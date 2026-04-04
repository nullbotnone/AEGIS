#!/usr/bin/env python3
"""Experiment 2: Multi-User Co-Location Injection.

Demonstrates attack through shared scratch space on co-located compute nodes.
"""
from src.paper.support.agent import Agent
from src.paper.support.filesystem import SharedFilesystem
from src.paper.support.constraints import create_strict_constraints
from src.paper.support.logger import ActionLogger
from src.paper.attacks.colocation_injection import CoLocationInjectionAttack, ComputeNode
from src.paper.support.attestation import AttestationEngine


def run_experiment():
    """Run the co-location injection experiment."""
    print("=" * 70)
    print("EXPERIMENT 2: MULTI-USER CO-LOCATION INJECTION")
    print("=" * 70)
    print()

    # Step 1: Set up environment
    print("[1] Setting up environment...")
    logger = ActionLogger()
    filesystem = SharedFilesystem(logger=logger)

    # Create compute node (both agents co-located)
    compute_node = ComputeNode("node-42", filesystem)

    # Create attacker agent
    attacker_constraints = create_strict_constraints("shared", "attacker")
    attacker_agent = Agent(
        user_id="attacker",
        project_id="shared",
        constraints=attacker_constraints,
        filesystem=filesystem,
        logger=logger,
    )

    # Create victim agent (working on finance project, but co-located on same node)
    victim_constraints = create_strict_constraints("finance", "victim")
    victim_agent = Agent(
        user_id="victim",
        project_id="finance",
        constraints=victim_constraints,
        filesystem=filesystem,
        logger=logger,
    )

    print(f"  Compute node: {compute_node.node_id}")
    print(f"  Attacker: {attacker_agent.user_id} (project: {attacker_agent.project_id})")
    print(f"  Victim:   {victim_agent.user_id} (project: {victim_agent.project_id})")
    print()

    # Step 2: Set up and execute attack
    print("[2] Executing attack...")
    attack = CoLocationInjectionAttack()
    attack.setup(filesystem, compute_node, attacker_agent, victim_agent)
    results = attack.execute()

    print(f"  Attack: {results['attack_name']}")
    print(f"  Co-location: {results['co_location']['node_id']}")
    print(f"  Jobs on node: {results['co_location']['jobs_on_node']}")
    print(f"  Injection succeeded: {results['injection_succeeded']}")
    print(f"  Data exfiltrated: {results['data_exfiltrated']}")
    print(f"  Exfiltrated bytes: {results['exfiltrated_bytes']}")
    print()

    # Step 3: Measure exfiltration
    print("[3] Measuring exfiltration...")
    exfil = attack.measure_exfiltration()
    print(f"  Total egress: {exfil['total_exfiltrated_bytes']} bytes")
    print(f"  LLM calls made: {exfil['num_llm_calls']}")
    print(f"  Finance data exfiltrated: {exfil['finance_data_exfiltrated']}")
    print()

    # Step 4: Run attestation defense
    print("[4] Running attestation defense...")
    attestation = AttestationEngine(logger)
    attestation.register_agent(attacker_agent)
    attestation.register_agent(victim_agent)
    attestation.start_monitoring()
    detections = attestation.analyze()

    print(attestation.report())

    # Step 5: Summary
    print("[5] EXPERIMENT RESULTS")
    print("-" * 40)
    attack_success = results['injection_succeeded'] and results['data_exfiltrated']
    detection_success = len(detections) > 0

    print(f"  Attack successful:     {attack_success}")
    print(f"  Attestation detected:  {detection_success}")
    print(f"  Detection count:       {len(detections)}")
    print(f"  Detection time:        {attestation.detection_time_ms:.2f} ms")
    print()

    return {
        "attack_success": attack_success,
        "detection_success": detection_success,
        "num_detections": len(detections),
        "detection_time_ms": attestation.detection_time_ms,
        "exfiltrated_bytes": exfil['total_exfiltrated_bytes'],
    }


if __name__ == "__main__":
    run_experiment()
