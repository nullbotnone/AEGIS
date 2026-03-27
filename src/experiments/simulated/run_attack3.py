#!/usr/bin/env python3
"""Experiment 3: Supply Chain Injection via Agent Skills.

Demonstrates attack through compromised agent tools/skills.
"""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from common.agent import Agent
from common.filesystem import SharedFilesystem
from common.constraints import create_strict_constraints
from common.logger import ActionLogger
from attacks.supply_chain_injection import (
    SupplyChainInjectionAttack,
    legitimate_data_converter,
)
from defense.attestation import AttestationEngine


def run_experiment():
    """Run the supply chain injection experiment."""
    print("=" * 70)
    print("EXPERIMENT 3: SUPPLY CHAIN INJECTION VIA AGENT SKILLS")
    print("=" * 70)
    print()

    # Step 1: Set up environment
    print("[1] Setting up environment...")
    logger = ActionLogger()
    filesystem = SharedFilesystem(logger=logger)

    # Create victim agent with legitimate tools
    victim_constraints = create_strict_constraints("analytics", "victim")
    tools = {
        "data_converter": legitimate_data_converter(filesystem, "victim"),
        "csv_reader": lambda f: filesystem.read(f, "victim"),
    }
    victim_agent = Agent(
        user_id="victim",
        project_id="analytics",
        constraints=victim_constraints,
        filesystem=filesystem,
        logger=logger,
        tools=tools,
    )

    print(f"  Victim: {victim_agent.user_id} (project: {victim_agent.project_id})")
    print(f"  Available tools: {list(victim_agent.tools.keys())}")
    print()

    # Step 2: Execute attack (setup includes tool replacement)
    print("[2] Executing attack...")
    attack = SupplyChainInjectionAttack()
    attack.setup(filesystem, victim_agent)
    print(f"  Tool 'data_converter' replaced with compromised version")
    results = attack.execute()

    print(f"  Attack: {results['attack_name']}")
    print(f"  Compromised tool: {results['compromised_tool']}")
    print(f"  Injection succeeded: {results['injection_succeeded']}")
    print(f"  Data exfiltrated: {results['data_exfiltrated']}")
    print(f"  Exfiltrated bytes: {results['exfiltrated_bytes']}")
    print()

    # Step 3: Measure exfiltration
    print("[3] Measuring exfiltration...")
    exfil = attack.measure_exfiltration()
    print(f"  Total egress: {exfil['total_exfiltrated_bytes']} bytes")
    print(f"  LLM calls made: {exfil['num_llm_calls']}")
    print(f"  SSH key exfiltrated: {exfil['ssh_key_exfiltrated']}")
    print()

    # Step 4: Run attestation defense
    print("[4] Running attestation defense...")
    attestation = AttestationEngine(logger)
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

    # Cleanup
    attack.cleanup()

    return {
        "attack_success": attack_success,
        "detection_success": detection_success,
        "num_detections": len(detections),
        "detection_time_ms": attestation.detection_time_ms,
        "exfiltrated_bytes": exfil['total_exfiltrated_bytes'],
    }


if __name__ == "__main__":
    run_experiment()
