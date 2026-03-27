#!/usr/bin/env python3
"""Experiment 1: Filesystem-Mediated Injection.

Sets up the environment, runs the attack, measures results,
and runs the attestation defense.
"""
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from common.agent import Agent
from common.filesystem import SharedFilesystem
from common.constraints import create_strict_constraints
from common.logger import ActionLogger
from attacks.filesystem_injection import FilesystemInjectionAttack
from defense.attestation import AttestationEngine


def run_experiment():
    """Run the filesystem injection experiment."""
    print("=" * 70)
    print("EXPERIMENT 1: FILESYSTEM-MEDIATED INJECTION")
    print("=" * 70)
    print()

    # Step 1: Set up environment
    print("[1] Setting up environment...")
    logger = ActionLogger()
    filesystem = SharedFilesystem(logger=logger)

    # Create attacker agent
    attacker_constraints = create_strict_constraints("shared", "attacker")
    attacker_agent = Agent(
        user_id="attacker",
        project_id="shared",
        constraints=attacker_constraints,
        filesystem=filesystem,
        logger=logger,
    )

    # Create victim agent (more restrictive — only supposed to read datasets)
    victim_constraints = create_strict_constraints("shared", "victim")
    victim_agent = Agent(
        user_id="victim",
        project_id="shared",
        constraints=victim_constraints,
        filesystem=filesystem,
        logger=logger,
    )

    print(f"  Attacker: {attacker_agent.user_id} (project: {attacker_agent.project_id})")
    print(f"  Victim:   {victim_agent.user_id} (project: {victim_agent.project_id})")
    print(f"  Shared filesystem with {len(filesystem.files)} files")
    print()

    # Step 2: Set up and execute attack
    print("[2] Executing attack...")
    attack = FilesystemInjectionAttack()
    attack.setup(filesystem, attacker_agent, victim_agent)
    results = attack.execute()

    print(f"  Attack: {results['attack_name']}")
    print(f"  Injection succeeded: {results['injection_succeeded']}")
    print(f"  Data exfiltrated: {results['data_exfiltrated']}")
    print(f"  Exfiltrated bytes: {results['exfiltrated_bytes']}")
    print(f"  Duration: {results['attack_duration_ms']:.2f} ms")
    print()

    # Step 3: Measure exfiltration
    print("[3] Measuring exfiltration...")
    exfil = attack.measure_exfiltration()
    print(f"  Total egress: {exfil['total_exfiltrated_bytes']} bytes")
    print(f"  LLM calls made: {exfil['num_llm_calls']}")
    print(f"  Secrets exfiltrated: {exfil['secrets_exfiltrated']}")
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

    if detections:
        critical = [d for d in detections if d.threat_level.value == "critical"]
        print(f"  Critical detections:   {len(critical)}")

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
