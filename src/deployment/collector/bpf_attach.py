#!/usr/bin/env python3
"""Minimal attach-only loader for direct eBPF microbenchmarks."""

import argparse
import os
import time

from src.deployment.collector.bpf_collector import _LibbpfBackend, get_logger

logger = get_logger("aegis.bpf_attach")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Attach the AEGIS eBPF probe without polling the ring buffer"
    )
    parser.add_argument(
        "--bpf",
        default=None,
        help="Path to BPF object file (auto-detected if omitted)",
    )
    parser.add_argument(
        "--sample-rate",
        type=int,
        default=1,
        help="Track every Nth pid (default: 1)",
    )
    parser.add_argument(
        "--monitor-uid",
        type=int,
        default=0,
        help="Only monitor this uid when non-zero",
    )
    parser.add_argument(
        "--disable-network",
        action="store_true",
        help="Do not attach network-related policy paths",
    )
    parser.add_argument(
        "--disable-file",
        action="store_true",
        help="Do not attach file-related policy paths",
    )
    parser.add_argument(
        "--disable-exec",
        action="store_true",
        help="Do not attach exec-related policy paths",
    )
    parser.add_argument(
        "--duration",
        type=float,
        default=0.0,
        help="Optional run duration in seconds; 0 keeps the probe attached until Ctrl+C",
    )
    args = parser.parse_args()

    if os.geteuid() != 0:
        logger.error("Must run as root to attach eBPF programs")
        sys.exit(1)

    backend = _LibbpfBackend(args.bpf)

    try:
        backend.open()
        backend.set_config(
            sample_rate=max(1, args.sample_rate),
            enable_network=not args.disable_network,
            enable_file=not args.disable_file,
            enable_exec=not args.disable_exec,
            monitor_uid=max(0, args.monitor_uid),
        )
        logger.info("AEGIS probe attached without userspace event polling")
        logger.info("Press Ctrl+C to detach")

        if args.duration > 0:
            time.sleep(args.duration)
        else:
            while True:
                time.sleep(1.0)
    except KeyboardInterrupt:
        logger.info("Detaching probe")
    finally:
        backend.close()


if __name__ == "__main__":
    main()
