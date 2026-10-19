"""CLI entry point for the STS chaos benchmark.

Usage (from repo root):
    python3 -m bench.run_benchmark --phases baseline stress verification --interface eth0

This is a thin, stable alias around ``bench.pipeline`` so runbooks/CI can call
``bench.run_benchmark`` without depending on the module layout. All real logic
(telemetry capture, tc/netem + stress-ng fault injection, hash-chained sealed
ledger, results.json / report.md generation) lives in ``bench/pipeline.py``.
"""

import argparse

from bench.pipeline import run_pipeline


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="python3 -m bench.run_benchmark",
        description=(
            "Run the STS benchmark pipeline with optional chaos-fault "
            "injection and a sealed append-only result ledger."
        ),
    )
    parser.add_argument(
        "--phases",
        nargs="+",
        default=["baseline", "stress", "verification"],
        choices=["baseline", "stress", "verification"],
        help="Ordered phases to execute (default: baseline stress verification).",
    )
    parser.add_argument(
        "--interface",
        default="eth0",
        help="Network interface to degrade during the stress phase (e.g., eth0, enp0s1).",
    )
    args = parser.parse_args(argv)

    # Duplicate phases are harmless but almost certainly a typo; reject early.
    if len(set(args.phases)) != len(args.phases):
        parser.error(f"--phases contains duplicates: {args.phases}")

    run_pipeline(args.phases, interface=args.interface)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
