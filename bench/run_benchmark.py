"""CLI entry point for the STS chaos benchmark.

Usage (from repo root):
    python3 -m bench.run_benchmark --phases baseline stress verification --interface eth0

This is a thin, stable alias around ``bench.pipeline`` so runbooks/CI can call
``bench.run_benchmark`` without depending on the module layout. All real logic
(telemetry capture, tc/netem + stress-ng fault injection, hash-chained sealed
ledger, results.json / report.md generation) lives in ``bench/pipeline.py``.
"""

import argparse
import asyncio
import logging
import time

from bench.pipeline import run_pipeline

CORE_COMMAND_ENDPOINT = "http://localhost:8000/anchors/batch"


def run_edge_orchestrator(args) -> int:
    """Edge Orchestrator mode: generate -> sign -> quarantine -> flush -> confirm.

    Uses the device keypair registered with Core Command (orin-splinter-01)
    and points the AnchorClient at http://localhost:8000.
    """
    from bench.anchor import AnchorClient

    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(name)s %(levelname)s: %(message)s")

    client = AnchorClient(
        db_path=args.edge_db,
        device_id=args.device_id,
        keys_file=args.keys_file,
        endpoint=args.endpoint,
        batch_size=args.batch_size,
    )
    try:
        if args.events:
            logging.getLogger("bench.anchor").info(
                "Appending %d synthetic telemetry events to the edge ledger...",
                args.events)
            for i in range(args.events):
                client.engine.append_event({"sensor": "imu", "t": time.time(), "n": i})

        async def drive():
            outcomes = []
            for cycle in range(args.cycles):
                logging.getLogger("bench.anchor").info("--- orchestrator cycle %d ---", cycle + 1)
                outcome = await client.run_once()
                if outcome is None:
                    break
                outcomes.append(outcome)
            return outcomes

        outcomes = asyncio.run(drive())
        for o in outcomes:
            print(f"RESULT {o['result']}: anchor={o['anchor_id'][:8]} seq={o['seq'][0]}..{o['seq'][1]}")
        return 0 if outcomes and all(o["result"] == "ANCHORED" for o in outcomes) else 1
    finally:
        client.close()


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
    # --- Edge Orchestrator options -------------------------------------
    parser.add_argument(
        "--orchestrator",
        action="store_true",
        help="Run the Edge Orchestrator against Core Command instead of the chaos benchmark.",
    )
    parser.add_argument("--endpoint", default=CORE_COMMAND_ENDPOINT,
                        help=f"Core Command sync endpoint (default: {CORE_COMMAND_ENDPOINT})")
    parser.add_argument("--device-id", default="orin-splinter-01")
    parser.add_argument("--keys-file", default="bench/orin-splinter-01_keys.json")
    parser.add_argument("--edge-db", default="bench/edge_orchestrator.db")
    parser.add_argument("--events", type=int, default=0,
                        help="Synthetic telemetry events to append before anchoring.")
    parser.add_argument("--batch-size", type=int, default=50)
    parser.add_argument("--cycles", type=int, default=4)
    args = parser.parse_args(argv)

    if args.orchestrator:
        return run_edge_orchestrator(args)

    # Duplicate phases are harmless but almost certainly a typo; reject early.
    if len(set(args.phases)) != len(args.phases):
        parser.error(f"--phases contains duplicates: {args.phases}")

    run_pipeline(args.phases, interface=args.interface)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
