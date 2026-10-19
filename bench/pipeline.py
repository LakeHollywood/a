"""STS benchmark pipeline: telemetry + chaos hooks + sealed result ledger.

Usage (from repo root):
    STS_LEDGER_KEY=<hex-or-passphrase> python -m bench.pipeline \
        --phases baseline stress verification --interface eth0

Every phase result is appended as a hash-chained, HMAC-sealed row in
<data/reports>/ledger.jsonl. The run's own rows are audited at the end and
sealed with a .seal.json manifest; results.json embeds the audit report so
downstream tooling can verify provenance offline via SEALedger.verify_seal().
"""

import argparse
import json
import os
import time

from bench.hardware_hooks import TegrastatsMonitor, network_degradation, hardware_saturation
from bench.ledger import SEALedger, SealError, load_key


def run_pipeline(phases: list[str], interface: str = "eth0") -> dict:
    output_dir = os.getenv("STS_OUTPUT_DIR", "./data/reports")
    os.makedirs(output_dir, exist_ok=True)

    telemetry_path = os.path.join(output_dir, "tegrastats_log.csv")
    ledger_path = os.path.join(output_dir, "ledger.jsonl")
    keyfile = os.path.join(output_dir, ".ledger.key")

    # Key resolution order: $STS_LEDGER_KEY -> existing keyfile -> generate one.
    try:
        key = load_key(path=keyfile)
    except SealError:
        key = os.urandom(32).hex().encode()
        fd = os.open(keyfile, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(key)
        print(f"[LEDGER] No ${'STS_LEDGER_KEY'} set; generated keyfile {keyfile} (0600)")

    ledger = SEALedger(ledger_path, key)

    telemetry = TegrastatsMonitor(output_path=telemetry_path)
    telemetry.start()

    results = {"started_at": time.time(), "phases": {}, "status": "success"}

    try:
        for phase in phases:
            print(f"\n=== EXECUTING PHASE: {phase.upper()} ===")
            t0 = time.time()

            if phase == "baseline":
                # Baseline runs clean, no injected faults.
                payload = run_baseline_benchmark()

            elif phase == "stress":
                # Stress combines network degradation AND hardware saturation.
                # Nested context managers: netem applies first, stress-ng second;
                # teardown unwinds in reverse (stress-ng dies before tc rules).
                #
                # soak_s: how long the fault window stays open. stress-ng needs
                # ~1s just to spin up its workers, so a mock/instant workload
                # would tear the hooks down before any load lands (the measured
                # TPS would be baseline TPS with a fake label). Real inference
                # benchmarks should pass soak_s=0 and let their own runtime
                # define the window.
                soak_s = float(os.getenv("STS_STRESS_SOAK_S", "5"))
                with network_degradation(interface=interface, loss="15%", delay="30ms", jitter="10ms"):
                    with hardware_saturation(cpu_workers=4, vm_workers=2, io_workers=2):
                        payload = run_stress_benchmark()
                        if soak_s > 0:
                            time.sleep(soak_s)
                payload["soak_s"] = soak_s

            elif phase == "verification":
                # Verification runs clean to ensure the ledger recovered and
                # sealed correctly after fault injection tore down.
                payload = run_verification_audit(ledger)

            else:
                raise ValueError(f"unknown phase: {phase!r}")

            payload.setdefault("status", "ok")
            payload["duration_s"] = round(time.time() - t0, 3)
            row = ledger.append({"phase": phase, **payload})
            results["phases"][phase] = payload
            print(f"[LEDGER] sealed row seq={row.seq} phase={phase}")

    except Exception as e:
        results["status"] = f"failed: {e}"
        # Record the failure itself in the ledger — a crashed run must not
        # silently leave fewer rows than the plan called for.
        try:
            ledger.append({"phase": "abort", "status": "failed", "error": str(e)})
        except SealError as le:
            print(f"[LEDGER] WARNING: could not record abort row: {le}", flush=True)
        # Persist a machine-readable failure artifact BEFORE re-raising, so CI
        # can classify the crash even though no seal/report is produced.
        results["finished_at"] = time.time()
        _write_json(os.path.join(output_dir, "results.json"), results)
        raise
    finally:
        # ALWAYS stop telemetry, even if the benchmark crashes.
        telemetry.stop()

    # Audit this run's rows (the chain spans previous runs too — that's the point).
    audit_report = ledger.audit()
    results["ledger"] = {
        "path": ledger_path,
        "audit": {"ok": audit_report["ok"], "rows_checked": audit_report["rows_checked"]},
    }
    if not audit_report["ok"]:
        results["status"] = "failed: ledger audit found tampering/corruption"
        results["ledger"]["audit"]["errors"] = audit_report["errors"]

    if os.path.exists(telemetry_path):
        with open(telemetry_path) as f:
            results["telemetry_samples"] = sum(1 for _ in f)

    # Write machine-readable results, then seal only if everything passed.
    _write_json(os.path.join(output_dir, "results.json"), results)

    if audit_report["ok"]:
        manifest = ledger.seal()
        results["ledger"]["seal"] = manifest
        print(f"[LEDGER] sealed run: {manifest['rows']} rows, head={manifest['head_digest'][:12]}…")
    else:
        print("[LEDGER] REFUSING TO SEAL — audit failed:", *audit_report["errors"], sep="\n  ")

    # Rewrite results.json now that it carries the seal manifest.
    _write_json(os.path.join(output_dir, "results.json"), results)

    # Post-flight telemetry correlation plots. Guarded so a plotting failure
    # (missing matplotlib, malformed CSV, headless-env quirks) can never mask
    # a successful benchmark run or corrupt the sealed artifacts above. This
    # runs BEFORE report generation so report.md can embed the charts; the
    # final results.json write below then carries the chart manifest too.
    try:
        from bench.plot_telemetry import parse_tegrastats_log, generate_correlation_plots
        telemetry_df = parse_tegrastats_log(telemetry_path)
        charts = generate_correlation_plots(
            telemetry_df, os.path.join(output_dir, "results.json"), output_dir
        )
        if charts:
            results["charts"] = charts
    except Exception as e:
        print(f"[WARN] Post-flight telemetry plotting failed: {e}")

    generate_markdown_report(results, output_dir)
    _write_json(os.path.join(output_dir, "results.json"), results)

    if results["status"] != "success":
        raise SystemExit(1)
    return results


def _write_json(path: str, obj: dict) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(obj, f, indent=2)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


# --- Benchmark workloads (mocked for demonstration) -------------------------
def run_baseline_benchmark():
    return {"tps": 6669, "status": "ok"}


def run_stress_benchmark():
    return {"tps": 4100, "status": "ok", "note": "Degraded by hooks"}


def run_verification_audit(ledger: SEALedger):
    """Clean-phase audit: walk the chain, verify every HMAC, confirm the
    post-stress teardown left the ledger appendable."""
    report = ledger.audit()
    if not report["ok"]:
        raise SealError(f"verification audit failed: {report['errors']}")
    # Prove liveness: the chain must accept a new block right after faults tore down.
    probe = ledger.append({"phase": "_probe", "status": "ok"})
    return {
        "rows_audited": report["rows_checked"],
        "seal_failures": 0,
        "chain_live_seq": probe.seq,
        "status": "ok",
    }


def generate_markdown_report(results: dict, out_dir: str) -> None:
    lines = ["# STS Chaos Benchmark Report", ""]
    lines.append(f"**Status:** `{results['status']}`  ")
    lines.append(f"**Telemetry samples:** {results.get('telemetry_samples', 'n/a')}")
    lines.append("")
    lines.append("| Phase | Result |")
    lines.append("|-------|--------|")
    for phase, data in results["phases"].items():
        summary = ", ".join(f"{k}={v}" for k, v in data.items() if k != "note")
        lines.append(f"| {phase} | {summary} |")
    led = results.get("ledger", {})
    if led:
        seal = led.get("seal")
        lines += [
            "",
            f"**Ledger:** `{led['path']}` — audit ok: `{led['audit']['ok']}`, "
            f"rows: `{led['audit']['rows_checked']}`",
            f"**Seal:** {'`' + seal['signature'][:16] + '…`' if seal else 'NOT SEALED (audit failed)'}",
        ]
    charts = results.get("charts") or []
    if charts:
        lines.append("")
        lines.append("## Telemetry correlation charts")
        for c in charts:
            # report.md lives in the same dir as the PNGs; link by basename.
            lines.append(f"![{os.path.basename(c)}]({os.path.basename(c)})")
    with open(os.path.join(out_dir, "report.md"), "w") as f:
        f.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--phases", nargs="+", default=["baseline", "stress", "verification"])
    parser.add_argument("--interface", default="eth0", help="Network interface to degrade (e.g., eth0, enp0s1)")
    args = parser.parse_args()

    run_pipeline(args.phases, interface=args.interface)
