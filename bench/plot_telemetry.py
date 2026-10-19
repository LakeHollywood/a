"""Correlation plots: tegrastats telemetry vs. sealed benchmark ledger.

Usage (same artifact layout as bench.run_benchmark):

    python3 -m bench.plot_telemetry [--output-dir DIR]

Reads <STS_OUTPUT_DIR>/tegrastats_log.csv + results.json and writes PNGs:

  * orin_power_throttle_overlay.png - CPU power draw vs. CPU frequency, with
    shaded phase windows overlaid so throttling events can be attributed to a
    fault window rather than guessed at.
  * orin_gpu_activity_overlay.png   - GPU util% vs. GR3D_FREQ (added; the
    original snippet parsed GR3D_FREQ but never plotted it).

Design notes / fixes over the first draft of this script
--------------------------------------------------------
1. Regexes match the token shapes JetPack 5.x/6.x tegrastats actually emits,
   with a fallback for the VDD_SYS_* milliwatt style (some L4T builds print
   ``VDD_SYS_CPU 8500mW`` instead of ``CPU 8.5W/9.2W``; the original snippet's
   single W-form pattern silently produced an all-NaN column there).
2. Missing fields become NaN instead of being silently skipped. A row that
   lacks cpu_power_w used to make the column ragged and, if NO line matched,
   ``df['cpu_power_w']`` raised KeyError deep inside matplotlib.
3. Phase windows come from results.json (started_at + per-phase duration_s),
   which run_pipeline records for exactly this kind of correlation. If the
   telemetry epoch and the results clock ever diverge (e.g., capture started
   in a different boot epoch), we fall back to proportional windowing and say
   so loudly -- do not trust shaded regions produced by the fallback.
4. Matplotlib backend is forced headless ("Agg") before pyplot import so the
   script works on a headless Jetson over SSH without $DISPLAY.
"""

import argparse
import json
import math
import os
import re

import matplotlib

matplotlib.use("Agg")  # headless-safe; must precede pyplot import

import matplotlib.pyplot as plt
import pandas as pd


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------
# JetPack 5.x/6.x tegrastats power block looks like:
#   ... RAM 5123/15255MB SWAP 0/7627MB temp 45.0C ... VDD_SYS_CPU 8500mW/9200mW
#   VDD_SYS_GPU 2100mW/1800mW ...   (newer builds may print CPU/GPU W/Avg form)
# Anchored patterns below cover both the explicit "CPU xW/yW" style AND the
# VDD_SYS_* milliwatt style, preferring whichever the device actually prints.
_CPU_POWER_RE = re.compile(r"\bCPU\s+([\d.]+)W/([\d.]+)W")
_GPU_POWER_RE = re.compile(r"\bGPU\s+([\d.]+)W/([\d.]+)W")
_VDD_CPU_RE = re.compile(r"\bVDD_SYS_CPU\s+(\d+)mW")
_VDD_GPU_RE = re.compile(r"\bVDD_SYS_GPU\s+(\d+)mW")
# Real tegrastats CPU block (JetPack 5.x/6.x, ORIN line prefix):
#   CPU [9%@1326,off 12%@1326,off ...] -- per-core util is followed by '@<MHz>'.
# Two bugs in the original snippet's r"CPU\s+\[(\d+)%@(\d+)":
#   a) requires a space after "CPU"; JetPack prints "CPU[" -> zero matches,
#      silently empty column. We allow optional whitespace.
#   b) only matched the FIRST core; if it was idle ("0%@...") or offline the
#      readout was useless. We now take the MAX frequency across all cores.
_CPU_FREQ_RE = re.compile(r"\bCPU\s*\[([^\]]+)\]")
_CORE_MHZ_RE = re.compile(r"@(\d+)")
_GPU_UTIL_RE = re.compile(r"\bGR3D_FREQ\s+(\d+)%@(\d+)")
_TEMP_RE = re.compile(r"\btemp\s+([\d.]+)C")


def parse_tegrastats_log(filepath):
    """Parse raw tegrastats CSV dump into a DataFrame.

    Expected input format (written by bench.hardware_hooks.TegrastatsMonitor):
    one line per sample, ``<epoch_seconds>,<raw tegrastats line>``.

    Columns: timestamp, elapsed_sec, cpu_power_w, gpu_power_w,
    cpu_freq_mhz, gpu_util_pct, gpu_freq_mhz, temp_c. Missing values are NaN.
    """
    records = []
    with open(filepath, "r") as f:
        for lineno, line in enumerate(f, 1):
            parts = line.strip().split(",", 1)
            if len(parts) < 2:
                continue  # header/partial write; cheap to skip
            try:
                timestamp = float(parts[0])
            except ValueError:
                continue  # not our epoch-prefixed format; ignore gracefully
            raw = parts[1]

            rec = {
                "timestamp": timestamp,
                "cpu_power_w": math.nan,
                "gpu_power_w": math.nan,
                "cpu_freq_mhz": math.nan,
                "gpu_util_pct": math.nan,
                "gpu_freq_mhz": math.nan,
                "temp_c": math.nan,
            }

            if m := _CPU_POWER_RE.search(raw):
                rec["cpu_power_w"] = float(m.group(1))
            elif m := _VDD_CPU_RE.search(raw):
                rec["cpu_power_w"] = int(m.group(1)) / 1000.0

            if m := _GPU_POWER_RE.search(raw):
                rec["gpu_power_w"] = float(m.group(1))
            elif m := _VDD_GPU_RE.search(raw):
                rec["gpu_power_w"] = int(m.group(1)) / 1000.0

            if m := _CPU_FREQ_RE.search(raw):
                # max over all online cores == current governor ceiling; robust
                # to leading idle/offline cores in the block
                mhz = [int(v) for v in _CORE_MHZ_RE.findall(m.group(1)) if int(v) > 0]
                if mhz:
                    rec["cpu_freq_mhz"] = max(mhz)

            if m := _GPU_UTIL_RE.search(raw):
                rec["gpu_util_pct"] = int(m.group(1))
                rec["gpu_freq_mhz"] = int(m.group(2))

            if m := _TEMP_RE.search(raw):
                rec["temp_c"] = float(m.group(1))

            records.append(rec)

    df = pd.DataFrame(records)
    if not df.empty:
        df = df.sort_values("timestamp").reset_index(drop=True)
        df["elapsed_sec"] = df["timestamp"] - df["timestamp"].iloc[0]
    return df


# ---------------------------------------------------------------------------
# Phase-window reconstruction
# ---------------------------------------------------------------------------
def compute_phase_windows(results, t_min, t_max):
    """Return [(name, start_epoch, end_epoch)] from results.json timing.

    run_pipeline stores absolute started_at plus per-phase duration_s; phases
    run sequentially, so windows chain forward from started_at. The abort row
    (if any) gets no window. Returns ([], mode_note) when nothing usable.
    """
    started = results.get("started_at")
    phases = results.get("phases", {})
    if not started or not phases:
        return [], "no-windows"

    # Sanity: telemetry epochs should live near the run's clock domain.
    if not (t_min - 3600 <= started <= t_max + 3600):
        # Clock domains disagree (stale csv? different boot?). Fall back to
        # splitting the telemetry span proportionally to phase durations.
        durs = {p: float(d.get("duration_s", 0) or 0) for p, d in phases.items()}
        total = sum(durs.values())
        if total <= 0:
            return [], "proportional-fallback(no-durations)"
        windows, cursor = [], t_min
        for name, d in durs.items():
            frac = d / total * (t_max - t_min)
            windows.append((name, cursor, cursor + frac))
            cursor += frac
        return windows, "PROPORTIONAL-FALLBACK(clock-domain-mismatch)"

    windows, cursor = [], float(started)
    for name, data in phases.items():
        dur = float(data.get("duration_s", 0) or 0)
        windows.append((name, cursor, cursor + dur))
        cursor += dur
    return windows, "absolute"


_PHASE_COLORS = {"baseline": "#2ca02c", "stress": "#d62728", "verification": "#1f77b4"}


# ---------------------------------------------------------------------------
# Plots
# ---------------------------------------------------------------------------
def generate_correlation_plots(telemetry_df, results_json_path, output_dir):
    """Generate hardware-vs-ledger correlation charts. Returns list of paths."""
    if telemetry_df.empty:
        print("[PLOT] No telemetry data found to plot.")
        return []

    with open(results_json_path, "r") as f:
        results = json.load(f)

    saved = []
    t_min = float(telemetry_df["timestamp"].iloc[0])
    t_max = float(telemetry_df["timestamp"].iloc[-1])
    windows, mode = compute_phase_windows(results, t_min, t_max)
    if mode.startswith("PROPORTIONAL"):
        print(f"[PLOT] WARNING: telemetry epochs don't match results clock ({mode}); "
              "phase shading is approximate. Re-run capture+benchmark together.")

    def _has(col):
        return col in telemetry_df.columns and telemetry_df[col].notna().any()

    # --- Plot 1: CPU power vs CPU frequency (throttling indicator) ---------
    if _has("cpu_power_w") or _has("cpu_freq_mhz"):
        fig, ax1 = plt.subplots(figsize=(12, 6))
        if _has("cpu_power_w"):
            ax1.plot(telemetry_df["elapsed_sec"], telemetry_df["cpu_power_w"],
                     color="tab:red", label="CPU power (W)")
        if _has("cpu_freq_mhz"):
            ax2 = ax1.twinx()
            ax2.plot(telemetry_df["elapsed_sec"], telemetry_df["cpu_freq_mhz"],
                     color="tab:blue", linestyle="--", label="CPU freq (MHz)")
            ax2.set_ylabel("CPU frequency (MHz)", color="tab:blue")
            ax2.tick_params(axis="y", labelcolor="tab:blue")
        ax1.set_xlabel("Elapsed time (s)")
        ax1.set_ylabel("CPU power (W)", color="tab:red")
        ax1.tick_params(axis="y", labelcolor="tab:red")
        _draw_windows(ax1, windows, t_min)
        ax1.set_title("Jetson AGX Orin: CPU power vs. frequency scaling under ledger stress")
        ax1.grid(alpha=0.25)
        fig.tight_layout()
        p = os.path.join(output_dir, "orin_power_throttle_overlay.png")
        fig.savefig(p, dpi=150)
        plt.close(fig)
        saved.append(p)
        print(f"[PLOT] Saved {p}")

    # --- Plot 2: GPU util vs GPU frequency ---------------------------------
    if _has("gpu_util_pct") or _has("gpu_freq_mhz"):
        fig, ax1 = plt.subplots(figsize=(12, 6))
        if _has("gpu_util_pct"):
            ax1.plot(telemetry_df["elapsed_sec"], telemetry_df["gpu_util_pct"],
                     color="tab:green", label="GPU util (%)")
        if _has("gpu_freq_mhz"):
            ax2 = ax1.twinx()
            ax2.plot(telemetry_df["elapsed_sec"], telemetry_df["gpu_freq_mhz"],
                     color="tab:purple", linestyle="--", label="GR3D freq (MHz)")
            ax2.set_ylabel("GPU frequency (MHz)", color="tab:purple")
            ax2.tick_params(axis="y", labelcolor="tab:purple")
        ax1.set_xlabel("Elapsed time (s)")
        ax1.set_ylabel("GPU utilization (%)", color="tab:green")
        ax1.tick_params(axis="y", labelcolor="tab:green")
        _draw_windows(ax1, windows, t_min)
        ax1.set_title("Jetson AGX Orin: GPU activity vs. GR3D frequency")
        ax1.grid(alpha=0.25)
        fig.tight_layout()
        p = os.path.join(output_dir, "orin_gpu_activity_overlay.png")
        fig.savefig(p, dpi=150)
        plt.close(fig)
        saved.append(p)
        print(f"[PLOT] Saved {p}")

    # --- Plot 3: SoC temperature trace (cheap, high-value for thermal runs) -
    if _has("temp_c"):
        fig, ax = plt.subplots(figsize=(12, 4))
        ax.plot(telemetry_df["elapsed_sec"], telemetry_df["temp_c"], color="tab:orange")
        _draw_windows(ax, windows, t_min)
        ax.set_xlabel("Elapsed time (s)")
        ax.set_ylabel("SoC temp (C)")
        ax.set_title("Jetson AGX Orin: board temperature across fault-injection phases")
        ax.grid(alpha=0.25)
        fig.tight_layout()
        p = os.path.join(output_dir, "orin_temperature_trace.png")
        fig.savefig(p, dpi=150)
        plt.close(fig)
        saved.append(p)
        print(f"[PLOT] Saved {p}")

    return saved


def _draw_windows(ax, windows, t0):
    """Shade + label phase windows (converted to elapsed coords) on axis."""
    for name, s, e in windows:
        xs, xe = max(s - t0, 0.0), max(e - t0, 0.0)
        if xe <= 0:
            continue
        ax.axvspan(xs, xe, alpha=0.12, color=_PHASE_COLORS.get(name, "#7f7f7f"), lw=0)
        ax.text((xs + xe) / 2, 1.01, name.upper(), transform=ax.get_xaxis_transform(),
                ha="center", fontsize=7, color=_PHASE_COLORS.get(name, "#555"))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--output-dir", default=os.getenv("STS_OUTPUT_DIR", "./data/reports"),
                        help="Directory holding tegrastats_log.csv / results.json (default: $STS_OUTPUT_DIR)")
    args = parser.parse_args()

    telemetry_path = os.path.join(args.output_dir, "tegrastats_log.csv")
    results_path = os.path.join(args.output_dir, "results.json")

    if not os.path.exists(telemetry_path):
        raise SystemExit(f"[PLOT] telemetry file not found: {telemetry_path} "
                         "(did the run have tegrastats available?)")
    if not os.path.exists(results_path):
        raise SystemExit(f"[PLOT] results file not found: {results_path}")

    df = parse_tegrastats_log(telemetry_path)
    print(f"[PLOT] parsed {len(df)} telemetry samples")
    generate_correlation_plots(df, results_path, args.output_dir)
