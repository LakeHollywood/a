"""Chaos-testing hooks for Jetson AGX Orin (and generic Linux) targets.

Provides:
  1. TegrastatsMonitor  - background CSV telemetry capture (tegrastats --interval 500)
  2. network_degradation - tc/netem qdisc injection with guaranteed teardown
  3. hardware_saturation - stress-ng CPU/VM/IO load with guaranteed termination

All context managers are exception-safe: cleanup runs even if the ``with`` body
raises, so the device can never be left degraded by a failed test run.
"""

import os
import shutil
import signal
import subprocess
import threading
import time
from contextlib import contextmanager


# ---------------------------------------------------------------------------
# 1. Telemetry Monitor
# ---------------------------------------------------------------------------
class TegrastatsMonitor:
    """Streams ``tegrastats`` output into a timestamped CSV in a worker thread.

    Each line is written as ``<epoch_seconds>,<raw tegrastats line>``, which
    keeps the native RGV / VDD / temperature / frequency layout intact while
    giving you a monotonic wall-clock column for correlation with fault
    injection timestamps.
    """

    def __init__(self, output_path="tegrastats_log.csv", interval_ms=500):
        self.output_path = output_path
        self.interval_ms = interval_ms
        self._stop_event = threading.Event()
        self._thread = None
        self._proc = None

    def _poll(self):
        try:
            with open(self.output_path, "w") as f:
                proc = subprocess.Popen(
                    ["tegrastats", "--interval", str(self.interval_ms)],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    text=True,
                    bufsize=1,  # line-buffered
                )
                self._proc = proc
                while not self._stop_event.is_set():
                    line = proc.stdout.readline()
                    if not line:
                        break  # tegrastats exited / pipe closed
                    f.write(f"{time.time()},{line.strip()}\n")
                    f.flush()  # crash-safe: flush every sample
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
        except FileNotFoundError:
            print("[TEG] 'tegrastats' not found on PATH; telemetry disabled.")
        finally:
            self._proc = None

    def start(self):
        if self._thread is not None and self._thread.is_alive():
            return  # idempotent: don't double-spawn / clobber the log file
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._poll, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=10)
            self._thread = None

    # Allow use as a context manager too:
    #     with TegrastatsMonitor("run.csv"):
    #         ...
    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc, tb):
        self.stop()
        return False


# ---------------------------------------------------------------------------
# 2. Network Degradation Hook (tc/netem)
# ---------------------------------------------------------------------------
def _require_tools(*tools):
    missing = [t for t in tools if shutil.which(t) is None]
    if missing:
        raise RuntimeError(
            f"required tool(s) not found on PATH: {', '.join(missing)}"
        )


@contextmanager
def network_degradation(interface="eth0", loss="10%", delay="20ms", jitter="5ms"):
    """Applies kernel-level network degradation via tc/netem.

    CRITICAL: Uses try/finally to guarantee the qdisc is removed, preventing
    the Orin from being permanently locked out of the network. Any pre-existing
    root qdisc is cleared first so ``add`` cannot fail with RTNETLINK error 22.
    """
    _require_tools("tc")

    sudo = ["sudo"] if os.geteuid() != 0 else []

    setup_cmd = sudo + [
        "tc", "qdisc", "add", "dev", interface, "root", "netem",
        "loss", loss, "delay", delay, jitter,
    ]
    teardown_cmd = sudo + ["tc", "qdisc", "del", "dev", interface, "root"]

    print(f"[HOOK] Applying network degradation on {interface} "
          f"(loss={loss}, delay={delay}, jitter={jitter})...")

    # Idempotent setup: drop any stale root qdisc, then add ours.
    subprocess.run(teardown_cmd, check=False,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(setup_cmd, check=True)
    try:
        yield
    finally:
        print(f"[HOOK] Tearing down network degradation on {interface}...")
        # check=False ensures teardown doesn't throw if the rule was already cleared
        subprocess.run(teardown_cmd, check=False)


# ---------------------------------------------------------------------------
# 3. Hardware Saturation Hook (stress-ng)
# ---------------------------------------------------------------------------
@contextmanager
def hardware_saturation(cpu_workers=4, vm_workers=2, io_workers=2, timeout=None):
    """Spawns stress-ng to saturate CPU, Memory, and NVMe I/O.

    Guarantees process termination upon exit. If ``timeout`` (seconds) is set,
    passes ``--timeout`` to stress-ng so it self-terminates even if this
    process dies without running the finally block.
    """
    _require_tools("stress-ng")

    sudo = ["sudo"] if os.geteuid() != 0 else []

    cmd = sudo + [
        "stress-ng",
        "--cpu", str(cpu_workers),
        "--vm", str(vm_workers),
        "--io", str(io_workers),
        "--metrics-brief",
    ]
    if timeout is not None:
        cmd += ["--timeout", f"{timeout}s"]

    print(f"[HOOK] Spawning stress-ng (CPU:{cpu_workers}, VM:{vm_workers}, "
          f"IO:{io_workers})...")

    # start_new_session puts stress-ng in its own process group, so teardown
    # can SIGTERM/SIGKILL the entire tree (stress-ng forks one worker per
    # --cpu/--vm/--io class) without ever touching the caller's group.
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                            start_new_session=True)
    try:
        yield proc
    finally:
        print("[HOOK] Terminating stress-ng...")
        # Kill the whole group so no orphaned workers keep burning the Orin's
        # thermal budget after teardown.
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                proc.kill()
            proc.wait()


# ---------------------------------------------------------------------------
# Example orchestration: ./chaos_hooks.py
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    # Sanity-check the environment before starting a campaign.
    for tool in ("tegrastats", "tc", "stress-ng"):
        status = "OK" if shutil.which(tool) else "MISSING"
        print(f"[CHECK] {tool:<12} : {status}")

    monitor = TegrastatsMonitor("chaos_run.csv")
    monitor.start()
    try:
        # Phase 1: baseline soak
        time.sleep(5)

        # Phase 2: network fault while under compute load
        with network_degradation(interface="eth0"), \
             hardware_saturation(cpu_workers=4, vm_workers=2, io_workers=2):
            print("[RUN] Injecting faults for 30s...")
            time.sleep(30)

        # Phase 3: recovery observation
        time.sleep(10)
    finally:
        monitor.stop()
        print("[DONE] Telemetry saved to chaos_run.csv")
