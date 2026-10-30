"""
Periodic self-test that proves the telemetry pipeline delivers real events
end-to-end, beyond just checking that heartbeat threads are alive.
Scoped to what this codebase's sensors can actually prove (process-create
visibility + alert pipeline). A self-test that reports PASS for unchecked
telemetry is worse than not having one.
"""

import logging
import os
import subprocess
import time
from collections import deque

DEFAULT_INTERVAL_SECONDS = 300
DEFAULT_TIMEOUT_SECONDS = 15
DEFAULT_POLL_SECONDS = 0.5

# Inert: parent is this EDR process, never an Office app, so the
# OFFICE_PARENTS -> LOLBIN_CHILDREN rule structurally cannot fire on it.
_BENIGN_COMMAND = ["cmd.exe", "/c", "exit", "0"] if os.name == "nt" else ["/usr/bin/true"]


class RecentPidSightings:
    """Tracks observed PIDs regardless of score. Zero-scored self-test processes
    won't appear in HeuristicEngine.process_scores - can't use that to detect them.
    web_server.py's Backend uses ProcessActivityStore instead."""

    def __init__(self, maxlen=2000):
        self._pids = deque(maxlen=maxlen)

    def observe(self, event_id, data_dict):
        if event_id != 1:  # ProcessCreate only
            return
        pid = data_dict.get('ProcessId')
        if pid is not None:
            self._pids.append(str(pid))

    def seen(self, pid):
        return str(pid) in self._pids


def check_process_visibility(pid_seen_fn, timeout=DEFAULT_TIMEOUT_SECONDS, poll_interval=DEFAULT_POLL_SECONDS):
    """Spawn an inert process and poll until telemetry sees it or timeout elapses.
    Returns (ok, pid); pid included on failure so the caller can log which PID was missed."""
    proc = subprocess.Popen(_BENIGN_COMMAND, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    pid = proc.pid
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()

    deadline = time.monotonic() + timeout
    while True:
        if pid_seen_fn(pid):
            return True, pid
        if time.monotonic() >= deadline:
            return False, pid
        time.sleep(poll_interval)


def check_alert_pipeline(alert_sink, timeout=DEFAULT_TIMEOUT_SECONDS, poll_interval=DEFAULT_POLL_SECONDS):
    """Send a canary through the real logging pipeline and confirm it lands in alert_sink.
    Logged at INFO so a passing canary never inflates WARNING/CRITICAL tiles."""
    marker = f"self-test-canary-{time.monotonic_ns()}"
    logging.info(f"[SELF-TEST] alert pipeline canary {marker}")
    deadline = time.monotonic() + timeout
    while True:
        if any(marker in a.get("message", "") for a in alert_sink.snapshot()):
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(poll_interval)


def run_once(pid_seen_fn, alert_sink=None, timeout=DEFAULT_TIMEOUT_SECONDS):
    """Run all applicable checks; never raises so one failure doesn't skip others.
    alert_sink=None skips the alert pipeline check (main.py headless CLI has no AlertStore)."""
    results = {}

    try:
        ok, pid = check_process_visibility(pid_seen_fn, timeout=timeout)
        results['process_visibility'] = (ok, f"PID {pid}")
    except Exception as e:
        results['process_visibility'] = (False, f"check raised: {e}")

    if alert_sink is not None:
        try:
            ok = check_alert_pipeline(alert_sink, timeout=timeout)
            results['alert_generation'] = (ok, "")
        except Exception as e:
            results['alert_generation'] = (False, f"check raised: {e}")

    return results


def self_test_loop(pid_seen_fn, alert_sink=None, interval=DEFAULT_INTERVAL_SECONDS, timeout=DEFAULT_TIMEOUT_SECONDS):
    """Run on a daemon thread. Logs only on pass/fail transitions to avoid spamming
    the feed; baseline assumed passing so a first-run failure still logs immediately."""
    last_ok = {}
    while True:
        time.sleep(interval)
        for check, (ok, detail) in run_once(pid_seen_fn, alert_sink, timeout=timeout).items():
            if ok == last_ok.get(check, True):
                continue
            if ok:
                logging.info(f"[SELF-TEST] {check} recovered - now passing ({detail})")
            else:
                logging.critical(
                    f"[SELF-TEST] FAILED: {check} - telemetry pipeline did not deliver the "
                    f"expected result within {timeout}s ({detail})"
                )
            last_ok[check] = ok
