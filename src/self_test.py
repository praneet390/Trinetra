"""
Benign, periodic self-test that proves the telemetry pipeline actually
delivers real events end-to-end - not just that a sensor's heartbeat
thread is alive (sensor_health.py's watchdog/blind-state already covers
that: a thread can be alive and still silently see nothing real).

Scoped honestly to what this prototype's actual sensors can prove:
process-create visibility (Sysmon + ETW, the only two behavioral sensors
this codebase has) and the alert-generation pipeline (logging ->
AlertStore, web_server.py only). There is no file, memory, network, or
cloud-delivery sensor in this codebase, so this module makes no claim
about those - a self-test that silently reports "PASS" for telemetry it
never actually checked would be worse than not having one at all.
"""

import logging
import os
import subprocess
import time
from collections import deque

DEFAULT_INTERVAL_SECONDS = 300
DEFAULT_TIMEOUT_SECONDS = 15
DEFAULT_POLL_SECONDS = 0.5

# Deliberately inert: exits immediately, touches no file, opens no network
# connection, spawns no child of its own. Its parent is this EDR process
# itself, never an Office app, so heuristic_engine.py's OFFICE_PARENTS ->
# LOLBIN_CHILDREN rule (the only rule that scores cmd.exe at all)
# structurally cannot fire on it - confirmed by reading that rule's guard
# (`parent_name in OFFICE_PARENTS`) before choosing this command.
_BENIGN_COMMAND = ["cmd.exe", "/c", "exit", "0"] if os.name == "nt" else ["/usr/bin/true"]


class RecentPidSightings:
    """Minimal on_event observer for entrypoints that don't already keep a
    richer per-event history - main.py has nothing else using
    HeuristicEngine.on_event, so it can wire this in directly.
    web_server.py's Backend already has ProcessActivityStore for this
    purpose and should reuse that instead of this class.

    Tracks PIDs only, regardless of score - a genuinely benign self-test
    process scores zero, so HeuristicEngine.process_scores (which only
    holds scored PIDs) can never be used to answer "was this PID seen"."""

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
    """Spawns one real, inert OS process and polls `pid_seen_fn(pid)`
    until it reports that PID has actually been observed by telemetry, or
    `timeout` elapses. Returns (ok, pid) - `pid` is included even on
    failure so the caller can log exactly which real process the pipeline
    failed to see."""
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
    """Round-trips a canary line through the *real* logging pipeline (not
    a direct call into alert_sink) and confirms it lands in `alert_sink`
    (anything with .snapshot() returning dicts that have a "message" key -
    e.g. web_server.AlertStore) - proves alert generation is actually
    wired end-to-end, not just importable. Logged at INFO specifically so
    a passing canary never inflates the dashboard's WARNING/CRITICAL
    tiles - only a genuine finding should do that."""
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
    """Runs every check that applies and returns {check_name: (ok, detail)}.
    Never raises - a bug in one check must not prevent the other check (or
    the caller's transition-based logging) from running. `alert_sink=None`
    (e.g. main.py's headless CLI, which has no AlertStore) skips
    alert_generation entirely rather than reporting a misleading result
    for a pipeline stage that doesn't exist in that entrypoint."""
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
    """Runs forever (call on a daemon thread), re-running run_once() every
    `interval` seconds. Logs a result only on transition (pass -> fail or
    fail -> pass) per check - same "log on transition, not every tick"
    convention as sensor_health.watchdog_loop, so a long-healthy pipeline
    doesn't spam the alert feed with a routine PASS every `interval`
    seconds. Baseline is assumed passing, so a check that already fails on
    its very first run is still logged immediately (fails loudly) rather
    than treated as an already-known condition."""
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
