"""
Failure-injection lab (threat-model item #26): deliberately breaks the
telemetry pipeline in software and verifies the EDR reacts correctly - it
must detect the failure, record what visibility was lost, change its
health state, fall back to the surviving telemetry, reduce confidence,
alert loudly on total loss, and recover when telemetry returns. Every
scenario also measures how long detection and recovery actually took.

What is real and what is synthetic:
  REAL      - etw_monitor's ETW callback + bounded queue + scoring worker,
              telemetry_monitor's Sysmon callback + queue + scoring worker,
              ProcessCorrelator, HeuristicEngine, SensorHealth,
              watchdog_loop and the blind-state/caveat logic.
  SYNTHETIC - only the OS event source. Events are fabricated and fed in
              through the same callbacks the kernel/Event Log would call.

Safety: software-only. No service is stopped, no ETW session is touched,
nothing is elevated. Synthetic PIDs start at 2,000,000,000, far outside
the real PID range; HeuristicEngine.mitigate is replaced with a recorder
and every scenario asserts it was never called. Synthetic events are
benign, so nothing is ever scored either (also asserted).

This is a standalone tool: it temporarily replaces the root logger's
handlers to capture the EDR's own log output, so never run it inside the
live dashboard process.

Usage:
    python failure_lab.py                    run every scenario
    python failure_lab.py sysmon_silence     run selected scenarios
    python failure_lab.py --list
    python failure_lab.py --json report.json

Exit status: 0 if every check passed, 1 otherwise, 2 for a bad argument.
"Known gaps" are reported but do not fail the run - they document real
weaknesses the lab observed, rather than encoding them as expected.
"""

import argparse
import itertools
import json
import logging
import queue
import sys
import threading
import time
from dataclasses import dataclass, field

import etw_monitor
import telemetry_monitor
from heuristic_engine import HeuristicEngine
from process_correlator import ProcessCorrelator
from sensor_health import (
    SensorHealth, watchdog_loop, current_blind_state, negative_evidence_caveat,
    BLIND_STATE_HEALTHY, BLIND_STATE_DEGRADED, BLIND_STATE_PARTIALLY_BLIND,
    BLIND_STATE_CRITICALLY_BLIND,
)

SYNTHETIC_PID_BASE = 2_000_000_000
SYNTHETIC_PARENT_PID = SYNTHETIC_PID_BASE - 1
CONTRADICTION_PPID_SKEW = 7

# Generous on purpose: bounds are upper limits on detection latency, so a
# loaded CI machine slows the lab down without turning it flaky.
SLACK_SECONDS = 1.0

_SYSMON_IMAGE = r"C:\Windows\System32\notepad.exe"
_SYSMON_PARENT_IMAGE = r"C:\Windows\explorer.exe"
_ETW_IMAGE = "notepad.exe"


# ---- result types ---------------------------------------------------------

@dataclass
class Check:
    name: str
    passed: bool
    detail: str = ""


@dataclass
class ScenarioResult:
    name: str
    description: str
    checks: list = field(default_factory=list)
    metrics: dict = field(default_factory=dict)
    gaps: list = field(default_factory=list)
    error: str = None
    duration_s: float = 0.0

    @property
    def passed(self):
        return self.error is None and bool(self.checks) and all(c.passed for c in self.checks)


# ---- log capture -----------------------------------------------------------

class LogCapture(logging.Handler):
    """Records every log line the EDR emits as (monotonic time, level,
    message) - the lab's view of what the EDR "recorded" and "alerted"."""

    def __init__(self):
        super().__init__(level=logging.DEBUG)
        self._records_lock = threading.Lock()
        self._records = []

    def emit(self, record):
        entry = (time.monotonic(), record.levelno, record.getMessage())
        with self._records_lock:
            self._records.append(entry)

    def snapshot(self):
        with self._records_lock:
            return list(self._records)

    def first_match(self, substring, since=0.0):
        for t, level, message in self.snapshot():
            if t >= since and substring in message:
                return t, level, message
        return None

    def count(self, substring, since=0.0):
        return sum(1 for t, _, message in self.snapshot() if t >= since and substring in message)


# ---- synthetic event builders ------------------------------------------------

def _sysmon_xml(pid, ppid):
    return (
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        '<System><EventID>1</EventID></System><EventData>'
        f'<Data Name="ProcessId">{pid}</Data>'
        f'<Data Name="ParentProcessId">{ppid}</Data>'
        f'<Data Name="Image">{_SYSMON_IMAGE}</Data>'
        f'<Data Name="ParentImage">{_SYSMON_PARENT_IMAGE}</Data>'
        '<Data Name="CommandLine">notepad.exe</Data>'
        '<Data Name="User">LAB\\synthetic</Data>'
        '</EventData></Event>'
    )


def _etw_event(pid, ppid):
    """The (event_id, event_dict) tuple pywintrace hands the ETW callback.
    Field values are strings, matching the real decoder: pywintrace formats
    every property through TdhFormatProperty and its int conversion is
    guarded by `type(data) == int` on what is always a str, so it never
    fires. (Sysmon's XML values are strings too, which is what lets
    ProcessCorrelator's raw-pid key match across the two sensors.)"""
    return (1, {
        "Task Name": "ProcessStart",
        "ProcessID": str(pid),
        "ParentProcessID": str(ppid),
        "ImageName": _ETW_IMAGE,
        "CreateTime": "lab-synthetic",
    })


class _EvtLogShim:
    """Stands in for telemetry_monitor's `win32evtlog` name during a lab
    run: real constants pass through, but EvtRender treats the "event
    handle" as already-rendered XML so no real Event Log handle is needed."""

    def __init__(self, real):
        self._real = real

    def __getattr__(self, name):
        return getattr(self._real, name)

    @staticmethod
    def EvtRender(handle, flags):
        return handle


class _StallableConsumer:
    """Sits between etw_monitor's real scoring worker and the real
    ProcessCorrelator so a scenario can stall the consumer (overload)."""

    def __init__(self, correlator):
        self._correlator = correlator
        self._go = threading.Event()
        self._go.set()
        self._lock = threading.Lock()
        self.entered = 0
        self.processed = 0

    def stall(self):
        self._go.clear()

    def release(self):
        self._go.set()

    def idle(self):
        with self._lock:
            return self.entered == self.processed

    def submit_etw(self, pid, parent_pid, image_name, create_time):
        with self._lock:
            self.entered += 1
        self._go.wait()
        try:
            self._correlator.submit_etw(pid, parent_pid, image_name, create_time)
        finally:
            with self._lock:
                self.processed += 1


# ---- the lab ------------------------------------------------------------------

class Lab:
    """One isolated instance of the EDR's telemetry pipeline plus fault
    injectors. Use as a context manager - it installs (and on exit
    restores) the log capture and the Event Log shim."""

    def __init__(self, result, stale_after=0.4, watchdog_interval=0.1, fuse_window=0.15,
                 event_interval=0.05, etw_queue_maxsize=etw_monitor.EVENT_QUEUE_MAXSIZE, drop_window=0.6):
        self.result = result
        self.stale_after = stale_after
        self.watchdog_interval = watchdog_interval
        self.fuse_window = fuse_window
        self.event_interval = event_interval
        self.etw_queue_maxsize = etw_queue_maxsize

        self.detect_bound = stale_after + SLACK_SECONDS
        self.log_bound = stale_after + watchdog_interval + SLACK_SECONDS
        self.drop_window = drop_window
        self.recover_bound = drop_window + SLACK_SECONDS

        self.log = LogCapture()
        self.mitigations = []
        self.callback_exceptions = []
        self.dispatches = []
        self.etw_offered = 0
        self.max_callback_s = 0.0
        self.contradict = False

        self._lock = threading.Lock()
        self._pids = itertools.count(SYNTHETIC_PID_BASE)
        self._paused = frozenset()
        self._stop = threading.Event()
        self._source_stop = threading.Event()
        self._threads = []
        self._source_thread = None
        self._saved_handlers = None
        self._saved_level = None
        self._saved_evtlog = None

        self.sysmon_health = SensorHealth("sysmon", stale_after=stale_after, drop_window=drop_window)
        self.etw_health = SensorHealth("etw", stale_after=stale_after, drop_window=drop_window)
        self.sysmon_handle = None
        self.etw_handle = None
        self.engine = None
        self.correlator = None
        self.consumer = None
        self.sysmon_queue = None
        self.etw_queue = None

    # -- lifecycle --

    def __enter__(self):
        root = logging.getLogger()
        self._saved_handlers = root.handlers[:]
        self._saved_level = root.level
        for handler in self._saved_handlers:
            root.removeHandler(handler)
        root.addHandler(self.log)
        root.setLevel(logging.INFO)

        self._saved_evtlog = telemetry_monitor.win32evtlog
        telemetry_monitor.win32evtlog = _EvtLogShim(self._saved_evtlog)

        self.engine = HeuristicEngine()
        self.engine.mitigate = self.mitigations.append
        self.engine.on_event = self._record_event
        self.correlator = ProcessCorrelator(self.engine, fuse_window=self.fuse_window)
        self.engine.correlator = self.correlator
        self.consumer = _StallableConsumer(self.correlator)
        return self

    def __exit__(self, exc_type, exc, tb):
        self.stop()
        root = logging.getLogger()
        root.removeHandler(self.log)
        for handler in self._saved_handlers:
            root.addHandler(handler)
        root.setLevel(self._saved_level)
        telemetry_monitor.win32evtlog = self._saved_evtlog
        return False

    def _spawn(self, target, *args):
        thread = threading.Thread(target=target, args=args, daemon=True)
        thread.start()
        return thread

    def start(self, sysmon=True, etw=True, source=True):
        """Bring up the pipeline. A disabled sensor has no handle, exactly
        like a sensor that failed to start in production ("unavailable")."""
        self.sysmon_handle = object() if sysmon else None
        self.etw_handle = object() if etw else None
        self.sysmon_queue = queue.Queue(maxsize=telemetry_monitor.EVENT_QUEUE_MAXSIZE)
        self.etw_queue = queue.Queue(maxsize=self.etw_queue_maxsize)

        # The two scoring workers block forever on their queue and cannot be
        # stopped; they are daemon threads that go idle (silent) when a
        # scenario ends, which is harmless for a short-lived lab process.
        if sysmon:
            self._spawn(telemetry_monitor._scoring_worker, self.engine, self.sysmon_queue)
        if etw:
            self._spawn(etw_monitor._scoring_worker, self.engine, self.etw_queue, self.consumer)

        self._threads.append(self._spawn(self._gc_loop))
        self._threads.append(self._spawn(
            watchdog_loop, [self.sysmon_health, self.etw_health], self.watchdog_interval,
            self.blind_state, self._stop,
        ))
        if source:
            self._source_thread = self._spawn(self._source_loop)
            self._threads.append(self._source_thread)
        self.t_start = time.monotonic()

    def stop(self):
        self._stop.set()
        self._source_stop.set()
        if self.consumer is not None:
            self.consumer.release()
        for thread in self._threads:
            thread.join(timeout=2.0)

    def stop_source(self):
        self._source_stop.set()
        if self._source_thread is not None:
            self._source_thread.join(timeout=2.0)

    # -- background loops --

    def _gc_loop(self):
        while not self._stop.wait(0.05):
            self.correlator._gc_once()

    def _source_loop(self):
        while not self._source_stop.wait(self.event_interval):
            try:
                self.emit_process()
            except Exception as e:
                self._record_callback_exception("source", e)

    # -- observation --

    def blind_state(self):
        return current_blind_state(
            [(self.sysmon_handle, self.sysmon_health), (self.etw_handle, self.etw_health)],
            self.engine.total_events_seen,
        )

    def _record_event(self, event_id, data):
        entry = (time.monotonic(), event_id, data.get('_source'), data.get('ProcessId'))
        with self._lock:
            self.dispatches.append(entry)

    def dispatch_count(self, source, since=0.0):
        with self._lock:
            return sum(1 for t, eid, src, _ in self.dispatches if eid == 1 and src == source and t >= since)

    def was_dispatched(self, pid):
        with self._lock:
            return any(eid == 1 and str(p) == str(pid) for _, eid, _, p in self.dispatches)

    def wait_for(self, predicate, timeout, poll=0.005):
        """Seconds until predicate() first held, or None on timeout."""
        start = time.monotonic()
        deadline = start + timeout
        while True:
            if predicate():
                return time.monotonic() - start
            if time.monotonic() >= deadline:
                return None
            time.sleep(poll)

    def wait_state(self, state, timeout):
        return self.wait_for(lambda: self.blind_state() == state, timeout)

    def wait_log(self, substring, since, timeout):
        """First matching (time, level, message) at/after `since`, or None."""
        deadline = time.monotonic() + timeout
        while True:
            match = self.log.first_match(substring, since)
            if match is not None:
                return match
            if time.monotonic() >= deadline:
                return None
            time.sleep(0.005)

    def wait_settled(self, timeout):
        """Queue empty and consumer idle on two checks 0.1s apart - the gap
        closes the window where a worker holds a dequeued, not-yet-counted
        item."""
        def settled():
            return self.etw_queue.empty() and self.consumer.idle()

        def settled_twice():
            if not settled():
                return False
            time.sleep(0.1)
            return settled()

        return self.wait_for(settled_twice, timeout, poll=0.02)

    # -- traffic --

    def emit_process(self):
        """One synthetic process, observed by every sensor that is enabled
        and not silenced - exactly how one real process is seen by both."""
        pid = next(self._pids)
        skew = CONTRADICTION_PPID_SKEW if self.contradict else 0
        if self.etw_handle is not None and 'etw' not in self._paused:
            self.deliver_etw(_etw_event(pid, SYNTHETIC_PARENT_PID))
        if self.sysmon_handle is not None and 'sysmon' not in self._paused:
            self.deliver_sysmon(_sysmon_xml(pid, SYNTHETIC_PARENT_PID + skew))
        return pid

    def emit_etw_only(self):
        pid = next(self._pids)
        self.deliver_etw(_etw_event(pid, SYNTHETIC_PARENT_PID))
        return pid

    def deliver_etw(self, event_tuple):
        with self._lock:
            self.etw_offered += 1
        started = time.monotonic()
        try:
            etw_monitor._on_etw_event(event_tuple, self.etw_queue, on_heartbeat=self.etw_health.touch,
                                      on_drop=self.etw_health.record_drop)
        except Exception as e:
            self._record_callback_exception("etw", e)
        finally:
            self._note_callback_duration(time.monotonic() - started)

    def deliver_sysmon(self, xml):
        started = time.monotonic()
        try:
            telemetry_monitor.on_sysmon_event(
                telemetry_monitor.win32evtlog.EvtSubscribeActionDeliver,
                self.sysmon_queue, xml, on_heartbeat=self.sysmon_health.touch,
                on_drop=self.sysmon_health.record_drop,
            )
        except Exception as e:
            self._record_callback_exception("sysmon", e)
        finally:
            self._note_callback_duration(time.monotonic() - started)

    def _record_callback_exception(self, where, exc):
        with self._lock:
            self.callback_exceptions.append(f"{where}: {type(exc).__name__}: {exc}")

    def _note_callback_duration(self, seconds):
        with self._lock:
            self.max_callback_s = max(self.max_callback_s, seconds)

    # -- fault injection --

    def silence(self, sensor):
        """The sensor stops delivering events (it is alive but sees
        nothing). Returns the injection timestamp."""
        self._paused = self._paused | {sensor}
        return time.monotonic()

    def resume(self, sensor):
        self._paused = self._paused - {sensor}
        return time.monotonic()

    # -- reporting --

    def check(self, name, passed, detail=""):
        self.result.checks.append(Check(name, bool(passed), detail))
        return bool(passed)

    def metric(self, name, value):
        self.result.metrics[name] = None if value is None else round(value, 3)

    def gap(self, text):
        self.result.gaps.append(text)

    def finalize_checks(self):
        """Invariants every scenario must uphold, whatever it injected."""
        self.check("safety: synthetic traffic never triggered a mitigation",
                   not self.mitigations, f"mitigate() called for {self.mitigations}")
        self.check("safety: benign synthetic traffic scored nothing",
                   not self.engine.process_scores, f"scores: {self.engine.process_scores}")
        self.check("harness: no sensor callback raised an exception",
                   not self.callback_exceptions, "; ".join(self.callback_exceptions[:3]))


def _lat(seconds, bound):
    if seconds is None:
        return f"not observed within {bound:.2f}s"
    return f"{seconds:.2f}s (bound {bound:.2f}s)"


# ---- scenarios ------------------------------------------------------------------

SCENARIOS = {}


def scenario(name, description, **lab_kwargs):
    def register(fn):
        SCENARIOS[name] = (description, fn, lab_kwargs)
        return fn
    return register


def _healthy_baseline(lab):
    dt = lab.wait_state(BLIND_STATE_HEALTHY, 3.0)
    ok = lab.check("baseline: HEALTHY while both sensors deliver", dt is not None,
                   f"observed {lab.blind_state()}")
    lab.check("baseline: no visibility caveat while HEALTHY",
              negative_evidence_caveat(lab.blind_state()) is None)
    return ok


def _single_sensor_silence(lab, silent, surviving_source):
    lab.start()
    if not _healthy_baseline(lab):
        return
    lab.check("baseline: both sensors corroborate each other (fused dispatches)",
              lab.wait_for(lambda: lab.dispatch_count('fused') > 0, 3.0) is not None)

    t0 = lab.silence(silent)
    dt = lab.wait_state(BLIND_STATE_DEGRADED, lab.detect_bound)
    lab.check("detected: blind state becomes DEGRADED", dt is not None,
              _lat(dt, lab.detect_bound) if dt is not None else f"observed {lab.blind_state()}")
    lab.metric("time_to_degraded_s", dt)

    stale_log = lab.wait_log(f"[WATCHDOG] {silent} sensor stale", t0, lab.log_bound)
    lab.check("recorded: watchdog names the silent sensor", stale_log is not None,
              _lat(stale_log[0] - t0 if stale_log else None, lab.log_bound))
    lab.metric("time_to_watchdog_log_s", stale_log[0] - t0 if stale_log else None)

    transition = lab.wait_log("[BLIND-STATE] HEALTHY -> DEGRADED", t0, lab.log_bound)
    lab.check("alerted: DEGRADED transition logged at WARNING",
              transition is not None and transition[1] == logging.WARNING,
              f"level {transition[1] if transition else None}")

    lab.check("confidence reduced: negative-evidence caveat is active",
              negative_evidence_caveat(lab.blind_state()) is not None)

    settle_until = t0 + lab.fuse_window + 0.85
    time.sleep(max(0.0, settle_until - time.monotonic()))
    lab.check(f"fallback: surviving sensor keeps feeding the engine ('{surviving_source}' dispatches)",
              lab.dispatch_count(surviving_source, since=t0 + 0.3) > 0)
    lab.check("visible: cross-sensor corroboration is lost (no fused dispatches after the fault)",
              lab.dispatch_count('fused', since=t0 + lab.fuse_window + 0.5) == 0)

    t1 = lab.resume(silent)
    dt = lab.wait_state(BLIND_STATE_HEALTHY, lab.detect_bound)
    lab.check("recovered: HEALTHY once telemetry returns", dt is not None, _lat(dt, lab.detect_bound))
    lab.metric("time_to_recover_s", dt)
    recovery = lab.wait_log("[BLIND-STATE] DEGRADED -> HEALTHY", t1, lab.log_bound)
    lab.check("recovery logged at INFO", recovery is not None and recovery[1] == logging.INFO,
              f"level {recovery[1] if recovery else None}")
    lab.check("recovered: cross-sensor corroboration resumes (fused dispatches)",
              lab.wait_for(lambda: lab.dispatch_count('fused', since=t1) > 0, 3.0) is not None)


@scenario("sysmon_silence", "Sysmon stops delivering while ETW keeps working")
def _sysmon_silence(lab):
    _single_sensor_silence(lab, silent="sysmon", surviving_source="etw")


@scenario("etw_silence", "ETW stops delivering while Sysmon keeps working")
def _etw_silence(lab):
    _single_sensor_silence(lab, silent="etw", surviving_source="sysmon")


@scenario("total_silence", "Both sensors go silent after telemetry had been flowing")
def _total_silence(lab):
    lab.start()
    if not _healthy_baseline(lab):
        return

    t0 = lab.silence("sysmon")
    lab.silence("etw")
    dt = lab.wait_state(BLIND_STATE_PARTIALLY_BLIND, lab.detect_bound)
    lab.check("detected: blind state becomes PARTIALLY_BLIND", dt is not None,
              _lat(dt, lab.detect_bound) if dt is not None else f"observed {lab.blind_state()}")
    lab.metric("time_to_partially_blind_s", dt)

    transition = lab.wait_log("-> PARTIALLY_BLIND", t0, lab.log_bound)
    lab.check("alerted: total loss of behavioral visibility is logged at CRITICAL",
              transition is not None and transition[1] >= logging.CRITICAL,
              f"level {logging.getLevelName(transition[1]) if transition else None}")
    lab.metric("time_to_alert_s", transition[0] - t0 if transition else None)

    lab.check("confidence reduced: negative-evidence caveat is active",
              negative_evidence_caveat(lab.blind_state()) is not None)

    time.sleep(max(0.0, t0 + lab.fuse_window + 0.85 - time.monotonic()))
    phantom = sum(lab.dispatch_count(s, since=t0 + lab.fuse_window + 0.5) for s in ('etw', 'sysmon', 'fused'))
    lab.check("integrity: no telemetry is fabricated while both sensors are silent", phantom == 0,
              f"{phantom} unexpected dispatches")

    t1 = lab.resume("sysmon")
    lab.resume("etw")
    dt = lab.wait_state(BLIND_STATE_HEALTHY, lab.detect_bound)
    lab.check("recovered: HEALTHY once telemetry returns", dt is not None, _lat(dt, lab.detect_bound))
    lab.metric("time_to_recover_s", dt)
    recovery = lab.wait_log("-> HEALTHY", t1, lab.log_bound)
    lab.check("recovery logged at INFO", recovery is not None and recovery[1] == logging.INFO,
              f"level {recovery[1] if recovery else None}")


@scenario("cold_start_blind", "No sensor ever comes up (e.g. agent started without Administrator)")
def _cold_start_blind(lab):
    lab.start(sysmon=False, etw=False, source=False)
    dt = lab.wait_state(BLIND_STATE_CRITICALLY_BLIND, 0.5)
    lab.check("detected: blind state is CRITICALLY_BLIND immediately", dt is not None,
              f"observed {lab.blind_state()}")

    transition = lab.wait_log("-> CRITICALLY_BLIND", lab.t_start, lab.watchdog_interval + SLACK_SECONDS)
    lab.check("alerted: CRITICALLY_BLIND is logged at CRITICAL",
              transition is not None and transition[1] >= logging.CRITICAL,
              f"level {logging.getLevelName(transition[1]) if transition else None}")
    lab.metric("time_to_alert_s", transition[0] - lab.t_start if transition else None)

    lab.check("confidence reduced: negative-evidence caveat is active",
              negative_evidence_caveat(lab.blind_state()) is not None)
    lab.check("integrity: no telemetry is fabricated", lab.dispatch_count('etw') + lab.dispatch_count('sysmon') == 0)


@scenario("etw_only_total_loss", "Sysmon is not deployed and the only sensor (ETW) dies mid-run")
def _etw_only_total_loss(lab):
    lab.start(sysmon=False, etw=True)
    dt = lab.wait_state(BLIND_STATE_DEGRADED, 3.0)
    lab.check("baseline: DEGRADED while Sysmon is not deployed and ETW is live", dt is not None,
              f"observed {lab.blind_state()}")
    if dt is None:
        return

    t0 = lab.silence("etw")
    dt = lab.wait_state(BLIND_STATE_PARTIALLY_BLIND, lab.detect_bound)
    lab.check("detected: mid-run loss of the only sensor is PARTIALLY_BLIND (telemetry had been seen)",
              dt is not None, _lat(dt, lab.detect_bound) if dt is not None else f"observed {lab.blind_state()}")
    lab.metric("time_to_partially_blind_s", dt)

    transition = lab.wait_log("-> PARTIALLY_BLIND", t0, lab.log_bound)
    lab.check("alerted: total loss of behavioral visibility is logged at CRITICAL",
              transition is not None and transition[1] >= logging.CRITICAL,
              f"level {logging.getLevelName(transition[1]) if transition else None}")

    t1 = lab.resume("etw")
    dt = lab.wait_state(BLIND_STATE_DEGRADED, lab.detect_bound)
    lab.check("recovered: back to the DEGRADED baseline once ETW returns", dt is not None,
              _lat(dt, lab.detect_bound))
    lab.metric("time_to_recover_s", dt)


@scenario("queue_flood", "Event burst overwhelms a stalled consumer and the bounded queue overflows",
          etw_queue_maxsize=50)
def _queue_flood(lab):
    lab.start()
    if not _healthy_baseline(lab):
        return

    lab.consumer.stall()
    t0 = time.monotonic()
    for _ in range(lab.etw_queue_maxsize * 8):
        lab.emit_etw_only()

    lab.check("bounded: queue never exceeds its configured size",
              lab.etw_queue.qsize() <= lab.etw_queue_maxsize,
              f"qsize {lab.etw_queue.qsize()} / max {lab.etw_queue_maxsize}")
    lab.check("non-blocking: the ETW callback never stalled behind the blocked consumer",
              lab.max_callback_s < 0.25, f"slowest callback {lab.max_callback_s * 1000:.1f}ms")

    dt = lab.wait_state(BLIND_STATE_DEGRADED, lab.detect_bound)
    lab.check("detected: queue overflow degrades the blind state to DEGRADED", dt is not None,
              f"observed {lab.blind_state()}")
    lab.check("labelled correctly: the sensor is dropping events, not stale (it is alive)",
              lab.etw_health.is_lossy() and not lab.etw_health.is_stale(),
              f"lossy={lab.etw_health.is_lossy()} stale={lab.etw_health.is_stale()}")

    lossy_log = lab.wait_log("[WATCHDOG] etw sensor dropping events", t0, lab.log_bound)
    lab.check("recorded: watchdog names the sensor that is dropping events and how many",
              lossy_log is not None and "dropped so far" in lossy_log[2],
              lossy_log[2] if lossy_log else f"not observed within {lab.log_bound:.2f}s")
    transition = lab.wait_log("[BLIND-STATE] HEALTHY -> DEGRADED", t0, lab.log_bound)
    lab.check("alerted: DEGRADED transition logged at WARNING",
              transition is not None and transition[1] == logging.WARNING,
              f"level {transition[1] if transition else None}")
    lab.check("confidence reduced: negative-evidence caveat is active",
              negative_evidence_caveat(lab.blind_state()) is not None)

    # The generator keeps running so both sensors stay live while the drops
    # age out of the window - recovery is measured from the moment the
    # consumer is released.
    lab.consumer.release()
    t1 = time.monotonic()
    dt = lab.wait_state(BLIND_STATE_HEALTHY, lab.recover_bound)
    lab.check("recovered: HEALTHY once the consumer catches up and drops stop", dt is not None,
              _lat(dt, lab.recover_bound) if dt is not None else f"observed {lab.blind_state()}")
    lab.metric("time_to_recover_s", dt)
    recovery = lab.wait_log("[BLIND-STATE] DEGRADED -> HEALTHY", t1, lab.log_bound + lab.drop_window)
    lab.check("recovery logged at INFO", recovery is not None and recovery[1] == logging.INFO,
              f"level {recovery[1] if recovery else None}")

    lab.stop_source()
    settled = lab.wait_settled(5.0)
    lab.check("recovered: consumer drains the queue once unstalled", settled is not None)

    offered = lab.etw_offered
    processed = lab.consumer.processed
    dropped = lab.log.count("[ETW] Event queue full", since=t0)
    lab.check("recorded: overflow drops were logged", dropped > 0, f"{dropped} drop warnings")
    lab.check("accounting: every offered event was either processed or logged as dropped",
              offered == processed + dropped, f"offered={offered} processed={processed} dropped={dropped}")
    lab.check("accounting: the sensor's own drop counter agrees with the log record",
              lab.etw_health.drops_total() == dropped,
              f"counter={lab.etw_health.drops_total()} logged={dropped}")
    lab.metric("events_offered", offered)
    lab.metric("events_dropped", dropped)

    pid = lab.emit_etw_only()
    lab.check("recovered: a post-flood event is dispatched normally",
              lab.wait_for(lambda: lab.was_dispatched(pid), 3.0) is not None)


@scenario("malformed_input", "Malformed events are fed to both sensor callbacks")
def _malformed_input(lab):
    lab.start()
    if not _healthy_baseline(lab):
        return

    # The last ETW item is a ProcessStart-shaped event with no ProcessID: it
    # passes the task filter but is unusable.
    etw_garbage = [None, "garbage", (1,), (1, "not-a-dict"), (1, {}), (1, {"Task Name": "ImageLoad"}),
                   (1, {"Task Name": "ProcessStart"})]
    xml_garbage = ["<Event>", "not xml at all", "",
                   '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System/></Event>',
                   '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
                   "<System><EventID>abc</EventID></System></Event>"]  # namespaced, so the engine reaches int('abc')
    t0 = time.monotonic()
    for item in etw_garbage:
        lab.deliver_etw(item)
    for item in xml_garbage:
        lab.deliver_sysmon(item)

    etw_errors = lambda: lab.log.count("[ETW] Error extracting fields", since=t0)
    worker_errors = lambda: lab.log.count("[ETW] Scoring worker failed", since=t0)
    xml_errors = lambda: lab.log.count("[ERROR] Parsing event XML failed", since=t0)
    lab.wait_for(lambda: etw_errors() >= 4 and xml_errors() >= 4 and worker_errors() >= 1, 3.0)
    lab.check("recorded: malformed ETW input is logged, not silently swallowed", etw_errors() >= 4,
              f"{etw_errors()} ETW extraction errors logged")
    lab.check("recorded: an unusable ProcessStart (no ProcessID) is logged as a scoring error",
              worker_errors() >= 1, f"{worker_errors()} worker errors logged")
    lab.check("recorded: malformed Sysmon XML is logged, not silently swallowed", xml_errors() >= 4,
              f"{xml_errors()} XML parse errors logged")

    pid = lab.emit_process()
    lab.check("resilient: valid events are still processed after malformed input",
              lab.wait_for(lambda: lab.was_dispatched(pid), 3.0) is not None)

    # A silenced sensor must go stale even while malformed events keep
    # arriving - garbage must not masquerade as liveness.
    lab.silence("etw")
    garbage_stream = itertools.cycle(etw_garbage)
    end = time.monotonic() + lab.stale_after + 0.6
    while time.monotonic() < end:
        lab.deliver_etw(next(garbage_stream))
        time.sleep(0.02)
    lab.check("integrity: malformed ETW events cannot keep a silent ETW sensor 'live'",
              lab.etw_health.is_stale() and lab.blind_state() == BLIND_STATE_DEGRADED,
              f"etw stale={lab.etw_health.is_stale()}, state={lab.blind_state()}")
    lab.resume("etw")
    lab.check("recovered: HEALTHY once valid ETW events return",
              lab.wait_state(BLIND_STATE_HEALTHY, lab.detect_bound) is not None)

    lab.silence("sysmon")
    garbage_stream = itertools.cycle(xml_garbage)
    end = time.monotonic() + lab.stale_after + 0.6
    while time.monotonic() < end:
        lab.deliver_sysmon(next(garbage_stream))
        time.sleep(0.02)
    lab.check("integrity: malformed Sysmon events cannot keep a silent Sysmon sensor 'live'",
              lab.sysmon_health.is_stale() and lab.blind_state() == BLIND_STATE_DEGRADED,
              f"sysmon stale={lab.sysmon_health.is_stale()}, state={lab.blind_state()}")
    lab.resume("sysmon")
    lab.check("recovered: HEALTHY once valid Sysmon events return",
              lab.wait_state(BLIND_STATE_HEALTHY, lab.detect_bound) is not None)


@scenario("sensor_contradiction", "ETW and Sysmon disagree about a process's parent")
def _sensor_contradiction(lab):
    lab.start()
    if not _healthy_baseline(lab):
        return

    lab.contradict = True
    t0 = time.monotonic()
    bound = lab.fuse_window + SLACK_SECONDS
    match = lab.wait_log("[TELEMETRY_CONTRADICTION]", t0, bound)
    lab.check("detected: parent-PID disagreement raises TELEMETRY_CONTRADICTION", match is not None,
              _lat(match[0] - t0 if match else None, bound))
    lab.metric("time_to_contradiction_s", match[0] - t0 if match else None)
    if match is not None:
        _, level, message = match
        lab.check("recorded: the log names both disagreeing parent PIDs",
                  f"ETW reports parent PID {SYNTHETIC_PARENT_PID}," in message
                  and f"Sysmon reports parent PID {SYNTHETIC_PARENT_PID + CONTRADICTION_PPID_SKEW}" in message,
                  message)
        lab.check("alerted: logged at WARNING", level == logging.WARNING,
                  logging.getLevelName(level))

    lab.check("visibility preserved: fused dispatches continue despite the disagreement",
              lab.wait_for(lambda: lab.dispatch_count('fused', since=t0) > 0, 3.0) is not None)
    lab.check("health: both sensors are alive, so blind state stays HEALTHY",
              lab.blind_state() == BLIND_STATE_HEALTHY, f"observed {lab.blind_state()}")

    lab.contradict = False
    t1 = time.monotonic()
    time.sleep(lab.fuse_window + 0.75)
    window_start = t1 + lab.fuse_window + 0.4
    lab.check("recovered: no new contradictions once the sensors agree again",
              lab.log.count("[TELEMETRY_CONTRADICTION]", since=window_start) == 0)
    lab.check("recovered: corroborated (fused) traffic is flowing again",
              lab.dispatch_count('fused', since=window_start) > 0)


# ---- runner -----------------------------------------------------------------------

def run_scenario(name):
    description, fn, lab_kwargs = SCENARIOS[name]
    result = ScenarioResult(name, description)
    started = time.monotonic()
    try:
        with Lab(result, **lab_kwargs) as lab:
            try:
                fn(lab)
            except Exception as e:
                result.error = f"{type(e).__name__}: {e}"
            lab.finalize_checks()
    except Exception as e:
        result.error = result.error or f"lab setup/teardown failed: {type(e).__name__}: {e}"
    result.duration_s = round(time.monotonic() - started, 2)
    return result


def run_all(names=None):
    return [run_scenario(name) for name in (names or list(SCENARIOS))]


def format_report(results):
    lines = ["FAILURE LAB - software fault injection, synthetic traffic only", ""]
    for r in results:
        lines.append(f"[{'PASS' if r.passed else 'FAIL'}] {r.name} ({r.duration_s}s) - {r.description}")
        for c in r.checks:
            detail = f"  -> {c.detail}" if c.detail else ""
            lines.append(f"    [{'ok' if c.passed else 'FAIL'}] {c.name}{detail}")
        for key, value in r.metrics.items():
            lines.append(f"    metric {key} = {value}")
        for gap in r.gaps:
            lines.append(f"    KNOWN GAP: {gap}")
        if r.error:
            lines.append(f"    ERROR: {r.error}")
        lines.append("")
    failed = [r for r in results if not r.passed]
    gaps = sum(len(r.gaps) for r in results)
    lines.append(f"{len(results)} scenarios, {len(results) - len(failed)} passed, {len(failed)} failed; "
                 f"{gaps} known gap(s) observed")
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description="EDR failure-injection lab (software-only)")
    parser.add_argument("scenarios", nargs="*", help="scenario names (default: all)")
    parser.add_argument("--list", action="store_true", help="list scenarios and exit")
    parser.add_argument("--json", metavar="PATH", help="also write a JSON report")
    args = parser.parse_args(argv)

    if args.list:
        for name, (description, _, _) in SCENARIOS.items():
            print(f"{name:22s} {description}")
        return 0

    unknown = [n for n in args.scenarios if n not in SCENARIOS]
    if unknown:
        print(f"unknown scenario(s): {', '.join(unknown)} (see --list)", file=sys.stderr)
        return 2

    results = run_all(args.scenarios or None)
    print(format_report(results))
    if args.json:
        with open(args.json, "w") as f:
            json.dump([{
                "name": r.name, "description": r.description, "passed": r.passed,
                "duration_s": r.duration_s, "error": r.error, "metrics": r.metrics, "gaps": r.gaps,
                "checks": [{"name": c.name, "passed": c.passed, "detail": c.detail} for c in r.checks],
            } for r in results], f, indent=2)
    return 0 if all(r.passed for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
