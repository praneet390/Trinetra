"""
Web dashboard for the EDR prototype: stdlib-only HTTP server (no Flask/
Django - nothing new to install) serving a Falcon/Singularity-style
single-page dashboard (stat tiles, charts, live detections feed, endpoint
process table with a Terminate response action, static-scan verdicts).

Wires the exact same detection surfaces main.py does (StaticScanner,
Sysmon telemetry, ModuleInspector) into one HeuristicEngine - this file
only adds a JSON API + static file serving on top, no detection logic
changes.
"""

import os
import re
import sys
import json
import time
import ctypes
import logging
import psutil
import socket
import subprocess
import threading
import urllib.request
import urllib.error
import webbrowser
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, parse_qs

from heuristic_engine import HeuristicEngine
from static_scanner import StaticScanner
from telemetry_monitor import start_monitor
from etw_monitor import start_etw_monitor, stop_etw_monitor
from kernel_sensor import ensure_driver_running, start_kernel_monitor, stop_kernel_monitor, stop_driver_service
from module_inspector import ModuleInspector
from process_correlator import ProcessCorrelator
from rule_engine import RuleEngine
from sensor_health import (
    SensorHealth, watchdog_loop, sensor_label, current_blind_state,
    negative_evidence_caveat, BLIND_STATE_HEALTHY,
)
from detection_config import load_config
from self_test import self_test_loop
from process_tracker import ProcessTracker
from hands_on import is_hands_on_message, HANDS_ON_LABEL
import dashboard_data as dd

HOST = "127.0.0.1"  # loopback only - this server exposes a process-kill endpoint
PORT = 8787
BINARIES_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'binaries.json')
WEBAPP_DIR = os.path.join(os.path.dirname(__file__), 'webapp')
MODULE_SWEEP_INTERVAL_SECONDS = 30
MAX_ALERTS = 2000

STATIC_CONTENT_TYPES = {
    '.html': 'text/html; charset=utf-8',
    '.css': 'text/css; charset=utf-8',
    '.js': 'application/javascript; charset=utf-8',
}

PID_TERMINATE_RE = re.compile(r"^/api/processes/(\d+)/terminate$")
# Detection-forensics API routes. PIDs are parsed as strictly-numeric path
# segments - a non-numeric PID is a client error (400), not a 500, and the
# regexes make the routing unambiguous against each other.
PID_LIVE_RE = re.compile(r"^/api/processes/(\d+)/live$")
PID_ANCESTRY_RE = re.compile(r"^/api/processes/(\d+)/ancestry$")


def api_process_live(pid_str):
    """GET /api/processes/<pid>/live - the Live Agent Feedback feed.

    Answers, for the PID an alert is about: is it still alive RIGHT NOW,
    what is it called, how many threads, how much memory, which files does
    it hold open, which network connections does it have, and how many
    mapped modules. All of it is a single psutil snapshot taken inside this
    request - the dashboard polls it on demand (per analyst click), which
    keeps the 'respond within two seconds' contract trivial: there is no
    agent round-trip because the agent and the dashboard are one process.

    Failure model: every psutil read is individually guarded. An elevated
    or protected process typically denies open_files/net_connections/
    memory_maps - those come back as null plus a `denied` list instead of
    failing the whole response, because 'alive, but locked down' is itself
    the analyst's answer. A dead process is 404 with its capture-time name
    when psutil can still tell us anything, or a bare 404 when it cannot.

    Module-level for the same testability reason as api_process_ancestry;
    psutil is imported at module top so tests monkeypatch the same object
    the handler path uses."""
    try:
        pid = int(pid_str)
    except (TypeError, ValueError):
        return {"error": "invalid pid"}, 400

    try:
        proc = psutil.Process(pid)
    except psutil.NoSuchProcess:
        return {"error": "process not found (already exited)", "pid": pid, "alive": False}, 404
    except psutil.AccessDenied:
        # The process EXISTS (AccessDenied is a visibility result, not an
        # absence result) - answer what we know and mark the rest denied.
        return {
            "pid": pid, "alive": True, "status": "unknown",
            "denied": ["name", "open_files", "net_connections", "memory_maps", "memory_info"],
        }, 200

    payload = {
        "pid": pid,
        "alive": True,
        "denied": [],
    }
    try:
        payload["name"] = proc.name()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        payload["name"] = None
        payload["denied"].append("name")
    try:
        payload["status"] = proc.status()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        payload["status"] = None
        payload["denied"].append("status")
    try:
        payload["create_time"] = proc.create_time()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        payload["create_time"] = None
        payload["denied"].append("create_time")
    try:
        payload["num_threads"] = proc.num_threads()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        payload["num_threads"] = None
        payload["denied"].append("num_threads")
    try:
        mem = proc.memory_info()
        payload["rss"] = mem.rss
        payload["vms"] = mem.vms
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        payload["rss"] = payload["vms"] = None
        payload["denied"].append("memory_info")
    try:
        payload["open_files"] = [
            {"path": f.path, "fd": f.fd}
            for f in proc.open_files()
        ]
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        payload["open_files"] = None
        payload["denied"].append("open_files")
    try:
        payload["net_connections"] = [
            {"fd": c.fd, "laddr": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else None,
             "raddr": f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else None,
             "status": c.status}
            for c in proc.net_connections()
        ]
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        payload["net_connections"] = None
        payload["denied"].append("net_connections")
    try:
        maps = proc.memory_maps()
        payload["memory_maps_count"] = len(maps)
        # Paths only - full map dumps belong in a forensic tool, not a
        # status panel; and non-Windows hosts emit POSIX-style paths, so no
        # normalization is attempted here, the path is shown verbatim.
        payload["memory_maps_sample"] = [m.path for m in maps[:20]]
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        payload["memory_maps_count"] = None
        payload["memory_maps_sample"] = None
        payload["denied"].append("memory_maps")
    return payload, 200


def api_process_ancestry(backend, pid_str):
    """GET /api/processes/<pid>/ancestry - the Memory Ancestry Graph feed.
    Returns the full ancestry (EXEC-labeled edges) plus the forensic snapshot when one exists.
    The snapshot survives mitigation; 404 when neither source knows the PID.
    Merges the engine's live access edge (kind='access') into the ancestry so birth + injection
    form one graph; the snapshot itself is never rewritten."""
    try:
        pid = int(pid_str)
    except (TypeError, ValueError):
        return {"error": "invalid pid"}, 400

    ancestry = backend.process_tracker.get_ancestry(pid, include_env=True)
    snapshot = backend.engine.forensic_snapshots.get(pid)
    if ancestry is None and snapshot is None:
        return {"error": "no ancestry or forensic snapshot recorded for this pid", "pid": pid}, 404

    if isinstance(ancestry, dict):
        # Prefer live edge store; fall back to snapshot's frozen trigger_edge if evicted from LRU.
        edge = backend.engine._access_edge_for(pid) or (snapshot or {}).get('trigger_edge')
        if edge is not None and not any(e.get('kind') == 'access' for e in ancestry.get('edges', [])):
            merged = dict(edge)
            merged['kind'] = 'access'
            ancestry.setdefault('edges', []).append(merged)

    return {
        "pid": pid,
        "ancestry": ancestry,
        "forensic_snapshot": snapshot,
    }, 200


class AlertStore:
    """Thread-safe, bounded buffer of structured alerts, fed by a logging
    handler attached to the root logger - every finding the engine/scanner/
    monitor/inspector already log becomes a dashboard alert for free.

    HANDS-ON THREAT classification: any log message carrying the
    hands_on.HANDS_ON_TAG marker (see hands_on.py - emitted by the static
    scanner when a finding positively identifies a Cobalt Strike stager)
    is stored with hands_on=True + classification='HANDS-ON THREAT', and
    snapshot() pins those alerts to the TOP of the queue regardless of
    timestamp. The rationale: the most dangerous class of detection must
    be impossible to miss - a hands-on alert that arrived an hour ago and
    has since been buried under thirty benign INFO lines is exactly the
    alert that gets missed during an active intrusion."""

    def __init__(self, maxlen=MAX_ALERTS):
        self._lock = threading.Lock()
        self._alerts = deque(maxlen=maxlen)
        self._next_id = 1

    def add(self, record: logging.LogRecord):
        with self._lock:
            message = record.getMessage()
            entry = {
                "id": self._next_id,
                "ts": record.created,
                "time": time.strftime("%H:%M:%S", time.localtime(record.created)),
                "severity": dd.severity_of(record),
                "category": dd.categorize(message),
                "message": message,
            }
            if is_hands_on_message(message):
                # Distinct visual classification, separate from generic
                # findings: the frontend renders the orange banner off
                # these two fields, and snapshot() pins the row to the
                # top of the queue. Kept as explicit fields (not guessed
                # from the message text at render time) so the contract
                # lives in one place - hands_on.py - not in JavaScript.
                entry["hands_on"] = True
                entry["classification"] = HANDS_ON_LABEL
            self._next_id += 1
            self._alerts.appendleft(entry)

    def snapshot(self, limit=None):
        """Alerts newest-first, EXCEPT that HANDS-ON THREAT alerts are
        pinned to the very top regardless of timestamp. The partition is
        stable (both halves keep their newest-first order), so pinning
        reorders classes, never timestamps. `limit` is applied AFTER
        pinning: a hands-on alert is never truncated away by the page
        size - it would defeat the whole point if the one alert that must
        be seen was the one dropped."""
        with self._lock:
            items = list(self._alerts)
        pinned = [a for a in items if a.get("hands_on")]
        rest = [a for a in items if not a.get("hands_on")]
        ordered = pinned + rest
        return ordered[:limit] if limit else ordered


class AlertLogHandler(logging.Handler):
    def __init__(self, store: AlertStore):
        super().__init__()
        self.store = store

    def emit(self, record):
        self.store.add(record)


class ProcessActivityStore:
    """Thread-safe, bounded buffer of every ProcessCreate Sysmon event seen,
    scored or not - the Falcon/Singularity-style "Process Explorer" view.
    Kept entirely separate from AlertStore: dumping every process launch
    into the Detections feed would drown the actual security signal that
    feed exists to surface."""

    def __init__(self, maxlen=500):
        self._lock = threading.Lock()
        self._events = deque(maxlen=maxlen)

    def add(self, event_id, data):
        if event_id != 1:  # ProcessCreate only
            return
        with self._lock:
            self._events.appendleft({
                "ts": time.time(),
                "time": time.strftime("%H:%M:%S"),
                "pid": data.get("ProcessId"),
                "image": data.get("Image"),
                "parent_image": data.get("ParentImage"),
                "command_line": data.get("CommandLine"),
                "user": data.get("User"),
                # 'sysmon' (default, pre-correlator/single-sensor rows),
                # 'etw' (provisional - ETW's own thin fields only), 'fused'
                # (ETW's low latency + Sysmon's richer fields merged - see
                # process_correlator.py), or 'kernel' (driver-verified
                # ancestry, dispatched independently by submit_kernel -
                # see kernel_sensor.py/process_correlator.py).
                "source": data.get("_source", "sysmon"),
            })

    def snapshot(self, limit=None):
        with self._lock:
            items = list(self._events)
        return items[:limit] if limit else items


class Backend:
    """Owns the engine + detection surfaces, mirroring main.py's wiring."""

    def __init__(self):
        self.session_start = time.time()
        self.alert_store = AlertStore()
        logging.getLogger().addHandler(AlertLogHandler(self.alert_store))
        logging.getLogger().setLevel(logging.INFO)

        # Same instances main.py's CLI constructs, so the dashboard and CLI never diverge in what they detect.
        self.rules = RuleEngine()
        self.config = load_config()
        self.engine = HeuristicEngine(rule_engine=self.rules, config=self.config)
        self.process_activity = ProcessActivityStore()
        self.process_tracker = ProcessTracker()
        self.engine.on_event = self._on_raw_event
        self.inspector = ModuleInspector(self.engine)
        self._sysmon_handle = None
        self._etw_handle = None
        self._kernel_handle = None
        self.correlator = ProcessCorrelator(self.engine, fuse_window=self.config['correlator']['fuse_window_seconds'],
                                            witness_window=self.config['correlator'].get('witness_window_seconds'))
        self.engine.correlator = self.correlator
        self.sysmon_health = SensorHealth("sysmon")
        self.etw_health = SensorHealth("etw")
        self.kernel_health = SensorHealth("kernel")
        # Wire ancestry provider so forensic snapshots walk this tracker's parent/child map.
        self.engine.ancestry_provider = self.process_tracker.get_ancestry

    def _on_raw_event(self, event_id, data):
        """Single fan-out point for HeuristicEngine.on_event - every raw
        Sysmon event feeds both the Process Explorer buffer and the
        lineage tracker, without either of them knowing about the other or
        heuristic_engine.py's on_event contract needing to support more
        than one observer."""
        self.process_activity.add(event_id, data)
        self.process_tracker.add(event_id, data)

    def _pid_seen(self, pid):
        """self_test.py's pid_seen_fn for this entrypoint - reuses
        ProcessActivityStore (every ProcessCreate event, scored or not)
        rather than a new observer, since it already records exactly this.
        str() on both sides because a pid recorded from Sysmon's XML text
        and one from ETW's decoded int field can differ in type for the
        same real PID."""
        return any(str(row.get("pid")) == str(pid) for row in self.process_activity.snapshot())

    def start(self):
        logging.info("[*] Starting Static Ingress Scanner...")
        StaticScanner(self.engine, BINARIES_PATH, rule_engine=self.rules).scan()
        logging.info("[+] Static Scan Complete.")

        logging.info("[*] Starting Behavioral Telemetry Monitors (Sysmon + ETW)...")
        self.correlator.start()
        self._sysmon_handle = start_monitor(self.engine, on_heartbeat=self.sysmon_health.touch,
                                            on_drop=self.sysmon_health.record_drop)
        self._etw_handle = start_etw_monitor(self.engine, on_heartbeat=self.etw_health.touch,
                                             correlator=self.correlator, on_drop=self.etw_health.record_drop)

        # Kernel sensor: ground truth for ancestry and LSASS access. Missing driver = "sensor unavailable", same as Sysmon absent.
        ensure_driver_running()
        self._kernel_handle = start_kernel_monitor(self.engine, self.correlator,
                                                    on_heartbeat=self.kernel_health.touch,
                                                    on_drop=self.kernel_health.record_drop)

        # Per-event witness-gap check (see process_correlator.enable_witness_check).
        if self.config['correlator'].get('witness_check', True):
            self.correlator.enable_witness_check(self._witness_gate)

        threading.Thread(
            target=watchdog_loop,
            args=([self.sysmon_health, self.etw_health, self.kernel_health],),
            kwargs={"blind_state_fn": self._blind_state},
            daemon=True,
        ).start()

        threading.Thread(target=self._module_sweep_loop, daemon=True).start()

        # Periodic self-test (see self_test.py): proves the telemetry pipeline delivers real events end-to-end.
        threading.Thread(
            target=self_test_loop,
            args=(self._pid_seen, self.alert_store),
            kwargs={
                "interval": self.config['self_test']['interval_seconds'],
                "timeout": self.config['self_test']['timeout_seconds'],
            },
            daemon=True,
        ).start()

    def stop(self):
        """Release the ETW session so the process can exit (see
        etw_monitor.stop_etw_monitor). Every other thread here is a daemon;
        pywintrace's consumer thread is the one that isn't. Idempotent."""
        etw_session, self._etw_handle = self._etw_handle, None
        stop_etw_monitor(etw_session)
        # Stops (not deletes) the service. Safe to call even if the kernel sensor never started.
        kernel_session, self._kernel_handle = self._kernel_handle, None
        stop_kernel_monitor(kernel_session)
        stop_driver_service()

    def _module_sweep_loop(self):
        while True:
            time.sleep(MODULE_SWEEP_INTERVAL_SECONDS)
            self.inspector.sweep()

    def _witness_gate(self, sensor_name):
        """True when `sensor_name` ('etw' or 'kernel') staying silent about a
        process creation the other one reported is UNEXPLAINED. A sensor
        that never came up ('unavailable') or is already known to be
        dropping events ('lossy') explains its own silence, so only
        'live'/'stale' count. Read fresh on every call (handles are set in
        start())."""
        handle, health = ((self._etw_handle, self.etw_health) if sensor_name == "etw"
                          else (self._kernel_handle, self.kernel_health))
        return sensor_label(handle, health) in ("live", "stale")

    def _blind_state(self):
        """Aggregate visibility state across both behavioral sensors (see
        sensor_health.compute_blind_state) - computed fresh on every call,
        same as the per-sensor labels below, so it reflects a sensor dying
        (or recovering) mid-run with no state to re-set anywhere."""
        return current_blind_state(
            [(self._sysmon_handle, self.sysmon_health), (self._etw_handle, self.etw_health),
             (self._kernel_handle, self.kernel_health)],
            self.engine.total_events_seen,
        )

    def summary(self):
        alerts = self.alert_store.snapshot()
        last_event = self.engine.last_event_time
        # 'unavailable' = never came up (permanent this run); 'stale'/'live' from SensorHealth heartbeat, fresh per call.
        sysmon_label = sensor_label(self._sysmon_handle, self.sysmon_health)
        etw_label = sensor_label(self._etw_handle, self.etw_health)
        # Kernel-driver: ground truth for ancestry and LSASS access; missing driver = "unavailable".
        kernel_label = sensor_label(self._kernel_handle, self.kernel_health)
        blind_state = self._blind_state()
        return {
            "hostname": socket.gethostname(),
            "session_start": self.session_start,
            "sensor_status": f"Sysmon: {sysmon_label} | ETW: {etw_label} | Kernel: {kernel_label}",
            "sysmon_stale": self.sysmon_health.is_stale(),
            "etw_stale": self.etw_health.is_stale(),
            "kernel_stale": self.kernel_health.is_stale(),
            "sysmon_state": sysmon_label,
            "etw_state": etw_label,
            "kernel_state": kernel_label,
            # Drops = events observed but discarded because the bounded queue was full (all time, this run).
            "sysmon_dropped_events": self.sysmon_health.drops_total(),
            "etw_dropped_events": self.etw_health.drops_total(),
            "kernel_dropped_events": self.kernel_health.drops_total(),
            "witness": self.correlator.witness_stats(),
            "blind_state": blind_state,
            # Negative-evidence flag: alert counts can only be read as "no activity" when blind_state is HEALTHY.
            "negative_evidence_reliable": blind_state == BLIND_STATE_HEALTHY,
            "visibility_caveat": negative_evidence_caveat(blind_state),
            "thresholds": self.config['thresholds'],
            "total_alerts": len(alerts),
            "critical_count": sum(1 for a in alerts if a["severity"] == "CRITICAL"),
            "warning_count": sum(1 for a in alerts if a["severity"] == "WARNING"),
            "processes_monitored": len(self.engine.process_scores),
            "samples_scanned": len(self.engine.static_scores),
            # Proves events flow in real time - benign activity produces no alert but must still be visible.
            "telemetry_events_seen": self.engine.total_events_seen,
            "seconds_since_last_event": (time.time() - last_event) if last_event else None,
        }


class DashboardServer(ThreadingHTTPServer):
    # HTTPServer sets allow_reuse_address=1; on Windows that lets two processes share one port silently.
    # Observed live: repeated runs left multiple elevated instances, and each poll landed on a different
    # in-memory HeuristicEngine. A second instance must fail loudly instead.
    allow_reuse_address = False


class DashboardHandler(BaseHTTPRequestHandler):
    backend: Backend = None  # set by main() before serve_forever

    def log_message(self, fmt, *args):
        pass  # avoid spamming the terminal with an access log line every poll

    def _send_json(self, obj, status=200):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_static(self, rel_path):
        full_path = os.path.normpath(os.path.join(WEBAPP_DIR, rel_path))
        if not full_path.startswith(os.path.normpath(WEBAPP_DIR)) or not os.path.isfile(full_path):
            self._send_json({"error": "not found"}, 404)
            return
        ext = os.path.splitext(full_path)[1]
        with open(full_path, 'rb') as f:
            body = f.read()
        self.send_response(200)
        self.send_header("Content-Type", STATIC_CONTENT_TYPES.get(ext, "application/octet-stream"))
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = urlsplit(self.path).path
        query = parse_qs(urlsplit(self.path).query)
        backend = self.backend

        if path == "/" or path == "/index.html":
            self._send_static("index.html")
        elif path in ("/app.js", "/style.css"):
            self._send_static(path.lstrip("/"))
        elif path == "/api/summary":
            self._send_json(backend.summary())
        elif path == "/api/alerts":
            limit = int(query.get("limit", [100])[0])
            self._send_json(backend.alert_store.snapshot(limit))
        elif path == "/api/alerts/timeseries":
            self._send_json(dd.bucket_alerts(backend.alert_store.snapshot(), minutes=20))
        elif path == "/api/alerts/categories":
            self._send_json(dd.category_counts(backend.alert_store.snapshot()))
        elif path == "/api/processes":
            self._send_json(dd.build_process_rows(backend.engine))
        elif path == "/api/static":
            self._send_json(dd.build_static_rows(backend.engine, BINARIES_PATH))
        elif path == "/api/process-activity":
            limit = int(query.get("limit", [200])[0])
            rows = backend.process_activity.snapshot(limit)
            for row in rows:
                try:
                    row["lineage"] = backend.process_tracker.lineage_string(int(row["pid"]))
                except (TypeError, ValueError):
                    row["lineage"] = ""
            self._send_json(rows)
        elif path == "/api/rules":
            self._send_json(backend.rules.summary())
        else:
            # Detection-forensics routes (see the *_RE regexes above). The
            # helpers return (payload, status) so error shapes are tested
            # without an HTTP server.
            live = PID_LIVE_RE.match(path)
            if live:
                payload, status = api_process_live(live.group(1))
                self._send_json(payload, status)
                return
            ancestry = PID_ANCESTRY_RE.match(path)
            if ancestry:
                payload, status = api_process_ancestry(backend, ancestry.group(1))
                self._send_json(payload, status)
                return
            self._send_json({"error": "not found"}, 404)

    def do_POST(self):
        path = urlsplit(self.path).path
        backend = self.backend

        match = PID_TERMINATE_RE.match(path)
        if match:
            pid = int(match.group(1))
            backend.engine.mitigate(pid)
            self._send_json({"status": "requested", "pid": pid})
            return

        if path == "/api/host/isolate":
            # Falcon/Singularity's "network containment" cuts the host off
            # the network in one click. Actually flipping firewall rules on
            # the operator's own machine from a prototype dashboard is a
            # real, hard-to-reverse system change - simulated only, same
            # line the engine already draws at its score>=50 "simulated
            # memory snapshot" action.
            logging.warning("[ISOLATE] Host isolation requested - simulated only, no firewall changes made.")
            self._send_json({"status": "simulated"})
            return

        self._send_json({"error": "not found"}, 404)


def _is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _relaunch_elevated():
    """Re-invoke this same script, with the same args, via Windows' own
    UAC consent dialog - the Sysmon behavioral monitor needs Administrator
    to subscribe to the event log (see telemetry_monitor.py), and Falcon/
    Singularity-style agents run elevated without the operator having to
    remember to open an elevated terminal by hand. Windows' UAC prompt is
    the actual consent gate here, not this code - a user who clicks "No"
    falls through to the degraded static-only mode below, same as today.
    lpDirectory is set explicitly because ShellExecuteW otherwise launches
    into a different working directory, which would break every relative
    path (BINARIES_PATH, webapp/) this module resolves at import time.

    A True return only means Windows *accepted the request to launch* -
    not that the user approved the prompt or that the new process is
    actually up yet. Callers must confirm with _wait_for_dashboard()
    before treating this as a success."""
    script = os.path.abspath(sys.argv[0])
    params = subprocess.list2cmdline([script] + sys.argv[1:])
    try:
        result = ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, os.getcwd(), 1)
    except Exception:
        return False
    return result > 32  # ShellExecuteW's own success contract


def _dashboard_url():
    return f"http://{HOST}:{PORT}"


def _wait_for_dashboard(timeout, interval=0.5):
    """Poll the dashboard's own API until it responds or `timeout` seconds
    pass. Used two ways: a near-zero-timeout check for "is one already
    running" before we start a second one, and a longer wait to confirm an
    elevated relaunch actually came up before treating it as a success."""
    deadline = time.monotonic() + timeout
    url = _dashboard_url() + "/api/summary"
    while True:
        try:
            with urllib.request.urlopen(url, timeout=1) as resp:
                return resp.status == 200
        except (urllib.error.URLError, OSError):
            pass
        if time.monotonic() >= deadline:
            return False
        time.sleep(interval)


def main():
    # force=True: pywintrace calls basicConfig(ERROR) at import time; without force this call is silently ignored.
    # Safe here because Backend() (which adds AlertLogHandler) isn't constructed until later.
    logging.basicConfig(level=logging.INFO, format='[*] %(message)s', force=True)

    if _wait_for_dashboard(timeout=0):
        logging.info(f"A dashboard is already running at {_dashboard_url()} - opening it instead of starting a duplicate.")
        webbrowser.open(_dashboard_url())
        return

    if os.name == "nt" and not _is_admin() and not os.environ.get("EDR_NO_ELEVATE"):
        logging.info("Not running elevated - requesting Administrator so Sysmon telemetry starts with no manual steps (approve the UAC prompt if one appears)...")
        if _relaunch_elevated() and _wait_for_dashboard(timeout=20):
            logging.info(f"Elevated dashboard is live at {_dashboard_url()} - opening it now. This window can be closed.")
            webbrowser.open(_dashboard_url())
            return
        logging.warning("Elevated instance never came up (declined, blocked, or failed) - continuing here without admin; Sysmon telemetry will be unavailable, static analysis and the module sweep still run.")

    backend = Backend()
    try:
        backend.start()

        DashboardHandler.backend = backend
        try:
            server = DashboardServer((HOST, PORT), DashboardHandler)
        except OSError as e:
            logging.error(f"Could not bind {HOST}:{PORT} ({e}). A dashboard is probably already running under a different account/elevation level - close it first.")
            return

        logging.info(f"Dashboard live at {_dashboard_url()}")
        webbrowser.open(_dashboard_url())
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            logging.info("Shutting down dashboard server...")
            server.shutdown()
    finally:
        # Every way out of main() - Ctrl+C, a failed bind, an unexpected error -
        # must release the ETW session or the process can't exit.
        backend.stop()


if __name__ == "__main__":
    main()
