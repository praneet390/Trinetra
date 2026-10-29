"""Self-check for web_server.py's self-elevation logic - monkeypatches
ShellExecuteW so this never pops a real UAC prompt. Run: python test_web_server.py"""

import logging
import os
import subprocess
import sys
import time

import web_server as ws


class _FakeShell32:
    def __init__(self, return_value=None, raises=None):
        self.return_value = return_value
        self.raises = raises
        self.calls = []

    def ShellExecuteW(self, hwnd, op, exe, params, cwd, show):
        self.calls.append((hwnd, op, exe, params, cwd, show))
        if self.raises:
            raise self.raises
        return self.return_value


def test_relaunch_success_uses_absolute_script_path_and_cwd():
    fake = _FakeShell32(return_value=42)  # ShellExecuteW: >32 means success
    ws.ctypes.windll.shell32 = fake
    sys.argv = ["web_server.py", "--extra"]

    assert ws._relaunch_elevated() is True
    _, op, exe, params, cwd, _ = fake.calls[0]
    assert op == "runas"
    assert exe == sys.executable
    assert cwd == os.getcwd()
    expected_script = os.path.abspath("web_server.py")
    assert params == subprocess.list2cmdline([expected_script, "--extra"])


def test_relaunch_declined_returns_false():
    ws.ctypes.windll.shell32 = _FakeShell32(return_value=5)  # UAC declined / access denied
    assert ws._relaunch_elevated() is False


def test_relaunch_exception_returns_false_not_raises():
    ws.ctypes.windll.shell32 = _FakeShell32(raises=OSError("boom"))
    assert ws._relaunch_elevated() is False


class _FakeResponse:
    def __init__(self, status):
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_wait_for_dashboard_true_when_reachable():
    ws.urllib.request.urlopen = lambda url, timeout=1: _FakeResponse(200)
    assert ws._wait_for_dashboard(timeout=0) is True


def test_wait_for_dashboard_false_when_unreachable():
    def _raise(url, timeout=1):
        raise ws.urllib.error.URLError("connection refused")
    ws.urllib.request.urlopen = _raise
    assert ws._wait_for_dashboard(timeout=0) is False


def test_process_activity_store_captures_process_create_only():
    store = ws.ProcessActivityStore()
    store.add(1, {"ProcessId": "123", "Image": r"C:\Windows\System32\notepad.exe", "ParentImage": r"C:\Windows\explorer.exe", "CommandLine": "notepad.exe", "User": "DESKTOP\\bob"})
    store.add(10, {"SourceProcessId": "999"})  # not a ProcessCreate event - must be ignored
    rows = store.snapshot()
    assert len(rows) == 1
    assert rows[0]["pid"] == "123"
    assert rows[0]["image"] == r"C:\Windows\System32\notepad.exe"


def test_process_activity_store_newest_first_and_bounded():
    store = ws.ProcessActivityStore(maxlen=2)
    for pid in ("1", "2", "3"):
        store.add(1, {"ProcessId": pid, "Image": "x.exe"})
    rows = store.snapshot()
    assert len(rows) == 2, "maxlen must actually bound the buffer"
    assert [r["pid"] for r in rows] == ["3", "2"], "newest event must be first"


def test_backend_wires_engine_events_into_process_activity_and_tracker():
    backend = ws.Backend()
    assert backend.engine.on_event == backend._on_raw_event  # bound methods: '==' not 'is'
    # Backend wires a ProcessCorrelator unconditionally (see process_correlator.py),
    # so a ProcessCreate event no longer dispatches synchronously - it's held
    # for up to fuse_window in case a matching ETW event arrives to fuse
    # with. Shrink the window and drive the GC directly instead of sleeping
    # out the real (2s) default in a test.
    backend.correlator.fuse_window = 0.01
    backend.engine.evaluate_event(
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        '<System><EventID>1</EventID></System>'
        '<EventData><Data Name="ProcessId">4242</Data><Data Name="ParentProcessId">1</Data>'
        '<Data Name="Image">calc.exe</Data></EventData>'
        '</Event>'
    )
    time.sleep(0.02)
    backend.correlator._gc_once()
    rows = backend.process_activity.snapshot()
    assert len(rows) == 1
    assert rows[0]["pid"] == "4242"
    # the same fan-out point must also have fed the lineage tracker
    assert backend.process_tracker.get_chain(4242) == ["calc.exe"]


def test_backend_constructs_rule_engine_and_config():
    backend = ws.Backend()
    assert backend.engine.rule_engine is backend.rules
    assert backend.engine.config is backend.config
    # RuleEngine() picks up the real rules/custom/*.yml, which ships with
    # one example rule - a real, non-mocked integration check that the
    # shipped example actually loads.
    ids = [r['id'] for r in backend.rules.summary()]
    assert 'custom_lolbin_from_appdata_roaming' in ids


def test_rules_endpoint_reflects_rule_engine_summary():
    backend = ws.Backend()
    baseline_count = len(backend.rules.summary())
    # simulate an additional loaded rule without needing a real YAML file on disk
    from rule_engine import Rule
    fake_rule = Rule({'id': 'r1', 'applies_to': 'process_create', 'score': 10,
                       'match': {'all': [{'field': 'image', 'op': 'contains', 'value': 'x'}]}}, source_file='<test>')
    backend.rules.rules.append(fake_rule)
    backend.rules.hit_counts['r1'] = 0
    summary = backend.rules.summary()
    assert len(summary) == baseline_count + 1
    assert any(r['id'] == 'r1' for r in summary)


def test_backend_surfaces_telemetry_contradiction_as_a_categorized_alert():
    # End-to-end through the real pipeline Backend wires up: correlator's
    # logging.warning() -> root logger -> AlertLogHandler -> AlertStore ->
    # dashboard_data.categorize(), with no mocking of any of those hops.
    backend = ws.Backend()
    backend.correlator.fuse_window = 0.01
    backend.correlator.submit_etw(4242, 1, "evil.exe", "t")       # parent PID 1
    backend.correlator.submit_sysmon({'ProcessId': 4242, 'ParentProcessId': 999, 'Image': 'evil.exe'}, "t")
    time.sleep(0.02)
    backend.correlator._gc_once()
    alerts = backend.alert_store.snapshot()
    contradiction_alerts = [a for a in alerts if a["category"] == "Telemetry Contradiction"]
    assert len(contradiction_alerts) == 1
    assert "PID 4242" in contradiction_alerts[0]["message"]
    assert contradiction_alerts[0]["severity"] == "WARNING"


def test_backend_summary_blind_state_critically_blind_before_start():
    # Backend() alone (start() never called) is exactly what a fresh
    # dashboard process looks like before any sensor has come up -
    # zero events ever seen, all three handles still None.
    backend = ws.Backend()
    assert backend.summary()["blind_state"] == "CRITICALLY_BLIND"


def test_backend_summary_blind_state_healthy_when_both_sensors_live():
    # "both" here now means all three (sysmon/etw/kernel) - a missing
    # kernel driver sensor is just as real a visibility gap as a dead
    # Sysmon subscription, so HEALTHY requires every one of them live.
    backend = ws.Backend()
    backend._sysmon_handle = object()
    backend._etw_handle = object()
    backend._kernel_handle = object()
    backend.sysmon_health.touch()
    backend.etw_health.touch()
    backend.kernel_health.touch()
    assert backend.summary()["blind_state"] == "HEALTHY"


def test_backend_summary_blind_state_degraded_when_one_sensor_down():
    backend = ws.Backend()
    backend._sysmon_handle = object()
    backend._etw_handle = object()
    backend._kernel_handle = object()
    backend.sysmon_health.touch()
    backend.kernel_health.touch()
    # etw_health never touched -> stale, sysmon/kernel still live
    assert backend.summary()["blind_state"] == "DEGRADED"


def test_backend_summary_blind_state_partially_blind_once_events_were_seen():
    backend = ws.Backend()
    backend._sysmon_handle = object()
    backend._etw_handle = object()
    backend._kernel_handle = object()
    backend.engine.total_events_seen = 1  # telemetry flowed at some point this session
    # no sensor touched -> all stale, no sensor currently live
    assert backend.summary()["blind_state"] == "PARTIALLY_BLIND"


def test_backend_summary_blind_state_recovers_when_sensor_comes_back():
    backend = ws.Backend()
    backend._sysmon_handle = object()
    backend._etw_handle = object()
    backend._kernel_handle = object()
    assert backend.summary()["blind_state"] == "CRITICALLY_BLIND"
    backend.sysmon_health.touch()
    backend.etw_health.touch()
    backend.kernel_health.touch()
    assert backend.summary()["blind_state"] == "HEALTHY", "must be recomputed fresh on every summary() call"


def test_backend_summary_negative_evidence_reliable_only_when_healthy():
    backend = ws.Backend()
    backend._sysmon_handle = object()
    backend._etw_handle = object()
    backend._kernel_handle = object()
    # CRITICALLY_BLIND (nothing touched yet) - "0 alerts" must not be
    # reported as trustworthy.
    summary = backend.summary()
    assert summary["negative_evidence_reliable"] is False
    assert summary["visibility_caveat"] is not None

    backend.sysmon_health.touch()
    backend.etw_health.touch()
    backend.kernel_health.touch()
    summary = backend.summary()
    assert summary["negative_evidence_reliable"] is True
    assert summary["visibility_caveat"] is None


def test_backend_summary_visibility_caveat_distinguishes_degraded_from_critically_blind():
    backend = ws.Backend()
    backend._sysmon_handle = object()
    backend._etw_handle = object()
    backend._kernel_handle = object()
    backend.sysmon_health.touch()
    backend.kernel_health.touch()  # sysmon+kernel live, etw never touched -> DEGRADED
    degraded_summary = backend.summary()
    assert degraded_summary["blind_state"] == "DEGRADED"

    backend2 = ws.Backend()
    backend2._sysmon_handle = object()
    backend2._etw_handle = object()
    backend2._kernel_handle = object()  # none touched -> CRITICALLY_BLIND
    critical_summary = backend2.summary()
    assert critical_summary["blind_state"] == "CRITICALLY_BLIND"

    assert degraded_summary["visibility_caveat"] != critical_summary["visibility_caveat"], \
        "a partially-redundant DEGRADED state and total CRITICALLY_BLIND must not get the same caveat"


def test_backend_summary_reports_a_lossy_sensor_its_drop_count_and_recovery():
    backend = ws.Backend()
    backend._sysmon_handle = object()
    backend._etw_handle = object()
    backend._kernel_handle = object()
    backend.sysmon_health.touch()
    backend.etw_health.touch()
    backend.kernel_health.touch()
    healthy = backend.summary()
    assert healthy["blind_state"] == "HEALTHY" and healthy["etw_state"] == "live"
    assert healthy["etw_dropped_events"] == 0 and healthy["sysmon_dropped_events"] == 0

    for _ in range(3):
        backend.etw_health.record_drop()
    lossy = backend.summary()
    assert lossy["etw_state"] == "lossy" and "ETW: lossy" in lossy["sensor_status"]
    assert lossy["sysmon_state"] == "live"
    assert lossy["blind_state"] == "DEGRADED"
    assert lossy["negative_evidence_reliable"] is False and lossy["visibility_caveat"]
    assert lossy["etw_dropped_events"] == 3 and lossy["sysmon_dropped_events"] == 0
    assert lossy["etw_stale"] is False, "a sensor that is dropping events is not stale"

    backend.etw_health.drop_window = 0.05  # let the drops age out
    time.sleep(0.07)
    backend.sysmon_health.touch()
    backend.etw_health.touch()
    backend.kernel_health.touch()
    recovered = backend.summary()
    assert recovered["etw_state"] == "live" and recovered["blind_state"] == "HEALTHY"
    assert recovered["etw_dropped_events"] == 3, "the all-time count is kept after recovery"


class _FakeETWSession:
    def __init__(self):
        self.stop_calls = 0

    def stop(self):
        self.stop_calls += 1


def test_backend_stop_releases_the_etw_session_exactly_once():
    backend = ws.Backend()
    session = _FakeETWSession()
    backend._etw_handle = session
    backend.stop()
    backend.stop()  # idempotent: a second call must not stop it again
    assert session.stop_calls == 1
    assert backend._etw_handle is None


def test_backend_stop_without_an_etw_session_is_harmless():
    ws.Backend().stop()  # ETW never started (e.g. not elevated): nothing to release, must not raise


def _run_web_main(serve_error=None, bind_error=None, start_error=None):
    """Runs web_server.main() with every side effect faked (backend, server,
    browser, UAC self-elevation, single-instance probe) and returns the order
    of the calls it made plus any exception it let escape."""
    import logging
    import os

    calls = []

    class _FakeBackend:
        def start(self):
            calls.append("start")
            if start_error:
                raise start_error

        def stop(self):
            calls.append("stop")

    class _FakeServer:
        def __init__(self, address, handler):
            if bind_error:
                raise bind_error
            calls.append("bind")

        def serve_forever(self):
            calls.append("serve")
            if serve_error:
                raise serve_error

        def shutdown(self):
            calls.append("shutdown")

    root = logging.getLogger()
    saved_handlers, saved_level = root.handlers[:], root.level
    saved = (ws.Backend, ws.DashboardServer, ws._wait_for_dashboard, ws.webbrowser.open,
             ws.DashboardHandler.backend, os.environ.get("EDR_NO_ELEVATE"))
    ws.Backend, ws.DashboardServer = _FakeBackend, _FakeServer
    ws._wait_for_dashboard = lambda timeout, interval=0.5: False
    ws.webbrowser.open = lambda url: None
    os.environ["EDR_NO_ELEVATE"] = "1"
    escaped = None
    try:
        ws.main()
    except BaseException as e:  # noqa: BLE001 - the test inspects exactly what escapes
        escaped = e
    finally:
        (ws.Backend, ws.DashboardServer, ws._wait_for_dashboard, ws.webbrowser.open,
         ws.DashboardHandler.backend, previous_env) = saved
        if previous_env is None:
            os.environ.pop("EDR_NO_ELEVATE", None)
        else:
            os.environ["EDR_NO_ELEVATE"] = previous_env
        for handler in root.handlers[:]:
            root.removeHandler(handler)
        for handler in saved_handlers:
            root.addHandler(handler)
        root.setLevel(saved_level)
    return calls, escaped


def test_main_releases_the_etw_session_on_ctrl_c():
    # The reported bug: Ctrl+C stopped the server but left pywintrace's
    # non-daemon consumer thread running, so the process hung until a 2nd Ctrl+C.
    calls, escaped = _run_web_main(serve_error=KeyboardInterrupt())
    assert escaped is None
    assert calls == ["start", "bind", "serve", "shutdown", "stop"], "stop() must run last, after the server shut down"


def test_main_releases_the_etw_session_when_the_port_is_already_taken():
    # Same bug, second exit path: backend.start() had already launched the ETW
    # thread when the bind failed and main() returned.
    calls, escaped = _run_web_main(bind_error=OSError("Address already in use"))
    assert escaped is None
    assert calls == ["start", "stop"]


def test_main_releases_the_etw_session_on_an_unexpected_error():
    boom = RuntimeError("boom")
    calls, escaped = _run_web_main(serve_error=boom)
    assert escaped is boom, "the error must still propagate, not be swallowed"
    assert calls == ["start", "bind", "serve", "stop"]


def test_main_releases_the_etw_session_even_if_backend_start_fails_midway():
    boom = RuntimeError("sensor start failed after ETW came up")
    calls, escaped = _run_web_main(start_error=boom)
    assert escaped is boom
    assert calls == ["start", "stop"]


def test_dashboard_server_refuses_to_share_a_port():
    # The bug this guards against: http.server's default
    # allow_reuse_address=True let two separate elevated instances bind
    # 127.0.0.1:8787 at once on Windows, silently round-robining requests
    # across two different HeuristicEngine states. A second instance must
    # fail loudly (Address already in use), never coexist silently.
    assert ws.DashboardServer.allow_reuse_address is False


def test_alertstore_flags_hands_on_threat_alerts():
    # The HANDS-ON THREAT contract end-to-end at the store level: a log
    # record carrying the hands_on tag (what static_scanner emits when a
    # finding positively identifies a Cobalt Strike stager) must come back
    # with the classification fields set, and an ordinary finding must not.
    store = ws.AlertStore()
    store.add(logging.LogRecord('t', logging.WARNING, __file__, 1,
                                "[HANDS-ON THREAT] evil.exe: Cobalt Strike stager - imphash matches known family 'CobaltStrike'",
                                None, None))
    store.add(logging.LogRecord('t', logging.WARNING, __file__, 1,
                                "Untrusted access to svchost.exe (Access: 0x143a) - Potential Process Hollowing",
                                None, None))
    rows = store.snapshot()
    assert rows[0]['hands_on'] is True
    assert rows[0]['classification'] == 'HANDS-ON THREAT'
    assert 'Cobalt Strike stager' in rows[0]['message']
    # ordinary findings carry no classification
    assert 'hands_on' not in rows[1]
    assert 'classification' not in rows[1]


def test_alertstore_pins_hands_on_alerts_regardless_of_timestamp():
    # Pinning contract: the hands-on alert arrived FIRST (oldest), got
    # buried under newer ordinary alerts, and must still come back on top
    # - the most dangerous class of detection is impossible to miss no
    # matter how much noise arrived after it.
    store = ws.AlertStore()
    store.add(logging.LogRecord('t', logging.WARNING, __file__, 1,
                                "[HANDS-ON THREAT] stager.exe: Cobalt Strike stager identified", None, None))
    for i in range(5):
        store.add(logging.LogRecord('t', logging.INFO, __file__, 1,
                                    f"benign operational line {i}", None, None))
    rows = store.snapshot()
    assert rows[0]['hands_on'] is True
    assert all(not a.get('hands_on') for a in rows[1:])
    # within each class the newest-first order is preserved (pinning
    # reorders classes, never timestamps)
    ordinary = [a['message'] for a in rows[1:]]
    assert ordinary == sorted(ordinary, key=lambda m: int(m.split()[-1]), reverse=True)


def test_alertstore_pinning_survives_limit():
    # limit is applied AFTER pinning: a page size smaller than the buffer
    # must never truncate away a hands-on alert - that would defeat the
    # whole point of pinning.
    store = ws.AlertStore()
    store.add(logging.LogRecord('t', logging.WARNING, __file__, 1,
                                "[HANDS-ON THREAT] stager.exe: Cobalt Strike stager identified", None, None))
    for i in range(20):
        store.add(logging.LogRecord('t', logging.INFO, __file__, 1,
                                    f"filler {i}", None, None))
    rows = store.snapshot(limit=10)
    assert len(rows) == 10
    assert rows[0]['hands_on'] is True


def test_backend_wires_ancestry_provider_for_forensic_snapshots():
    backend = ws.Backend()
    # The engine's detection-time ancestry capture must walk THIS backend's
    # lineage tracker - the same graph the Process Explorer Lineage column
    # renders - so snapshots and the UI can never disagree.
    assert backend.engine.ancestry_provider == backend.process_tracker.get_ancestry


def test_live_endpoint_reports_a_live_process(monkeypatch):
    class _FakeAddr:
        def __init__(self, ip, port):
            self.ip, self.port = ip, port

    class _FakeConn:
        fd = 99
        laddr = _FakeAddr('127.0.0.1', 4444)
        raddr = _FakeAddr('10.0.0.5', 80)
        status = 'ESTABLISHED'

    class _FakeMem:
        rss, vms = 1048576, 2097152

    class _FakeMap:
        def __init__(self, path):
            self.path = path

    class _FakeFile:
        def __init__(self, path):
            self.path, self.fd = path, 7

    class _FakeProc:
        def name(self):
            return 'implant.exe'
        def status(self):
            return 'running'
        def create_time(self):
            return 1000.0
        def num_threads(self):
            return 4
        def memory_info(self):
            return _FakeMem()
        def open_files(self):
            return [_FakeFile(r'C:\Temp\staged.dll')]
        def net_connections(self):
            return [_FakeConn()]
        def memory_maps(self):
            return [_FakeMap('a.dll'), _FakeMap('b.dll')]

    monkeypatch.setattr(ws.psutil, 'Process', lambda pid: _FakeProc())
    payload, status = ws.api_process_live('777003')
    assert status == 200
    assert payload['alive'] is True
    assert payload['name'] == 'implant.exe'
    assert payload['num_threads'] == 4
    assert payload['open_files'][0]['path'] == r'C:\Temp\staged.dll'
    assert payload['net_connections'][0]['raddr'] == '10.0.0.5:80'
    assert payload['memory_maps_count'] == 2
    assert payload['denied'] == []


def test_live_endpoint_reports_partial_denial_without_failing(monkeypatch):
    # Elevated/protected processes deny individual reads; 'alive but locked
    # down' is the analyst's answer, so denied fields are marked, not fatal.
    class _DeniedProc:
        def name(self):
            return 'protected.exe'
        def status(self):
            raise ws.psutil.AccessDenied()
        def create_time(self):
            raise ws.psutil.AccessDenied()
        def num_threads(self):
            raise ws.psutil.AccessDenied()
        def memory_info(self):
            raise ws.psutil.AccessDenied()
        def open_files(self):
            raise ws.psutil.AccessDenied()
        def net_connections(self):
            raise ws.psutil.AccessDenied()
        def memory_maps(self):
            raise ws.psutil.AccessDenied()

    monkeypatch.setattr(ws.psutil, 'Process', lambda pid: _DeniedProc())
    payload, status = ws.api_process_live('777004')
    assert status == 200
    assert payload['alive'] is True
    assert payload['name'] == 'protected.exe'
    assert 'net_connections' in payload['denied']
    assert payload['net_connections'] is None


def test_live_endpoint_404_for_dead_pid(monkeypatch):
    def _gone(pid):
        raise ws.psutil.NoSuchProcess(pid)
    monkeypatch.setattr(ws.psutil, 'Process', _gone)
    payload, status = ws.api_process_live('777005')
    assert status == 404
    assert payload['alive'] is False


def test_live_endpoint_400_for_garbage_pid():
    payload, status = ws.api_process_live('abc')
    assert status == 400


def test_ancestry_endpoint_merges_tracker_and_snapshot():
    backend = ws.Backend()
    pid = 777006
    backend.process_tracker.add(1, {'ProcessId': '1', 'ParentProcessId': None, 'Image': 'explorer.exe'})
    backend.process_tracker.add(1, {'ProcessId': str(pid), 'ParentProcessId': '1',
                                    'Image': 'evil.exe', 'CommandLine': 'evil.exe --go'})
    backend.engine._add_score(pid, 60, 'staging dir exec', check_id='staging_dir')  # crosses warning(50) -> snapshot
    payload, status = ws.api_process_ancestry(backend, str(pid))
    assert status == 200
    ancestry = payload['ancestry']
    assert [n['pid'] for n in ancestry['nodes']] == [1, pid]
    assert ancestry['edges'] == [{'from': 1, 'to': pid, 'label': 'EXEC'}]
    assert payload['forensic_snapshot']['trigger'] == 'warning_threshold'
    assert payload['forensic_snapshot']['chain_summary'] == 'explorer.exe -> evil.exe'


def test_ancestry_endpoint_merges_access_edge_observed_after_the_snapshot():
    # COMPLETE-CHAIN contract: the LSASS/injection connection can be
    # observed AFTER the warning-tier snapshot froze (first-wins evidence,
    # never rewritten). The endpoint must still present ONE complete graph
    # - EXEC birth edges from the tracker plus the MMAP(RWX) access edge
    # from the engine's store - without mutating the stored snapshot.
    backend = ws.Backend()
    pid = 777020
    backend.process_tracker.add(1, {'ProcessId': '1', 'ParentProcessId': None, 'Image': 'explorer.exe'})
    backend.process_tracker.add(1, {'ProcessId': str(pid), 'ParentProcessId': '1',
                                    'Image': 'implant.exe', 'CommandLine': 'implant.exe'})
    backend.engine._add_score(pid, 60, 'staging dir exec', check_id='staging_dir')  # warning -> snapshot frozen
    assert backend.engine.forensic_snapshots[pid]['trigger_edge'] is None
    backend.engine._handle_process_access({                       # connection seen LATER
        'SourceProcessId': pid, 'SourceImage': r'C:\Temp\implant.exe',
        'TargetProcessId': 700, 'TargetImage': 'c:\\windows\\system32\\lsass.exe',
        'GrantedAccess': '0x1438',
    })
    payload, status = ws.api_process_ancestry(backend, str(pid))
    assert status == 200
    edges = payload['ancestry']['edges']
    exec_edges = [e for e in edges if e['label'] == 'EXEC']
    access_edges = [e for e in edges if e.get('kind') == 'access']
    assert len(exec_edges) == 1
    assert len(access_edges) == 1
    assert access_edges[0]['syscall'] == 'MMAP(RWX)'
    # the frozen evidence itself must remain untouched
    assert backend.engine.forensic_snapshots[pid]['ancestry']['edges'] == [
        {'from': 1, 'to': pid, 'label': 'EXEC'}]


def test_ancestry_endpoint_snapshot_only_for_evicted_tracker_entries():
    # A PID whose tracker entries were evicted but whose forensic snapshot
    # survives must still return 200 - the snapshot IS the evidence copy.
    backend = ws.Backend()
    pid = 777007
    backend.engine.forensic_snapshots[pid] = {
        'pid': pid, 'taken_at': 0.0, 'trigger': 'critical_threshold',
        'score_at_capture': 90, 'activity_span_seconds': None,
        'activity_span_human': None, 'chain_summary': None,
        'ancestry': None, 'ancestry_note': 'test', 'trigger_edge': None,
    }
    payload, status = ws.api_process_ancestry(backend, str(pid))
    assert status == 200
    assert payload['ancestry'] is None
    assert payload['forensic_snapshot']['trigger'] == 'critical_threshold'


def test_ancestry_endpoint_404_when_neither_source_knows_the_pid():
    backend = ws.Backend()
    payload, status = ws.api_process_ancestry(backend, '777008')
    assert status == 404


def test_ancestry_endpoint_400_for_garbage_pid():
    backend = ws.Backend()
    payload, status = ws.api_process_ancestry(backend, '')
    assert status == 400


class _MonkeyPatch:
    """Minimal stand-in for pytest's `monkeypatch` fixture, for this file's
    standalone `python test_web_server.py` runner (pytest's fixture
    injection isn't available outside pytest itself). Tracks every setattr
    so it can be undone after the test, matching pytest's per-test teardown."""
    def __init__(self):
        self._undo = []

    def setattr(self, obj, name, value):
        self._undo.append((obj, name, getattr(obj, name)))
        setattr(obj, name, value)

    def undo(self):
        for obj, name, old in reversed(self._undo):
            setattr(obj, name, old)


def test_backend_summary_exposes_the_witness_stats():
    backend = ws.Backend()
    witness = backend.summary()["witness"]
    assert witness == {
        'enabled': False,  # armed in start(), which this test never calls
        'window_seconds': 5.0,
        'gaps': {'etw': 0, 'kernel': 0},
        'active_gaps': [],
        'creator_agreement': {'agree': 0, 'disagree': 0},
    }


def test_backend_witness_gate_trusts_only_live_or_stale_sensors():
    backend = ws.Backend()
    # never started: handles are None -> 'unavailable' -> silence is explained
    assert backend._witness_gate("etw") is False and backend._witness_gate("kernel") is False

    backend._etw_handle = object()
    backend._kernel_handle = object()
    assert backend._witness_gate("etw") is True, "up but never heartbeated ('stale'): silence is unexplained"
    backend.etw_health.touch()
    assert backend._witness_gate("etw") is True, "'live'"
    backend.etw_health.record_drop()
    assert backend._witness_gate("etw") is False, "'lossy': already known to be dropping events"
    assert backend._witness_gate("kernel") is True, "each sensor is judged on its own health"


def test_backend_surfaces_a_sensor_blindspot_as_a_categorized_alert():
    # Real pipeline, no mocks of the hops: correlator -> logging -> AlertStore -> categorize.
    backend = ws.Backend()
    backend._etw_handle = object()
    backend.etw_health.touch()
    backend.correlator.enable_witness_check(backend._witness_gate, startup_grace=0.0)
    time.sleep(0.01)
    backend.correlator.witness_window = 0.01
    backend.correlator.submit_kernel(4243, 1, 1, "evil.exe", False)
    time.sleep(0.03)
    backend.correlator._gc_once()
    alerts = [a for a in backend.alert_store.snapshot() if a["category"] == "Sensor Visibility"]
    assert len(alerts) == 1 and "PID 4243" in alerts[0]["message"] and alerts[0]["severity"] == "WARNING"
    assert backend.summary()["witness"]["gaps"]["etw"] == 1


if __name__ == "__main__":
    import inspect

    # Auto-collect every test_* function, same pattern every other test file
    # in this repo uses - the previous hand-written call list here silently
    # dropped 13 tests (every HANDS-ON alert, Live Agent Feedback, and
    # Ancestry endpoint test added alongside it) because nothing enforced
    # that the list stayed in sync with what was actually defined below.
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for t in tests:
        if "monkeypatch" in inspect.signature(t).parameters:
            mp = _MonkeyPatch()
            try:
                t(mp)
            finally:
                mp.undo()
        else:
            t()
        print(f"  ok  {t.__name__}")
    print(f"OK ({len(tests)} checks)")
