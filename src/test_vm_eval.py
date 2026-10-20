"""Self-check for vm_eval.py. Needs no agent, no Sysmon and no elevation: the
agent API is faked, and the scenario launchers are checked against the real
HeuristicEngine rules without starting the scenario processes.
Run: python test_vm_eval.py"""

import logging
import os
import subprocess
import time

import heuristic_engine as he
import vm_eval as ve

CMD = ["cmd.exe", "/c", "exit", "0"]
POWERSHELL = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"


def alert(id_, pid, context="ctx", total=45, ts=1000.0, prefix="[TELEMETRY]"):
    return {"id": id_, "ts": ts, "message": f"{prefix} PID {pid} -> +45 ({context}) | Total Score: {total}"}


def run_with(pids, token="deadbeef"):
    run = ve.Run()
    run.token, run.pids = token, set(pids)
    return run


# ---- evaluate() ----------------------------------------------------------------

def test_evaluate_matches_run_pids_and_ignores_others():
    alerts = [alert(1, 111, "Obfuscated/download-execute x", total=45, ts=1002.5), alert(2, 999, "other")]
    ev = ve.evaluate(alerts, run_with({111}), "Obfuscated/download-execute", t0=1000.0)
    assert ev["detected"] and ev["peak_score"] == 45 and ev["time_to_alert_s"] == 2.5
    assert not ve.evaluate(alerts[1:], run_with({111}), "other", 1000.0)["any_hit"]


def test_evaluate_expect_filters_by_message_but_peak_counts_every_hit():
    alerts = [alert(1, 111, "Execution from staging directory", total=30),
              alert(2, 111, "Obfuscated/download-execute", total=75)]
    ev = ve.evaluate(alerts, run_with({111}), "Execution from staging directory", 1000.0)
    assert ev["detected"] and ev["peak_score"] == 75
    assert not ve.evaluate(alerts, run_with({111}), "Attempted Defender tampering", 1000.0)["detected"]


def test_evaluate_matches_by_token_when_pid_unknown():
    alerts = [alert(1, 555, "Persistence attempt in Run key: ...\\edrevaldeadbeef")]
    assert ve.evaluate(alerts, run_with(set()), "Persistence", 1000.0)["detected"]
    assert not ve.evaluate(alerts, run_with(set(), token="cafef00d"), "Persistence", 1000.0)["detected"]


def test_evaluate_no_expect_means_any_hit_and_a_non_telemetry_line_is_not_a_hit():
    assert ve.evaluate([alert(1, 111)], run_with({111}), None, 0)["detected"]
    noise = [{"id": 1, "ts": 1.0, "message": "[SELF-TEST] PID 111 canary"}]
    assert not ve.evaluate(noise, run_with({111}), None, 0)["any_hit"]


def test_evaluate_sees_mitigation_only_for_this_runs_pids():
    kill = {"id": 3, "ts": 1.0, "message": "[+] Successfully terminated malicious process: powershell.exe (PID: 111)"}
    crit = {"id": 4, "ts": 1.0, "message": "[CRITICAL THREAT] PID 222 crossed mitigation threshold (Score 90). Mitigating..."}
    assert ve.evaluate([kill], run_with({111}), None, 0)["mitigated"]
    assert ve.evaluate([crit], run_with({222}), None, 0)["mitigated"]
    assert not ve.evaluate([kill, crit], run_with({333}), None, 0)["mitigated"]


# ---- Run.spawn / run_attack / run_benign with a fake agent --------------------------

def test_spawn_records_pid_and_returns_exit_code():
    run = ve.Run()
    assert run.spawn(CMD) == 0
    assert len(run.pids) >= 1


def test_spawn_records_descendants():
    run = ve.Run()
    run.spawn(["cmd.exe", "/c", "ping -n 3 127.0.0.1 >nul"])
    assert len(run.pids) >= 2, "cmd.exe and its ping.exe child"


def test_spawn_kills_its_own_overrunning_child():
    run, started = ve.Run(), time.monotonic()
    code = run.spawn(["ping.exe", "-n", "30", "127.0.0.1"], timeout=0.3)  # would run ~29s
    assert time.monotonic() - started < 5 and code != 0


class FakeApi:
    """Reports one alert per PID the scenario used, if `context` is set."""

    def __init__(self, seen, context=None):
        self.seen, self.context = seen, context

    def alerts(self):
        if not self.context:
            return []
        return [alert(10 + i, pid, self.context, ts=time.time()) for i, pid in enumerate(self.seen)]


def _spy_spawn(seen):
    original = ve.Run.spawn

    def spy(self, command, timeout=ve.PROC_TIMEOUT_SECONDS):
        result = original(self, command, timeout)
        seen.extend(self.pids)
        return result
    ve.Run.spawn = spy
    return original


def _run_attack(scenario, context, **kw):
    seen = []
    original = _spy_spawn(seen)
    try:
        return ve.run_attack(FakeApi(seen, context), scenario, **kw)
    finally:
        ve.Run.spawn = original


def test_run_attack_detected_missed_norule_and_unexpected():
    launch = lambda run: run.spawn(CMD)
    r = _run_attack(ve.Scenario("s", "T1", "Obfuscated", launch), "Obfuscated command", timeout=3)
    assert r.verdict == "DETECTED" and r.detected and r.time_to_alert_s is not None and not r.failed

    r = _run_attack(ve.Scenario("s", "T1", "Obfuscated", launch), None, timeout=1)
    assert r.verdict == "MISSED" and r.failed

    r = _run_attack(ve.Scenario("s", "T1", None, launch), None, settle=1)
    assert r.verdict == "NO RULE" and r.kind == "gap" and not r.failed  # a coverage gap is reported, not failed

    r = _run_attack(ve.Scenario("s", "T1", None, launch), "something", settle=1)
    assert r.verdict == "DETECTED*" and not r.failed


def test_run_attack_always_runs_cleanup_even_when_launch_fails():
    cleaned = []

    def boom(run):
        run.cleanups.append(lambda: cleaned.append(1))
        raise RuntimeError("launch exploded")

    r = _run_attack(ve.Scenario("s", "T1", "x", boom), None, timeout=1)
    assert r.verdict == "ERROR" and "launch exploded" in r.error and cleaned == [1] and r.failed


def test_a_failing_cleanup_is_reported_and_does_not_stop_the_others():
    run = ve.Run()
    done = []
    run.cleanups += [lambda: done.append("first-registered-runs-last"), lambda: 1 / 0]
    run.cleanup()
    assert done and len(run.cleanup_errors) == 1


def test_run_benign_flags_false_positives_skips_missing_tools():
    original_benign = ve.BENIGN
    ve.BENIGN = [("ok", CMD), ("missing_tool", ["definitely-not-installed-xyz.exe"])]
    try:
        seen = []
        original = _spy_spawn(seen)
        try:
            clean = ve.run_benign(FakeApi(seen, None), settle=0)
            flagged = ve.run_benign(FakeApi(seen, "Obfuscated"), settle=0)
        finally:
            ve.Run.spawn = original
    finally:
        ve.BENIGN = original_benign
    assert [r.verdict for r in clean] == ["CLEAN", "SKIPPED"]
    assert [r.verdict for r in flagged] == ["FALSE POSITIVE", "SKIPPED"] and flagged[0].failed
    assert not clean[1].failed


# ---- the scenario table must agree with the real engine ---------------------------

def test_every_expected_alert_text_exists_in_the_engine_source():
    source = open(os.path.join(os.path.dirname(he.__file__), "heuristic_engine.py"), encoding="utf-8").read()
    for sc in ve.SCENARIOS:
        assert sc.expect is None or sc.expect in source, f"{sc.name}: engine never emits {sc.expect!r}"


def _messages_from(engine_call):
    records = []

    class Grab(logging.Handler):
        def emit(self, record):
            records.append(record.getMessage())

    grab, root = Grab(), logging.getLogger()
    root.addHandler(grab)
    root.setLevel(logging.INFO)
    try:
        engine_call()
    finally:
        root.removeHandler(grab)
    return records


def _captured_command(launch):
    """The command a launcher would run, without running it."""
    captured = []
    original = ve.Run.spawn
    ve.Run.spawn = lambda self, command, timeout=0: captured.append(command)
    run = ve.Run()
    try:
        launch(run)
    finally:
        ve.Run.spawn = original
        run.cleanup()
    return captured, run


def _command_line(command):
    return command if isinstance(command, str) else subprocess.list2cmdline(command)


def test_command_line_launchers_trigger_the_expected_engine_rule():
    for sc in ve.SCENARIOS:
        if sc.name not in ("ps_encoded", "ps_download_cradle", "defender_tamper"):
            continue
        (command,), _ = _captured_command(sc.launch)
        engine, pid = he.HeuristicEngine(), 900_000_000 + len(sc.name)
        messages = _messages_from(lambda: engine._dispatch(
            1, {"ProcessId": pid, "Image": POWERSHELL, "CommandLine": _command_line(command)}))
        assert any(f"PID {pid} ->" in m and sc.expect in m for m in messages), (sc.name, messages)


def test_defender_tamper_launcher_never_runs_the_command_it_prints():
    (command,), _ = _captured_command(ve.launch_defender_tamper)
    line = _command_line(command)
    assert "Write-Output 'Set-MpPreference" in line, "the tamper text must only ever be printed"


def test_runkey_launcher_hits_the_run_key_rule_and_cleans_up_after_itself():
    (command,), run = _captured_command(ve.launch_runkey)
    assert command[1] == "add" and "\\CurrentVersion\\Run" in command[2] and command[4].endswith(run.token)
    engine, pid = he.HeuristicEngine(), 900_000_101
    messages = _messages_from(lambda: engine._dispatch(13, {
        "ProcessId": pid, "TargetObject": rf"HKU\S-1-5-21\{command[2].split(chr(92), 1)[1]}\{command[4]}"}))
    assert any(ve.SCENARIOS[5].expect in m and run.token in m.lower() for m in messages)
    assert run.cleanups, "the Run value must be deleted afterwards"


def test_staging_and_office_launchers_use_paths_the_engine_keys_on():
    (staged,), _ = _captured_command(ve.launch_staging_dir)
    assert "temp" in staged[0].lower() and staged[0].endswith("stage.exe")
    (office,), run = _captured_command(ve.launch_office_parent)
    assert office.startswith('"') and 'winword.exe" /c cmd.exe' in office and "temp" not in office.lower()
    engine, pid = he.HeuristicEngine(), 900_000_202
    messages = _messages_from(lambda: engine._dispatch(1, {
        "ProcessId": pid, "Image": r"C:\Windows\System32\cmd.exe", "ParentImage": office.split('"')[1],
        "CommandLine": "cmd.exe /c ping -n 3 127.0.0.1"}))
    assert any(ve.SCENARIOS[2].expect in m for m in messages), messages


def test_ransomware_launcher_stays_inside_a_monitored_dir_and_is_not_an_excluded_process():
    (command,), run = _captured_command(ve.launch_ransomware_burst)
    assert command.startswith("cmd.exe") and "cmd.exe" not in he.RANSOMWARE_EXCLUDED_PROCESSES
    assert any(d in command.lower() for d in he.RANSOMWARE_MONITORED_DIRS)
    threshold = he.HeuristicEngine().config["ransomware"]["file_event_threshold"]
    assert int(command.split("(1,1,")[1].split(")")[0]) > threshold
    engine, pid = he.HeuristicEngine(), 900_000_303
    messages = _messages_from(lambda: [engine._dispatch(11, {
        "ProcessId": pid, "Image": r"C:\Windows\System32\cmd.exe",
        "TargetFilename": rf"C:\Users\u\Documents\edr_eval_{run.token}\f{i}.txt"}) for i in range(threshold + 5)])
    assert any(ve.SCENARIOS[7].expect in m for m in messages)


def test_lsass_launcher_requests_an_access_mask_the_engine_treats_as_dangerous():
    (command,), _ = _captured_command(ve.launch_lsass_handle)
    assert "OpenProcess(0x1010" in command[-1]
    engine, pid = he.HeuristicEngine(), 900_000_404
    messages = _messages_from(lambda: engine._dispatch(10, {
        "SourceProcessId": pid, "SourceImage": r"C:\venv\python.exe",
        "TargetImage": r"C:\Windows\System32\lsass.exe", "GrantedAccess": "0x1010"}))
    assert any(ve.SCENARIOS[6].expect in m for m in messages), messages


def test_benign_corpus_is_not_flagged_by_the_real_engine():
    # every benign command line, fed through the real rules as its own image
    engine = he.HeuristicEngine()
    for i, (name, command) in enumerate(ve.BENIGN):
        image = command[0] if os.path.isabs(command[0]) else rf"C:\Windows\System32\{command[0]}"
        pid = 900_001_000 + i
        messages = _messages_from(lambda: engine._dispatch(
            1, {"ProcessId": pid, "Image": image, "CommandLine": _command_line(command)}))
        assert not any(f"PID {pid} ->" in m for m in messages), (name, messages)


# ---- report / CLI ------------------------------------------------------------------

def test_format_report_summarises_and_failed_property():
    results = [ve.Result("a", "attack", "T1", "DETECTED", detected=True, peak_score=45, time_to_alert_s=1.2),
               ve.Result("b", "attack", "T2", "MISSED"),
               ve.Result("c", "gap", "T3", "NO RULE"),
               ve.Result("d", "benign", verdict="FALSE POSITIVE"),
               ve.Result("e", "benign", verdict="CLEAN")]
    text = ve.format_report(results)
    assert "detected 1/2 rule-backed" in text and "no rule for 1/1" in text and "false positives 1/2" in text
    assert [r.failed for r in results] == [False, True, False, True, False]
    sensor = ve.Result("s", "sensor", verdict="FAILED", checks=[{"name": "x", "passed": False}])
    assert sensor.failed and "[FAIL] x" in ve.format_report([sensor])


def test_cli_list_is_side_effect_free_and_live_runs_need_vm_flag():
    assert ve.main(["--list"]) == 0
    assert ve.main([]) == 2
    assert ve.main(["--only", "ps_encoded"]) == 2


def test_wait_polls_until_truthy_or_times_out():
    calls = iter([None, None, "yes"])
    assert ve._wait(lambda: next(calls), 5, interval=0.01)[0] == "yes"
    assert ve._wait(lambda: None, 0.05, interval=0.01)[0] is None


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for t in tests:
        t()
        print(f"  ok  {t.__name__}")
    print(f"OK ({len(tests)} checks)")
