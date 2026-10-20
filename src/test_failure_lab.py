"""Self-check for failure_lab.py. Runs the real scenarios (about 10 seconds),
plus mutation tests that break the product on purpose to prove the lab can
actually FAIL - a lab that can only pass proves nothing.
Run: python test_failure_lab.py"""

import json
import logging
import os
import re
import tempfile

import psutil

import failure_lab as fl
import sensor_health as sh
import telemetry_monitor


def _failed_checks(result):
    return [c.name for c in result.checks if not c.passed]


def test_every_scenario_passes_against_the_real_pipeline():
    results = fl.run_all()
    assert len(results) == len(fl.SCENARIOS) >= 8
    problems = [
        f"{r.name}: error={r.error} failed={_failed_checks(r)}" for r in results if not r.passed
    ]
    assert not problems, "\n".join(problems)


def test_scenarios_record_detection_latency_metrics():
    result = fl.run_scenario("sysmon_silence")
    assert result.passed
    latency = result.metrics["time_to_degraded_s"]
    # detection cannot be faster than the staleness threshold, and must be
    # inside the lab's documented upper bound
    assert 0 < latency <= 0.4 + fl.SLACK_SECONDS


def test_lab_reports_a_gap_without_failing_the_scenario():
    # The mechanism for documenting a weakness the lab observed but that isn't
    # (yet) expected to be fixed: reported, but never a failure.
    def _observes_a_weakness(lab):
        lab.start(sysmon=False, etw=False, source=False)
        lab.check("a passing check", True)
        lab.gap("something the lab observed that is not yet handled")

    fl.SCENARIOS["_gap_demo"] = ("scenario that documents a gap", _observes_a_weakness, {})
    try:
        result = fl.run_scenario("_gap_demo")
    finally:
        del fl.SCENARIOS["_gap_demo"]
    assert result.passed
    assert result.gaps == ["something the lab observed that is not yet handled"]
    assert "KNOWN GAP: something the lab observed" in fl.format_report([result])


def test_the_two_original_gaps_stay_closed():
    # The lab first reported these as known gaps: queue drops left blind_state
    # HEALTHY, and garbage Sysmon events kept a silent sensor "live". Both are
    # fixed and now checked (queue_flood / malformed_input) - not merely
    # documented - so neither may reappear as a gap or a failure.
    for name in ("queue_flood", "malformed_input"):
        result = fl.run_scenario(name)
        assert result.passed, f"{name}: {_failed_checks(result)}"
        assert result.gaps == [], f"{name} reports a gap again: {result.gaps}"


# ---- mutation tests: the lab must notice a broken product --------------------

def test_mutation_blind_state_stuck_healthy_is_caught():
    original = sh.compute_blind_state
    sh.compute_blind_state = lambda states, ever_seen_event: sh.BLIND_STATE_HEALTHY
    try:
        result = fl.run_scenario("sysmon_silence")
    finally:
        sh.compute_blind_state = original
    assert not result.passed
    assert "detected: blind state becomes DEGRADED" in _failed_checks(result)


def test_mutation_total_loss_logged_below_critical_is_caught():
    # regression guard for the bug the lab originally found: PARTIALLY_BLIND
    # was logged at ERROR, which the dashboard shows as only a WARNING
    original = sh._BLIND_STATE_LOG_LEVEL[sh.BLIND_STATE_PARTIALLY_BLIND]
    sh._BLIND_STATE_LOG_LEVEL[sh.BLIND_STATE_PARTIALLY_BLIND] = logging.ERROR
    try:
        result = fl.run_scenario("total_silence")
    finally:
        sh._BLIND_STATE_LOG_LEVEL[sh.BLIND_STATE_PARTIALLY_BLIND] = original
    assert not result.passed
    assert "alerted: total loss of behavioral visibility is logged at CRITICAL" in _failed_checks(result)


def test_mutation_dropped_events_ignored_by_health_is_caught():
    # regression guard for gap 1: queue overflow must degrade the health state
    original = sh.SensorHealth.record_drop
    sh.SensorHealth.record_drop = lambda self: None
    try:
        result = fl.run_scenario("queue_flood")
    finally:
        sh.SensorHealth.record_drop = original
    assert not result.passed
    assert "detected: queue overflow degrades the blind state to DEGRADED" in _failed_checks(result)


def test_mutation_unvalidated_sysmon_heartbeat_is_caught():
    # regression guard for gap 2: a heartbeat that ignores event content lets
    # garbage keep a silent Sysmon sensor "live"
    original = telemetry_monitor._EVENT_ID_RE
    telemetry_monitor._EVENT_ID_RE = re.compile("")  # matches anything, like the old content-agnostic heartbeat
    try:
        result = fl.run_scenario("malformed_input")
    finally:
        telemetry_monitor._EVENT_ID_RE = original
    assert not result.passed
    assert "integrity: malformed Sysmon events cannot keep a silent Sysmon sensor 'live'" in _failed_checks(result)


def test_mutation_sensor_heartbeat_ignored_for_ever_seen_is_caught():
    # regression guard for the second bug the lab found: an ETW-only
    # deployment's mid-run total loss was reported as CRITICALLY_BLIND
    original = sh.SensorHealth.ever_seen
    sh.SensorHealth.ever_seen = lambda self: False
    try:
        result = fl.run_scenario("etw_only_total_loss")
    finally:
        sh.SensorHealth.ever_seen = original
    assert not result.passed
    assert any("PARTIALLY_BLIND" in name for name in _failed_checks(result))


# ---- framework behaviour ---------------------------------------------------------

def test_lab_restores_global_state_after_running():
    root = logging.getLogger()
    handlers_before, level_before = root.handlers[:], root.level
    evtlog_before = telemetry_monitor.win32evtlog
    fl.run_scenario("cold_start_blind")
    assert root.handlers == handlers_before
    assert root.level == level_before
    assert telemetry_monitor.win32evtlog is evtlog_before


def test_lab_restores_global_state_even_when_a_scenario_raises():
    def _boom(lab):
        raise RuntimeError("scenario exploded")

    fl.SCENARIOS["_boom"] = ("test scenario that raises", _boom, {})
    root = logging.getLogger()
    handlers_before, level_before = root.handlers[:], root.level
    evtlog_before = telemetry_monitor.win32evtlog
    try:
        result = fl.run_scenario("_boom")
    finally:
        del fl.SCENARIOS["_boom"]
    assert not result.passed
    assert "scenario exploded" in result.error
    assert root.handlers == handlers_before and root.level == level_before
    assert telemetry_monitor.win32evtlog is evtlog_before


def test_scenario_with_no_checks_does_not_count_as_passing():
    assert not fl.ScenarioResult("x", "y").passed


def test_synthetic_pids_are_outside_the_real_process_space():
    assert not psutil.pid_exists(fl.SYNTHETIC_PID_BASE)
    assert not psutil.pid_exists(fl.SYNTHETIC_PARENT_PID)
    assert fl.SYNTHETIC_PARENT_PID < fl.SYNTHETIC_PID_BASE


def test_log_capture_matching_and_counting():
    capture = fl.LogCapture()
    logger = logging.getLogger("test_failure_lab_capture")
    logger.addHandler(capture)
    logger.setLevel(logging.INFO)
    try:
        logger.info("alpha one")
        logger.warning("alpha two")
        logger.info("beta")
    finally:
        logger.removeHandler(capture)
    assert capture.count("alpha") == 2
    _, level, message = capture.first_match("alpha two")
    assert level == logging.WARNING and message == "alpha two"
    assert capture.first_match("gamma") is None
    assert capture.count("alpha", since=1e18) == 0


def test_cli_list_and_unknown_scenario_and_json_report():
    assert fl.main(["--list"]) == 0
    assert fl.main(["definitely_not_a_scenario"]) == 2

    path = os.path.join(tempfile.gettempdir(), "failure_lab_test_report.json")
    try:
        assert fl.main(["cold_start_blind", "--json", path]) == 0
        with open(path) as f:
            report = json.load(f)
    finally:
        if os.path.exists(path):
            os.unlink(path)
    assert len(report) == 1 and report[0]["name"] == "cold_start_blind" and report[0]["passed"] is True
    assert all(c["passed"] for c in report[0]["checks"])


def test_cli_exit_status_is_nonzero_when_a_scenario_fails():
    original = sh.compute_blind_state
    sh.compute_blind_state = lambda states, ever_seen_event: sh.BLIND_STATE_HEALTHY
    try:
        assert fl.main(["cold_start_blind"]) == 1
    finally:
        sh.compute_blind_state = original


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for t in tests:
        t()
        print(f"  ok  {t.__name__}")
    print(f"OK ({len(tests)} checks)")
