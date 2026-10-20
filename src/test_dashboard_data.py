"""Self-check for dashboard_data.py - no HTTP server, Tk, or live processes
needed. Run: python test_dashboard_data.py"""

import json
import logging
import os
import tempfile

from dashboard_data import (
    severity_of, categorize, build_process_rows, build_static_rows,
    bucket_alerts, category_counts,
)
from heuristic_engine import HeuristicEngine


def test_severity_of():
    critical = logging.LogRecord("x", logging.WARNING, "", 0, "[CRITICAL THREAT] PID 1", None, None)
    refused = logging.LogRecord("x", logging.CRITICAL, "", 0, "[REFUSED] protected pid", None, None)
    warning = logging.LogRecord("x", logging.WARNING, "", 0, "score >= 50", None, None)
    info = logging.LogRecord("x", logging.INFO, "", 0, "static scan complete", None, None)
    plain_error = logging.LogRecord("x", logging.ERROR, "", 0, "[!] Failed to subscribe to Sysmon events: access denied", None, None)
    assert severity_of(critical) == "CRITICAL"
    assert severity_of(refused) == "CRITICAL"
    assert severity_of(warning) == "WARNING"
    assert severity_of(info) == "INFO"
    assert severity_of(plain_error) == "WARNING", "a plain operational error is not an active threat - must not show as CRITICAL"


def test_categorize_first_match_wins():
    assert categorize("60 file creates in 20s - potential mass encryption (ransomware)") == "Ransomware"
    assert categorize("Untrusted process access to LSASS - Potential credential dumping") == "Credential Access"
    assert categorize("Execution from staging directory: c:\\temp\\evil.exe") == "Execution"
    assert categorize("something with no known keywords") == "Other"


def test_categorize_ignores_lifecycle_messages_even_with_keyword_collision():
    # Regression test: a custom rule's own id/name can legitimately contain
    # a category keyword (e.g. "custom_lolbin_from_appdata_roaming"). The
    # one-time "[RULES] Loaded custom rule '<id>'..." startup announcement
    # that echoes it back is not a finding and must never be categorized as
    # one, even though the raw text contains "lolbin".
    assert categorize("[RULES] Loaded custom rule 'custom_lolbin_from_appdata_roaming' from example.yml") == "Other"
    assert categorize("[*] Starting Static Ingress Scanner...") == "Other"
    assert categorize("[!] Failed to subscribe to Sysmon events: access denied") == "Other"
    # Same class of bug, same fix: an allowlist suppression echoes the
    # *suppressed* finding's text for operator context, but nothing was
    # actually detected - must not count toward a technique's tally either.
    assert categorize("[ALLOWLIST] abc123 -> ignoring finding, hash is known-good (reason: test) | Would-be: +40 (security_svc.exe: High-risk IAT (Keylogger/Exfil pattern))") == "Other"
    # a rule actually firing (different prefix) must still be categorized normally
    assert categorize("[TELEMETRY] PID 1 -> +35 ([RULE:custom_lolbin_from_appdata_roaming] LOLBin 'x' launched)") == "Execution"


def test_categorize_telemetry_contradiction():
    msg = ("[TELEMETRY_CONTRADICTION] PID 1234: independent sensors disagree on parent "
           "process - ETW reports parent PID 1, Sysmon reports parent PID 999")
    assert categorize(msg) == "Telemetry Contradiction"
    record = logging.LogRecord("x", logging.WARNING, "", 0, msg, None, None)
    assert severity_of(record) == "WARNING"


def test_build_process_rows_sorts_and_labels():
    engine = HeuristicEngine()
    engine.process_scores = {111111: 90, 222222: 60, 333333: 10}
    rows = build_process_rows(engine)
    assert [r["pid"] for r in rows] == [111111, 222222, 333333]
    assert rows[0]["verdict"] == "CRITICAL"
    assert rows[1]["verdict"] == "SUSPICIOUS"
    assert rows[2]["verdict"] == "MONITORING"


def test_build_static_rows_recovers_filename_and_verdict():
    engine = HeuristicEngine()
    engine.static_scores = {"deadbeef": 85, "cafebabe": 20}
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump([
            {"file_name": "evil.exe", "hashes": {"sha256": "deadbeef"}},
            {"file_name": "ok.exe", "hashes": {"sha256": "cafebabe"}},
        ], f)
        path = f.name
    try:
        rows = build_static_rows(engine, path)
    finally:
        os.unlink(path)
    assert rows[0] == {"file": "evil.exe", "hash": "deadbeef", "score": 85, "verdict": "MALICIOUS"}
    assert rows[1] == {"file": "ok.exe", "hash": "cafebabe", "score": 20, "verdict": "CLEAN"}


def test_bucket_alerts_places_in_correct_minute_and_ignores_outside_window():
    now = 1_000_000.0  # arbitrary fixed epoch, minute-aligned math only
    now_minute = int(now // 60)
    alerts = [
        {"ts": now, "severity": "CRITICAL"},               # current minute
        {"ts": (now_minute - 5) * 60, "severity": "WARNING"},  # 5 minutes ago
        {"ts": (now_minute - 100) * 60, "severity": "INFO"},   # outside a 20-minute window
    ]
    result = bucket_alerts(alerts, minutes=20, now=now)
    assert len(result["labels"]) == 20
    assert result["critical"][-1] == 1
    assert result["warning"][-6] == 1
    assert sum(result["info"]) == 0


def test_category_counts_sorted_descending():
    alerts = [{"category": "A"}, {"category": "B"}, {"category": "A"}, {"category": "A"}]
    counts = category_counts(alerts)
    assert list(counts.items())[0] == ("A", 3)
    assert counts["B"] == 1


if __name__ == "__main__":
    test_severity_of()
    test_categorize_first_match_wins()
    test_categorize_telemetry_contradiction()
    test_categorize_ignores_lifecycle_messages_even_with_keyword_collision()
    test_build_process_rows_sorts_and_labels()
    test_build_static_rows_recovers_filename_and_verdict()
    test_bucket_alerts_places_in_correct_minute_and_ignores_outside_window()
    test_category_counts_sorted_descending()
    print("OK")
