"""
Pure, testable data-shaping for the web dashboard: turns raw log records /
engine state into the JSON shapes the frontend charts and tables expect.
No Tk, no HTTP, no live processes required to exercise this module - see
test_dashboard_data.py.
"""

import json
import logging
import time
from collections import defaultdict

import psutil

CRITICAL_THRESHOLD = 80
WARNING_THRESHOLD = 50

# Ordered (label, keywords) rules matched against a log message's text to
# bucket it into the MITRE-ish technique categories already documented in
# README's "What each detector actually catches" table. First match wins,
# so more specific labels (Ransomware) are listed before ones their
# messages could also collide with (Execution).
CATEGORY_RULES = (
    ("Telemetry Contradiction", ("telemetry_contradiction",)),
    ("Ransomware", ("ransomware", "mass encryption")),
    ("Credential Access", ("lsass", "credential")),
    ("Process Injection", ("injection", "hollowing", "module loaded from staging")),
    ("Persistence", ("run key", "persistence")),
    ("Defense Evasion", ("amsi", "etw patch", "defender tampering", "nt*/zw*", "evasion")),
    ("Masquerading", ("impersonation",)),
    ("Family Intel", ("imphash matches known family", "metamorphic clone")),
    ("Execution", ("staging directory", "lolbin", "macro dropper", "powershell", "obfuscated", "keylogger")),
)

# Prefixes for pure lifecycle/status log lines - never keyword-categorized.
# Without this, a custom rule pack's own metadata (its `id`/`name`, echoed
# back verbatim in the "[RULES] Loaded custom rule '<id>'..." startup
# announcement) can coincidentally contain a category keyword - e.g. a rule
# id containing "lolbin" made a one-time "rule loaded" log line show up as
# an "Execution" technique hit on the dashboard's chart, even though
# nothing was ever detected. A rule *firing* (logged with a different
# prefix, "[TELEMETRY]"/"[STATIC]") still gets categorized normally - only
# messages that were never a finding in the first place are exempted here.
#
# [ALLOWLIST] belongs in this set for the same underlying reason, not a new
# one: its message embeds the *suppressed* finding's own text (e.g.
# "...Would-be: +40 (... Keylogger/Exfil pattern)") purely for operator
# context, but nothing was actually detected on this system - it was
# overridden as known-good. Counting it toward a technique's tally would
# make the chart claim a live finding that a human already vetted away.
NON_FINDING_PREFIXES = ('[RULES]', '[ALLOWLIST]', '[*]', '[+]', '[-]', '[!]')


def severity_of(record: logging.LogRecord) -> str:
    """Map a stdlib log record to the CRITICAL/WARNING/INFO buckets the
    dashboard displays and charts. Only actual security-critical events
    (a mitigation threshold crossing, or a safety-floor refusal to
    mitigate a protected process) count as CRITICAL - a plain
    logging.error() (Sysmon subscribe failed, a malformed event failed to
    parse, etc.) is an operational hiccup, not an active threat, so it's
    scored as WARNING. Conflating the two would bury real detections in
    startup/plumbing noise in the dashboard's Critical tile and feed."""
    msg = record.getMessage()
    if record.levelno >= logging.CRITICAL or "[CRITICAL THREAT]" in msg or "[REFUSED]" in msg:
        return "CRITICAL"
    if record.levelno >= logging.WARNING:
        return "WARNING"
    return "INFO"


def categorize(message: str) -> str:
    if message.startswith(NON_FINDING_PREFIXES):
        return "Other"
    lower = message.lower()
    for label, keywords in CATEGORY_RULES:
        if any(k in lower for k in keywords):
            return label
    return "Other"


def build_process_rows(engine):
    """(pid, name, score, verdict) for every currently-scored PID, highest
    score first."""
    rows = []
    for pid, score in engine.process_scores.items():
        try:
            name = psutil.Process(pid).name()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            name = "(exited)"
        if score >= CRITICAL_THRESHOLD:
            verdict = "CRITICAL"
        elif score >= WARNING_THRESHOLD:
            verdict = "SUSPICIOUS"
        else:
            verdict = "MONITORING"
        rows.append({"pid": pid, "name": name, "score": round(score, 1), "verdict": verdict})
    rows.sort(key=lambda r: r["score"], reverse=True)
    return rows


def build_static_rows(engine, binaries_path):
    """(file, hash, score, verdict) for every statically-scanned sample.
    Engine only keys static_scores by hash, so filenames are recovered from
    the same binaries.json the scanner already read."""
    filenames = {}
    try:
        with open(binaries_path, 'r') as f:
            for entry in json.load(f):
                h = entry.get('hashes', {}).get('sha256')
                if h:
                    filenames[h] = entry.get('file_name', 'Unknown')
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        pass

    rows = []
    for file_hash, score in engine.static_scores.items():
        if score >= CRITICAL_THRESHOLD:
            verdict = "MALICIOUS"
        elif score >= WARNING_THRESHOLD:
            verdict = "SUSPICIOUS"
        else:
            verdict = "CLEAN"
        rows.append({
            "file": filenames.get(file_hash, file_hash[:16]),
            "hash": file_hash,
            "score": round(score, 1),
            "verdict": verdict,
        })
    rows.sort(key=lambda r: r["score"], reverse=True)
    return rows


def bucket_alerts(alerts, minutes=20, now=None):
    """Per-minute CRITICAL/WARNING/INFO counts for the trailing `minutes`
    window ending now - feeds the Falcon-style detections-over-time chart.
    `alerts` items need a `ts` (epoch seconds) and `severity` key."""
    now = time.time() if now is None else now
    now_minute = int(now // 60)
    start_minute = now_minute - (minutes - 1)

    labels = [time.strftime("%H:%M", time.localtime((start_minute + i) * 60)) for i in range(minutes)]
    series = {"critical": [0] * minutes, "warning": [0] * minutes, "info": [0] * minutes}

    for alert in alerts:
        offset = int(alert["ts"] // 60) - start_minute
        if 0 <= offset < minutes:
            key = alert["severity"].lower()
            if key in series:
                series[key][offset] += 1

    return {"labels": labels, **series}


def category_counts(alerts):
    counts = defaultdict(int)
    for alert in alerts:
        counts[alert["category"]] += 1
    return dict(sorted(counts.items(), key=lambda kv: kv[1], reverse=True))
