"""
Live evaluation harness: run it INSIDE the VM, next to a running web_server.py.

Launches harmless emulations of attacker techniques (nothing is downloaded,
disabled, injected or encrypted - see each launch_* function), then asks the
agent's own dashboard API what it noticed. Reports, per scenario: detected or
missed, time to alert, peak score and whether the agent auto-mitigated. Also
runs a benign corpus (false-positive check) and, on request, stops Sysmon to
check that the blind state degrades and then recovers.

A scenario with no detection rule behind it is reported as "NO RULE" - a
coverage gap, not a failure - so the report doubles as an honest coverage map.

Usage (elevated PowerShell, in the VM only):
    python vm_eval.py --vm                      # attacks + benign corpus
    python vm_eval.py --vm --sensor-kill        # also stop/restart Sysmon
    python vm_eval.py --vm --json ..\\reports\\vm_eval.json
    python vm_eval.py --list                    # no side effects
Live runs need --vm because scenarios write a Run key, a scheduled task, a
service and files under Documents (all removed afterwards).
"""

import argparse
import base64
import ctypes
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
import uuid
from dataclasses import asdict, dataclass, field

import psutil

DEFAULT_URL = "http://127.0.0.1:8787"
DETECT_TIMEOUT_SECONDS = 15    # 2s fuse window + Sysmon/ETW delivery + polling
SETTLE_SECONDS = 5             # how long to wait before calling something "no alert"
PROC_TIMEOUT_SECONDS = 20      # a scenario process still alive after this is killed
SENSOR_WAIT_SECONDS = 150      # stale threshold is 60s; leave room either side
SYSTEM32 = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32")

TELEMETRY_RE = re.compile(r"PID (\d+) -> \+(\d+) \((.*)\) \| Total Score: ([\d.]+)")
MITIGATED_RES = (re.compile(r"\[CRITICAL THREAT\] PID (\d+)"),
                 re.compile(r"Successfully terminated malicious process: .*\(PID: (\d+)\)"))


# ---- agent API --------------------------------------------------------------

class Api:
    def __init__(self, url=DEFAULT_URL):
        self.url = url.rstrip("/")

    def _get(self, path):
        with urllib.request.urlopen(self.url + path, timeout=5) as resp:
            return json.load(resp)

    def summary(self):
        return self._get("/api/summary")

    def alerts(self):
        """Oldest first, so 'first match' means earliest."""
        return sorted(self._get("/api/alerts?limit=2000"), key=lambda a: a["id"])


def _last_id(api):
    return max((a["id"] for a in api.alerts()), default=0)


# ---- one launched scenario -----------------------------------------------------

class Run:
    """What a scenario launched: a unique token, every PID it (or a descendant)
    used, and the cleanups that must always happen afterwards."""

    def __init__(self):
        self.token = uuid.uuid4().hex[:8]  # lowercase hex: matches lowercased command lines
        self.pids = set()
        self.cleanups = []
        self.cleanup_errors = []

    def spawn(self, command, timeout=PROC_TIMEOUT_SECONDS):
        """Start a process and record its PID plus every descendant seen while it
        lives - a venv python or a cmd->cmd chain puts the process the agent
        actually scores one level below the one we launched."""
        proc = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL)
        self.pids.add(proc.pid)
        deadline = time.monotonic() + timeout
        while proc.poll() is None and time.monotonic() < deadline:
            try:
                self.pids.update(c.pid for c in psutil.Process(proc.pid).children(recursive=True))
            except psutil.Error:
                pass
            time.sleep(0.02)
        if proc.poll() is None:
            proc.kill()  # our own overrunning child, never anything else
        return proc.returncode

    def cleanup(self):
        for fn in reversed(self.cleanups):
            try:
                fn()
            except Exception as e:  # one failed cleanup must not stop the rest
                self.cleanup_errors.append(str(e))


# ---- scenario launchers --------------------------------------------------------

def _ps(*args):
    return ["powershell.exe", "-NoProfile", *args]


def _copy_cmd(directory, name):
    os.makedirs(directory, exist_ok=True)
    dest = os.path.join(directory, name)
    shutil.copy(os.path.join(SYSTEM32, "cmd.exe"), dest)
    return dest


def _quiet(command):
    return lambda: subprocess.run(command, capture_output=True)


def launch_ps_encoded(run):
    payload = base64.b64encode(f"Write-Output 'edr-eval-{run.token}'".encode("utf-16-le")).decode()
    run.spawn(_ps("-EncodedCommand", payload))


def launch_ps_download_cradle(run):
    # Port 9 (discard) on loopback: the connection is refused, nothing leaves the VM.
    run.spawn(_ps("-Command",
                  f"try {{ (New-Object Net.WebClient).DownloadString('http://127.0.0.1:9/{run.token}') }} "
                  f"catch {{ 'refused' }}"))


def launch_office_parent(run):
    work = os.path.join(os.environ.get("SystemDrive", "C:") + "\\", "edr_eval", run.token)
    run.cleanups.append(lambda: shutil.rmtree(work, ignore_errors=True))
    fake_word = _copy_cmd(work, "winword.exe")  # a renamed cmd.exe standing in for Office
    run.spawn(f'"{fake_word}" /c cmd.exe /c ping -n 3 127.0.0.1 >nul')


def launch_staging_dir(run):
    temp = tempfile.gettempdir()
    if "temp" not in temp.lower():
        temp = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "Temp")
    work = os.path.join(temp, f"edreval_{run.token}")
    run.cleanups.append(lambda: shutil.rmtree(work, ignore_errors=True))
    run.spawn([_copy_cmd(work, "stage.exe"), "/c", "exit", "0"])


def launch_defender_tamper(run):
    # The tamper command is only *printed*, inside single quotes; nothing changes.
    run.spawn(_ps("-Command", f"Write-Output 'Set-MpPreference -DisableRealtimeMonitoring $true {run.token}'"))


def launch_runkey(run):
    key = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
    name = f"EdrEval{run.token}"
    reg = os.path.join(SYSTEM32, "reg.exe")
    run.cleanups.append(_quiet([reg, "delete", key, "/v", name, "/f"]))
    run.spawn([reg, "add", key, "/v", name, "/t", "REG_SZ", "/d", "cmd.exe /c exit 0", "/f"])


def launch_lsass_handle(run):
    lsass = [p.pid for p in psutil.process_iter(["name"]) if (p.info["name"] or "").lower() == "lsass.exe"]
    if not lsass:
        raise RuntimeError("lsass.exe not found")
    # Opens (never reads) a handle with PROCESS_VM_READ|QUERY_INFORMATION, then closes it.
    code = ("import ctypes,time;k=ctypes.windll.kernel32;k.OpenProcess.restype=ctypes.c_void_p;"
            f"h=k.OpenProcess(0x1010,False,{lsass[0]});"
            "h and k.CloseHandle(ctypes.c_void_p(h));time.sleep(2)")
    run.spawn([sys.executable, "-c", code])


def launch_ransomware_burst(run):
    docs = os.path.join(os.path.expanduser("~"), "Documents", f"edr_eval_{run.token}")
    os.makedirs(docs, exist_ok=True)
    run.cleanups.append(lambda: shutil.rmtree(docs, ignore_errors=True))
    # 90 one-byte files from cmd.exe (not on the engine's excluded-process list) in Documents.
    run.spawn(f'cmd.exe /d /c for /L %i in (1,1,90) do @echo x>"{docs}\\f%i.txt"')


def launch_schtask(run):
    name = f"EdrEval{run.token}"
    exe = os.path.join(SYSTEM32, "schtasks.exe")
    run.cleanups.append(_quiet([exe, "/delete", "/tn", name, "/f"]))
    run.spawn([exe, "/create", "/tn", name, "/tr", "cmd.exe /c exit 0", "/sc", "once", "/st", "23:59", "/f"])


def launch_service(run):
    name = f"EdrEval{run.token}"
    exe = os.path.join(SYSTEM32, "sc.exe")
    run.cleanups.append(_quiet([exe, "delete", name]))
    run.spawn([exe, "create", name, "binPath=", os.path.join(SYSTEM32, "cmd.exe"), "start=", "demand"])


def launch_shadow_delete(run):
    # The nil GUID matches no shadow copy, so this deletes nothing.
    run.spawn([os.path.join(SYSTEM32, "vssadmin.exe"), "delete", "shadows",
               "/shadow={00000000-0000-0000-0000-000000000000}", "/quiet"])


def launch_certutil(run):
    run.spawn([os.path.join(SYSTEM32, "certutil.exe"), "-hashfile",
               os.path.join(SYSTEM32, "cmd.exe"), "SHA256"])


@dataclass
class Scenario:
    name: str
    technique: str
    expect: str        # substring of the alert message that counts as detection; None = no rule exists
    launch: object
    mitigation: bool = False  # the engine is expected to auto-mitigate (informational)


SCENARIOS = [
    Scenario("ps_encoded", "T1059.001", "Obfuscated/download-execute", launch_ps_encoded),
    Scenario("ps_download_cradle", "T1105", "Obfuscated/download-execute", launch_ps_download_cradle),
    Scenario("office_lolbin", "T1204.002", "Office app", launch_office_parent),
    Scenario("staging_exec", "T1204.002", "Execution from staging directory", launch_staging_dir),
    Scenario("defender_tamper", "T1562.001", "Attempted Defender tampering", launch_defender_tamper, True),
    Scenario("runkey_persistence", "T1547.001", "Persistence attempt in Run key", launch_runkey),
    Scenario("lsass_handle", "T1003.001", "process access to LSASS", launch_lsass_handle),
    Scenario("ransomware_burst", "T1486", "file creates/renames", launch_ransomware_burst, True),
    Scenario("schtask_persistence", "T1053.005", None, launch_schtask),
    Scenario("service_persistence", "T1543.003", None, launch_service),
    Scenario("shadow_delete", "T1490", None, launch_shadow_delete),
    Scenario("certutil_lolbin", "T1218", None, launch_certutil),
]

# Ordinary commands that must raise nothing - several deliberately contain the
# very text older rules false-positived on (grep -E, sed -e, Set-MpPreference).
BENIGN = [
    ("git_version", ["git", "--version"]),
    ("git_log_grep_tamper_text", ["git", "--no-pager", "log", "-1", "--grep=Set-MpPreference"]),
    ("python_print_grep_sed", [sys.executable, "-c", "print('grep -E foo; sed -e s/a/b/; node -e x')"]),
    ("python_print_tamper_text", [sys.executable, "-c", "print('sc stop windefend; Set-MpPreference -DisableRealtimeMonitoring')"]),
    ("python_pip_version", [sys.executable, "-m", "pip", "--version"]),
    ("powershell_get_date", _ps("-Command", "Get-Date")),
    ("powershell_list_dir", _ps("-Command", "Get-ChildItem . | Select-Object -First 3")),
    ("cmd_dir", ["cmd.exe", "/c", "dir"]),
    ("ping_loopback", ["ping.exe", "-n", "1", "127.0.0.1"]),
    ("whoami", ["whoami.exe"]),
    ("hostname", ["hostname.exe"]),
    ("ipconfig", ["ipconfig.exe"]),
    ("tasklist", ["tasklist.exe"]),
]


# ---- results ---------------------------------------------------------------------

@dataclass
class Result:
    name: str
    kind: str                    # attack | gap | benign | sensor
    technique: str = ""
    verdict: str = ""
    detected: bool = False
    peak_score: float = 0.0
    time_to_alert_s: float = None
    mitigated: bool = False
    expect_mitigation: bool = False
    detail: str = ""
    error: str = ""
    cleanup_errors: list = field(default_factory=list)
    checks: list = field(default_factory=list)   # sensor phase: [{"name", "passed"}]
    metrics: dict = field(default_factory=dict)

    @property
    def failed(self):
        return self.verdict in ("MISSED", "FALSE POSITIVE", "ERROR") or any(not c["passed"] for c in self.checks)


def evaluate(alerts, run, expect, t0):
    """Pure: which of these alerts belong to this run, and what do they say?
    An alert belongs to it when its PID is one the run used, or its text carries
    the run's unique token."""
    hits, mitigated = [], False
    for a in alerts:
        msg = a["message"]
        m = TELEMETRY_RE.search(msg)
        if m and (int(m.group(1)) in run.pids or run.token in msg.lower()):
            hits.append((a, float(m.group(4))))
        for pattern in MITIGATED_RES:
            mm = pattern.search(msg)
            if mm and int(mm.group(1)) in run.pids:
                mitigated = True
    matching = [h for h in hits if expect is None or expect in h[0]["message"]]
    return {
        "detected": bool(matching),
        "any_hit": bool(hits),
        "peak_score": max((score for _, score in hits), default=0.0),
        "time_to_alert_s": round(matching[0][0]["ts"] - t0, 2) if matching else None,
        "mitigated": mitigated,
        "detail": (matching[0][0]["message"] if matching else "")[:160],
    }


def run_attack(api, sc, timeout=DETECT_TIMEOUT_SECONDS, settle=SETTLE_SECONDS):
    res = Result(sc.name, "attack" if sc.expect else "gap", sc.technique, expect_mitigation=sc.mitigation)
    run, base, t0 = Run(), _last_id(api), time.time()
    try:
        sc.launch(run)
        deadline = time.monotonic() + (timeout if sc.expect else settle)
        while True:
            ev = evaluate([a for a in api.alerts() if a["id"] > base], run, sc.expect, t0)
            if (sc.expect and ev["detected"]) or time.monotonic() >= deadline:
                break
            time.sleep(0.5)
        if ev["detected"] and sc.mitigation and not ev["mitigated"]:
            time.sleep(2)  # the kill is logged just after the score that triggered it
            ev = evaluate([a for a in api.alerts() if a["id"] > base], run, sc.expect, t0)
        res.detected, res.peak_score = ev["detected"], ev["peak_score"]
        res.time_to_alert_s, res.mitigated, res.detail = ev["time_to_alert_s"], ev["mitigated"], ev["detail"]
        if sc.expect:
            res.verdict = "DETECTED" if ev["detected"] else "MISSED"
        else:
            res.verdict = "DETECTED*" if ev["any_hit"] else "NO RULE"
            res.detected = ev["any_hit"]
    except Exception as e:
        res.verdict, res.error = "ERROR", f"{type(e).__name__}: {e}"
    finally:
        run.cleanup()
        res.cleanup_errors = run.cleanup_errors
    return res


def run_benign(api, settle=SETTLE_SECONDS):
    launched = []
    base, t0 = _last_id(api), time.time()
    for name, command in BENIGN:
        res = Result(name, "benign")
        run = Run()
        if not shutil.which(command[0]):
            res.verdict, res.detail = "SKIPPED", f"{command[0]} not installed"
        else:
            try:
                run.spawn(command)
            except Exception as e:
                res.verdict, res.error = "ERROR", f"{type(e).__name__}: {e}"
        launched.append((res, run))
    time.sleep(settle)  # one wait for the whole corpus: alerts trail the events by a couple of seconds
    alerts = [a for a in api.alerts() if a["id"] > base]
    for res, run in launched:
        if res.verdict:
            continue
        ev = evaluate(alerts, run, None, t0)
        res.verdict = "FALSE POSITIVE" if ev["any_hit"] or ev["mitigated"] else "CLEAN"
        res.peak_score, res.mitigated, res.detail = ev["peak_score"], ev["mitigated"], ev["detail"]
    return [res for res, _ in launched]


# ---- sensor-kill phase -----------------------------------------------------------

def _wait(fn, timeout, interval=2.0):
    """Poll fn() until it returns something truthy; returns (value, seconds waited)."""
    start = time.monotonic()
    while True:
        value = fn()
        if value or time.monotonic() - start >= timeout:
            return value, round(time.monotonic() - start, 1)
        time.sleep(interval)


def sensor_kill(api):
    """Stop the Sysmon service while ETW keeps delivering, then restart it. The
    agent should notice (sensor stale -> DEGRADED, negative evidence flagged
    unreliable, a watchdog alert) and recover once Sysmon is back. A background
    loop keeps starting processes so ETW stays live and Sysmon has events to
    resume with."""
    res = Result("sensor_kill", "sensor", "T1562.001")
    sc = os.path.join(SYSTEM32, "sc.exe")
    service = next((n for n in ("Sysmon64", "Sysmon")
                    if subprocess.run([sc, "query", n], capture_output=True).returncode == 0), None)
    if not service:
        res.verdict, res.error = "ERROR", "no Sysmon/Sysmon64 service found"
        return res

    stop = threading.Event()

    def keepalive():
        while not stop.is_set():
            subprocess.run(["cmd.exe", "/c", "exit", "0"], capture_output=True)
            stop.wait(1)

    def check(name, passed):
        res.checks.append({"name": name, "passed": bool(passed)})

    base = _last_id(api)
    threading.Thread(target=keepalive, daemon=True).start()
    try:
        subprocess.run([sc, "stop", service], capture_output=True)
        summary, took = _wait(lambda: (lambda s: s if s["sysmon_state"] == "stale" else None)(api.summary()),
                              SENSOR_WAIT_SECONDS)
        res.metrics["time_to_stale_s"] = took
        check("Sysmon sensor reported stale", summary)
        summary = summary or api.summary()
        check("blind state DEGRADED (ETW still delivering)", summary["blind_state"] == "DEGRADED")
        check("negative evidence flagged unreliable, with a caveat",
              summary["negative_evidence_reliable"] is False and bool(summary["visibility_caveat"]))
        check("watchdog logged the stale sensor",
              any("sysmon sensor stale" in a["message"] for a in api.alerts() if a["id"] > base))
        res.detail = f"blind_state={summary['blind_state']} sysmon={summary['sysmon_state']} etw={summary['etw_state']}"
    finally:
        subprocess.run([sc, "start", service], capture_output=True)  # always put the sensor back
    try:
        healthy, took = _wait(lambda: api.summary()["blind_state"] == "HEALTHY", SENSOR_WAIT_SECONDS)
        res.metrics["time_to_recover_s"] = took
        check("recovered to HEALTHY after Sysmon restart", healthy)
    finally:
        stop.set()
    res.verdict = "FAILED" if any(not c["passed"] for c in res.checks) else "PASSED"
    return res


# ---- reporting / CLI --------------------------------------------------------------

def format_report(results):
    rows = [f"{'scenario':26s} {'technique':11s} {'verdict':15s} {'score':>6s} {'alert(s)':>9s}  mitigated",
            "-" * 82]
    for r in results:
        tta = "-" if r.time_to_alert_s is None else f"{r.time_to_alert_s:.1f}"
        mit = ("yes" if r.mitigated else "no") if (r.expect_mitigation or r.mitigated) else ""
        rows.append(f"{r.name:26s} {r.technique:11s} {r.verdict:15s} {r.peak_score:6.0f} {tta:>9s}  {mit}")
        for c in r.checks:
            rows.append(f"    [{'ok' if c['passed'] else 'FAIL'}] {c['name']}")
        if r.metrics:
            rows.append("    " + ", ".join(f"{k}={v}" for k, v in r.metrics.items()))
        if r.error:
            rows.append(f"    error: {r.error}")
        if r.cleanup_errors:
            rows.append(f"    CLEANUP FAILED, remove by hand: {r.cleanup_errors}")
    attacks = [r for r in results if r.kind == "attack"]
    gaps = [r for r in results if r.kind == "gap"]
    benign = [r for r in results if r.kind == "benign" and r.verdict != "SKIPPED"]
    rows += ["-" * 82,
             f"detected {sum(r.detected for r in attacks)}/{len(attacks)} rule-backed scenarios | "
             f"no rule for {sum(r.verdict == 'NO RULE' for r in gaps)}/{len(gaps)} gap scenarios | "
             f"false positives {sum(r.verdict == 'FALSE POSITIVE' for r in benign)}/{len(benign)} benign commands"]
    return "\n".join(rows)


def _is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _warm_up(api, timeout=30):
    """An idle VM starts almost no processes, which makes a healthy ETW sensor
    look stale. Start some until both sensors report live, or give up."""
    def ready():
        subprocess.run(["cmd.exe", "/c", "exit", "0"], capture_output=True)
        s = api.summary()
        return s if (s["blind_state"] == "HEALTHY" and s["sysmon_state"] == "live" and s["etw_state"] == "live") else None
    return _wait(ready, timeout, interval=2)[0]


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--vm", action="store_true", help="confirm this is a disposable VM (required for live runs)")
    p.add_argument("--url", default=DEFAULT_URL)
    p.add_argument("--only", help="comma-separated scenario names (and/or 'benign')")
    p.add_argument("--sensor-kill", action="store_true", help="also stop/restart the Sysmon service")
    p.add_argument("--json", metavar="PATH", help="write the full report as JSON")
    p.add_argument("--list", action="store_true")
    args = p.parse_args(argv)

    if args.list:
        for sc in SCENARIOS:
            print(f"{sc.name:22s} {sc.technique:11s} expects: {sc.expect or 'no rule (coverage gap)'}")
        print(f"{'benign':22s} {'-':11s} {len(BENIGN)} ordinary commands, expects: nothing")
        return 0
    if not args.vm:
        print("Refusing to run: scenarios write a Run key, scheduled task, service and files. "
              "Pass --vm to confirm this is a disposable VM.", file=sys.stderr)
        return 2
    if os.name != "nt" or not _is_admin():
        print("Run from an elevated PowerShell on Windows.", file=sys.stderr)
        return 2

    names = set(args.only.split(",")) if args.only else None
    unknown = (names or set()) - {s.name for s in SCENARIOS} - {"benign"}
    if unknown:
        print(f"Unknown scenario(s): {', '.join(sorted(unknown))}", file=sys.stderr)
        return 2

    api = Api(args.url)
    try:
        start_summary = api.summary()
    except OSError as e:
        print(f"Cannot reach the agent at {args.url} ({e}). Start web_server.py first.", file=sys.stderr)
        return 2
    if not _warm_up(api):
        print(f"Sensors are not both live and HEALTHY (blind_state={api.summary()['blind_state']}); "
              f"results would be meaningless. Fix that first.", file=sys.stderr)
        return 2

    results = []
    for sc in SCENARIOS:
        if names is None or sc.name in names:
            print(f"running {sc.name} ...", flush=True)
            results.append(run_attack(api, sc))
            time.sleep(1)
    if names is None or "benign" in names:
        print("running benign corpus ...", flush=True)
        results += run_benign(api)
    if args.sensor_kill:
        print("running sensor_kill (takes a few minutes) ...", flush=True)
        results.append(sensor_kill(api))

    print("\n" + format_report(results))
    if args.json:
        with open(args.json, "w") as f:
            json.dump({"host": socket.gethostname(), "time": time.strftime("%Y-%m-%d %H:%M:%S"),
                       "agent_at_start": start_summary, "results": [asdict(r) for r in results]}, f, indent=2)
        print(f"report written to {args.json}")
    return 1 if any(r.failed for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())
