"""
Exhaustive self-check for heuristic_engine.py: exercises every behavioral
rule in the README's detection table, plus the safety floor (protected
processes, decay, PID-reuse guard, mitigate()). Uses the same
synthetic-Sysmon-XML technique README documents for testing a rule without
a live attack. Run: python test_heuristic_engine.py
"""

import subprocess
import sys
import time

import psutil

import heuristic_engine as he
from heuristic_engine import HeuristicEngine

NS = "http://schemas.microsoft.com/win/2004/08/events/event"


def event(event_id, **fields):
    data = "".join(f'<Data Name="{k}">{v}</Data>' for k, v in fields.items())
    return f'<Event xmlns="{NS}"><System><EventID>{event_id}</EventID></System><EventData>{data}</EventData></Event>'


def fresh_pid():
    """A PID number guaranteed not to belong to a real process, so
    _is_protected/_reset_score_if_pid_reused treat it as an ordinary,
    unprotected, non-reused process."""
    fresh_pid.counter += 1
    return 900000 + fresh_pid.counter


fresh_pid.counter = 0


# ---- EventID 1: ProcessCreate ---------------------------------------------

def test_execution_from_staging_directory():
    engine = HeuristicEngine()
    pid = fresh_pid()
    engine.evaluate_event(event(1, ProcessId=pid, Image=r"C:\Users\bob\AppData\Local\Temp\evil.exe"))
    assert engine.process_scores[pid] == 30


def test_defender_tamper_command_line():
    # +90 alone crosses the >=80 mitigation threshold in one shot, so
    # _check_threshold() calls mitigate() (a no-op against this fake PID)
    # and resets the score to 0 - that reset to 0 is the correct, designed
    # outcome for a single-event critical, not a sign scoring didn't happen.
    engine = HeuristicEngine()
    pid = fresh_pid()
    engine.evaluate_event(event(1, ProcessId=pid, Image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                                 CommandLine="Set-MpPreference -DisableRealtimeMonitoring $true"))
    assert engine.process_scores[pid] == 0


def test_powershell_obfuscation():
    engine = HeuristicEngine()
    pid = fresh_pid()
    engine.evaluate_event(event(1, ProcessId=pid, Image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                                 CommandLine="powershell -WindowStyle Hidden -EncodedCommand aQBlAHgA"))
    assert engine.process_scores[pid] == 45


_POWERSHELL_IMAGE = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
_PWSH_IMAGE = r"C:\Program Files\PowerShell\7\pwsh.exe"

# Real command lines from a live false-positive report: Claude Code's Git
# Bash wrapper (whose text contains `grep -E`, lowercased to `grep -e`) and
# the grep it spawned, plus other common tools that use a bare -e flag.
_FALSE_POSITIVE_LINES = [
    (r"C:\Program Files\Git\usr\bin\bash.exe",
     r'"C:\Program Files\Git\bin\..\usr\bin\bash.exe" -c "source /c/x.sh 2>/dev/null || true && eval '
     r"'cd \"/c/proj/src\" && python failure_lab.py 2>&1 | grep -E \"scenarios,\"' < /dev/null\""),
    (r"C:\Program Files\Git\usr\bin\grep.exe", r'"C:\Program Files\Git\usr\bin\grep.exe" -E scenarios,'),
    (r"C:\Program Files\Git\usr\bin\sed.exe", "sed -e s/a/b/ file.txt"),
    (r"C:\Program Files\nodejs\node.exe", 'node -e "console.log(1)"'),
    (r"C:\Windows\System32\notepad.exe", "notepad.exe DownloadString.txt"),
]


def _score_process_create(pid, image, command_line, **extra):
    engine = HeuristicEngine()
    engine._handle_process_create({'ProcessId': pid, 'Image': image, 'CommandLine': command_line, **extra})
    return engine.process_scores.get(pid, 0)


def test_powershell_abuse_ignores_non_powershell_processes():
    # Regression: the bare '-e ' pattern used to score every process whose
    # (lowercased) command line contained it, e.g. `grep -E`.
    for image, command_line in _FALSE_POSITIVE_LINES:
        assert _score_process_create(fresh_pid(), image, command_line) == 0, f"false positive: {command_line[:60]}"


def test_powershell_abuse_flags_every_pattern_on_a_powershell_host():
    # Scoping to PowerShell hosts must not silently drop any pattern.
    for host in (_POWERSHELL_IMAGE, _PWSH_IMAGE):
        for pattern in he.POWERSHELL_ABUSE_PATTERNS:
            score = _score_process_create(fresh_pid(), host, f"powershell {pattern}x")
            assert score == 45, f"{pattern!r} on {host} scored {score}"


def test_powershell_abuse_host_match_is_case_insensitive():
    score = _score_process_create(fresh_pid(), r"C:\WINDOWS\SYSTEM32\WINDOWSPOWERSHELL\V1.0\POWERSHELL.EXE",
                                  "POWERSHELL -ENC AQBLAHGA")
    assert score == 45


def test_powershell_abuse_flags_a_renamed_host_via_original_file_name():
    # Sysmon's OriginalFileName is the name in the PE header, so renaming
    # powershell.exe to something else doesn't hide it from this rule.
    for original in ("PowerShell.EXE", "pwsh.dll"):
        score = _score_process_create(fresh_pid(), r"C:\ProgramData\svc.exe", "svc.exe -enc aQBlAHgA",
                                      OriginalFileName=original)
        assert score == 45, original


def test_powershell_abuse_scores_the_powershell_child_not_a_cmd_wrapper():
    # cmd.exe merely *quoting* a PowerShell command line is not itself the
    # PowerShell host; the powershell.exe child gets its own event.
    line = 'cmd.exe /c "powershell -enc aQBlAHgA"'
    assert _score_process_create(fresh_pid(), r"C:\Windows\System32\cmd.exe", line) == 0
    assert _score_process_create(fresh_pid(), _POWERSHELL_IMAGE, "powershell -enc aQBlAHgA") == 45


_SYS32 = r"C:\Windows\System32"

# Tools that merely CARRY tamper text in their command line (search, commit
# message, print, open a file) - none of them executes a tamper command, and a
# match here means mitigate() kills the tool.
_TAMPER_TEXT_CARRIERS = [
    r"C:\Program Files\Git\usr\bin\bash.exe", r"C:\Program Files\Git\usr\bin\grep.exe",
    r"C:\Program Files\Git\cmd\git.exe", r"C:\Users\bob\.vscode\rg.exe",
    r"C:\Python314\python.exe", r"C:\Program Files\nodejs\node.exe",
    r"C:\Program Files\Microsoft VS Code\Code.exe", _SYS32 + r"\notepad.exe",
    r"C:\Users\bob\.local\bin\claude.exe",
    # launchers that only pass a command along: still caught via the
    # interpreter/utility process they spawn, so not flagged themselves
    _SYS32 + r"\wbem\wmic.exe", _SYS32 + r"\schtasks.exe", _SYS32 + r"\mshta.exe",
]


def _new_recording_engine():
    engine = HeuristicEngine()
    mitigated = []
    engine.mitigate = mitigated.append
    return engine, mitigated


def _tamper_mitigation_count(engine, mitigated, image, command_line, **extra):
    """How many times mitigate() was called (for this fresh PID) by one
    ProcessCreate dispatch."""
    pid = fresh_pid()
    before = len(mitigated)
    engine._handle_process_create({'ProcessId': pid, 'Image': image, 'CommandLine': command_line, **extra})
    new_calls = mitigated[before:]
    assert all(p == pid for p in new_calls), f"mitigate() called for the wrong pid: {new_calls}"
    return len(new_calls)


def test_defender_tamper_ignores_processes_that_merely_carry_the_text():
    # Regression: the rule used to inspect every process, so any tool whose
    # command line contained a tamper pattern (grep, git commit -m, python -c,
    # an editor, a `bash -c` wrapper...) scored +90 and was mitigated.
    engine, mitigated = _new_recording_engine()
    for image in _TAMPER_TEXT_CARRIERS:
        for pattern in he.DEFENDER_TAMPER_PATTERNS:
            for line in (f'grep -rn "{pattern}" src/', f'git commit -m "about {pattern}"', pattern):
                assert _tamper_mitigation_count(engine, mitigated, image, line) == 0, f"{image}: {line}"
    assert mitigated == []


def test_defender_tamper_flags_every_pattern_on_every_host():
    # The host gate must not silently drop any pattern, nor any host, and it
    # must work both by image name and by the PE header's OriginalFileName.
    engine, mitigated = _new_recording_engine()
    for host in he.DEFENDER_TAMPER_HOSTS:
        for pattern in he.DEFENDER_TAMPER_PATTERNS:
            by_image = _tamper_mitigation_count(engine, mitigated, f"{_SYS32}\\{host}", f"x {pattern} y")
            assert by_image == 1, f"{pattern!r} on image {host} mitigated {by_image}x"
            by_original = _tamper_mitigation_count(engine, mitigated, r"C:\ProgramData\renamed.exe",
                                                   f"x {pattern} y", OriginalFileName=host)
            assert by_original == 1, f"{pattern!r} with OriginalFileName {host} mitigated {by_original}x"


def test_defender_tamper_matches_the_launchers_actual_spelling():
    # Sysmon records the launcher's exact text. These are the same commands
    # as the patterns, spelled the way PowerShell/cmd/CreateProcess emit them.
    engine, mitigated = _new_recording_engine()
    cases = [
        (_SYS32 + r"\sc.exe", r'"C:\WINDOWS\system32\sc.exe" stop windefend'),
        (_SYS32 + r"\sc.exe", r'"C:\WINDOWS\system32\sc.exe" config WinDefend start= disabled'),
        (_SYS32 + r"\net.exe", r'"C:\WINDOWS\system32\net.exe" stop windefend'),
        (_SYS32 + r"\net1.exe", r"C:\Windows\system32\net1 stop windefend"),
        (_SYS32 + r"\taskkill.exe", r'"C:\WINDOWS\system32\taskkill.exe" /f /im MsMpEng.exe'),
        (_SYS32 + r"\taskkill.exe", r'"C:\WINDOWS\system32\taskkill.exe" /im MsMpEng.exe /f'),
        (_SYS32 + r"\sc.exe", "sc   stop \t windefend"),
        (_SYS32 + r"\sc.exe", 'sc "stop" windefend'),
        (_SYS32 + r"\cmd.exe", r'"C:\Windows\system32\cmd.exe" /c "net stop windefend"'),
        (_POWERSHELL_IMAGE, 'powershell.exe -NoP -Command "Set-MpPreference   -DisableRealtimeMonitoring $true"'),
        (_SYS32 + r"\reg.exe",
         r'reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f'),
    ]
    for image, line in cases:
        assert _tamper_mitigation_count(engine, mitigated, image, line) == 1, line


def test_defender_tamper_host_match_is_case_insensitive_and_path_agnostic():
    engine, mitigated = _new_recording_engine()
    for image in (r"C:\WINDOWS\SYSTEM32\SC.EXE",
                  r"\Device\HarddiskVolume3\Windows\System32\sc.exe",  # ETW-style NT path
                  r"D:\anywhere\at\all\sc.exe"):
        assert _tamper_mitigation_count(engine, mitigated, image, "SC STOP WINDEFEND") == 1, image


def test_defender_tamper_original_file_name_only_widens_inspection():
    # A binary can claim any OriginalFileName in its own version resource;
    # claiming a host name only makes us LOOK at it, and a non-tamper command
    # line still scores nothing.
    engine, mitigated = _new_recording_engine()
    assert _tamper_mitigation_count(engine, mitigated, r"C:\ProgramData\x.exe", "x.exe --version",
                                    OriginalFileName="cmd.exe") == 0
    # ...while a non-host original name never grants a pass or an inspection
    assert _tamper_mitigation_count(engine, mitigated, _SYS32 + r"\notepad.exe", "sc stop windefend",
                                    OriginalFileName="notepad.exe") == 0


def test_defender_tamper_needs_a_command_line():
    engine, mitigated = _new_recording_engine()
    for host in ("cmd.exe", "sc.exe", "powershell.exe"):
        pid = fresh_pid()
        engine._handle_process_create({'ProcessId': pid, 'Image': f"{_SYS32}\\{host}", 'CommandLine': None})
        engine._handle_process_create({'ProcessId': pid, 'Image': f"{_SYS32}\\{host}", 'CommandLine': ""})
        engine._handle_process_create({'ProcessId': pid, 'Image': f"{_SYS32}\\{host}"})
    assert mitigated == []


def test_defender_tamper_normalization_never_changes_the_logged_command_line():
    import logging

    class _Capture(logging.Handler):
        def __init__(self):
            super().__init__(logging.INFO)
            self.messages = []

        def emit(self, record):
            self.messages.append(record.getMessage())

    engine, _ = _new_recording_engine()
    root = logging.getLogger()
    original_level = root.level
    capture = _Capture()
    root.addHandler(capture)
    root.setLevel(logging.INFO)
    line = r'"C:\WINDOWS\system32\sc.exe"   stop windefend'
    try:
        engine._handle_process_create({'ProcessId': fresh_pid(), 'Image': _SYS32 + r"\sc.exe", 'CommandLine': line})
    finally:
        root.removeHandler(capture)
        root.setLevel(original_level)
    finding = [m for m in capture.messages if "Attempted Defender tampering" in m]
    assert len(finding) == 1
    assert line.lower() in finding[0], "the alert must show the original, un-normalized command line"


def test_normalize_command_line():
    assert he._normalize_command_line('"a"  b\tc\n d') == "a b c d"
    assert he._normalize_command_line("") == ""
    assert he._normalize_command_line('""') == ""
    assert he._normalize_command_line("no change here") == "no change here"
    assert he._normalize_command_line("  padded  ") == "padded"


def test_defender_tamper_still_respects_the_protected_floor():
    # The two-layer safety floor must hold for the tamper rule too: the
    # agent's own PID is never scored, so mitigate() is never reached.
    engine, mitigated = _new_recording_engine()
    pid = fresh_pid()
    engine._own_pid = pid
    engine._handle_process_create({'ProcessId': pid, 'Image': _SYS32 + r"\cmd.exe",
                                   'CommandLine': "cmd.exe /c sc stop windefend"})
    assert mitigated == [] and pid not in engine.process_scores


def test_defender_tamper_is_deduplicated_across_provisional_and_fused_dispatches():
    engine, mitigated = _new_recording_engine()
    pid = fresh_pid()
    key = (pid, 4242.0)
    image = _SYS32 + r"\sc.exe"
    engine._handle_process_create({'ProcessId': pid, 'Image': image, '_dedup_key': key})  # ETW provisional: no CommandLine
    assert mitigated == []
    fused = {'ProcessId': pid, 'Image': image, 'CommandLine': "sc stop windefend", '_dedup_key': key}
    engine._handle_process_create(fused)
    engine._handle_process_create(dict(fused))  # the same real event dispatched again
    assert mitigated == [pid], "one real event must mitigate exactly once"


def test_defender_tamper_and_powershell_abuse_both_evaluate_on_a_powershell_host():
    # +90 mitigates and resets the score to 0; the PowerShell rule then adds
    # its own +45 on top - unchanged behavior, pinned here.
    engine, mitigated = _new_recording_engine()
    pid = fresh_pid()
    engine._handle_process_create({'ProcessId': pid, 'Image': _POWERSHELL_IMAGE,
                                   'CommandLine': 'powershell -enc AQBl -c "Set-MpPreference -DisableRealtimeMonitoring 1"'})
    assert mitigated == [pid]
    assert abs(engine.process_scores[pid] - 45) < 0.01


def test_defender_tamper_wrapper_is_not_flagged_but_its_spawned_child_is():
    engine, mitigated = _new_recording_engine()
    wrapper = 'wmic process call create "powershell -c Set-MpPreference -DisableRealtimeMonitoring 1"'
    assert _tamper_mitigation_count(engine, mitigated, _SYS32 + r"\wbem\wmic.exe", wrapper) == 0
    assert _tamper_mitigation_count(engine, mitigated, _POWERSHELL_IMAGE,
                                    "powershell -c Set-MpPreference -DisableRealtimeMonitoring 1") == 1


def test_defender_tamper_tests_can_actually_fail():
    # Mutation guard: if the host gate or the normalization is removed, the
    # tests above must notice - otherwise they prove nothing.
    class _Everything:
        def __contains__(self, item):
            return True

    original_hosts, original_normalize = he.DEFENDER_TAMPER_HOSTS, he._normalize_command_line
    try:
        he.DEFENDER_TAMPER_HOSTS = _Everything()  # old behavior: inspect every process
        try:
            test_defender_tamper_ignores_processes_that_merely_carry_the_text()
            raised = False
        except AssertionError:
            raised = True
        assert raised, "removing the host gate must make the false-positive test fail"
    finally:
        he.DEFENDER_TAMPER_HOSTS = original_hosts

    try:
        he._normalize_command_line = lambda s: s  # old behavior: raw substring match
        try:
            test_defender_tamper_matches_the_launchers_actual_spelling()
            raised = False
        except AssertionError:
            raised = True
        assert raised, "removing the normalization must make the spelling test fail"
    finally:
        he._normalize_command_line = original_normalize


def test_office_macro_dropper_chain():
    engine = HeuristicEngine()
    pid = fresh_pid()
    engine.evaluate_event(event(1, ProcessId=pid, Image=r"C:\Windows\System32\cmd.exe",
                                 ParentImage=r"C:\Program Files\Microsoft Office\WINWORD.EXE", CommandLine="cmd.exe /c whoami"))
    assert engine.process_scores[pid] == 60


def test_benign_launch_scores_nothing_but_still_counts_as_seen():
    engine = HeuristicEngine()
    pid = fresh_pid()
    before = engine.total_events_seen
    engine.evaluate_event(event(1, ProcessId=pid, Image=r"C:\Windows\System32\notepad.exe", ParentImage=r"C:\Windows\explorer.exe", CommandLine="notepad.exe"))
    assert pid not in engine.process_scores
    assert engine.total_events_seen == before + 1
    assert engine.last_event_time is not None


# ---- EventID 10: ProcessAccess --------------------------------------------

def test_hollowing_untrusted_source_scores_full():
    engine = HeuristicEngine()
    pid = fresh_pid()
    engine.evaluate_event(event(10, SourceProcessId=pid, SourceImage=r"C:\Users\bob\AppData\Local\Temp\evil.exe",
                                 TargetImage=r"C:\Windows\System32\svchost.exe", GrantedAccess="0x2A"))
    assert engine.process_scores[pid] == 50


def test_hollowing_trusted_path_source_scores_reduced():
    engine = HeuristicEngine()
    pid = fresh_pid()
    engine.evaluate_event(event(10, SourceProcessId=pid, SourceImage=r"C:\Windows\System32\wbem\WmiPrvSE.exe",
                                 TargetImage=r"C:\Windows\System32\svchost.exe", GrantedAccess="0x2A"))
    assert engine.process_scores[pid] == 15


def test_hollowing_ignores_query_only_access():
    # Regression test for the exact false positive documented in
    # heuristic_engine.py: PROCESS_QUERY_LIMITED_INFORMATION (0x1000) alone
    # is not evidence of hollowing and must not score.
    engine = HeuristicEngine()
    pid = fresh_pid()
    engine.evaluate_event(event(10, SourceProcessId=pid, SourceImage=r"C:\Windows\System32\wbem\WmiPrvSE.exe",
                                 TargetImage=r"C:\Windows\System32\svchost.exe", GrantedAccess="0x1000"))
    assert pid not in engine.process_scores


def test_lsass_untrusted_source_scores_full():
    engine = HeuristicEngine()
    pid = fresh_pid()
    engine.evaluate_event(event(10, SourceProcessId=pid, SourceImage=r"C:\Users\bob\AppData\Local\Temp\mimikatz.exe",
                                 TargetImage=r"C:\Windows\System32\lsass.exe", GrantedAccess="0x1010"))
    assert engine.process_scores[pid] == 70


def test_lsass_trusted_path_source_scores_reduced():
    engine = HeuristicEngine()
    pid = fresh_pid()
    engine.evaluate_event(event(10, SourceProcessId=pid, SourceImage=r"C:\Windows\System32\taskmgr.exe",
                                 TargetImage=r"C:\Windows\System32\lsass.exe", GrantedAccess="0x1010"))
    assert engine.process_scores[pid] == 30


def test_lsass_ignores_query_only_access():
    engine = HeuristicEngine()
    pid = fresh_pid()
    engine.evaluate_event(event(10, SourceProcessId=pid, SourceImage=r"C:\Users\bob\AppData\Local\Temp\tool.exe",
                                 TargetImage=r"C:\Windows\System32\lsass.exe", GrantedAccess="0x1000"))
    assert pid not in engine.process_scores


# ---- EventID 11: FileCreate (ransomware burst) ----------------------------

def test_ransomware_burst_fires_at_threshold():
    # +80 also crosses the mitigation threshold in one shot - see the
    # comment in test_defender_tamper_command_line about the reset to 0.
    engine = HeuristicEngine()
    pid = fresh_pid()
    for i in range(he.RANSOMWARE_FILE_EVENT_THRESHOLD):
        engine.evaluate_event(event(11, ProcessId=pid, Image=r"C:\Users\bob\ransom.exe",
                                     TargetFilename=fr"C:\Users\bob\Documents\file{i}.locked"))
    assert engine.process_scores[pid] == 0


def test_ransomware_burst_ignores_excluded_dev_tools():
    engine = HeuristicEngine()
    pid = fresh_pid()
    for i in range(he.RANSOMWARE_FILE_EVENT_THRESHOLD):
        engine.evaluate_event(event(11, ProcessId=pid, Image=r"C:\Program Files\Microsoft VS Code\Code.exe",
                                     TargetFilename=fr"C:\Users\bob\Documents\file{i}.txt"))
    assert pid not in engine.process_scores, "VS Code indexing Documents must never look like ransomware"


def test_ransomware_burst_ignores_files_outside_monitored_dirs():
    engine = HeuristicEngine()
    pid = fresh_pid()
    for i in range(he.RANSOMWARE_FILE_EVENT_THRESHOLD):
        engine.evaluate_event(event(11, ProcessId=pid, Image=r"C:\Users\bob\tool.exe",
                                     TargetFilename=fr"C:\mal_project\.venv\Lib\file{i}.pyc"))
    assert pid not in engine.process_scores


# ---- EventID 13: RegistryEvent (persistence) ------------------------------

def test_run_key_persistence():
    engine = HeuristicEngine()
    pid = fresh_pid()
    engine.evaluate_event(event(13, ProcessId=pid, TargetObject=r"HKU\S-1-5-21\Software\Microsoft\Windows\CurrentVersion\Run\Updater"))
    assert engine.process_scores[pid] == 40


# ---- Safety floor: protected processes ------------------------------------

def test_protected_pid_never_scored():
    engine = HeuristicEngine()
    engine._add_score(4, 1000, "should be ignored")  # PID 4 = System
    assert 4 not in engine.process_scores


def test_protected_process_name_never_scored():
    engine = HeuristicEngine()
    pid = fresh_pid()
    original = he.psutil.Process
    he.psutil.Process = lambda p: type("F", (), {"name": lambda self: "csrss.exe"})()
    try:
        engine._add_score(pid, 1000, "should be ignored")
    finally:
        he.psutil.Process = original
    assert pid not in engine.process_scores


def test_own_pid_never_scored():
    engine = HeuristicEngine()
    engine._add_score(engine._own_pid, 1000, "should be ignored")
    assert engine._own_pid not in engine.process_scores


# ---- Score decay + PID-reuse guard ----------------------------------------

def test_score_decays_over_time():
    engine = HeuristicEngine()
    pid = fresh_pid()
    engine._add_score(pid, 60, "initial")
    assert engine.process_scores[pid] == 60
    # Simulate 30 elapsed seconds without touching the monotonic clock.
    engine._last_score_time[pid] -= 30
    engine._apply_decay(pid)
    expected = 60 - 30 * he.SCORE_DECAY_PER_SECOND
    assert abs(engine.process_scores[pid] - expected) < 0.01


def test_pid_reuse_discards_old_score():
    engine = HeuristicEngine()
    pid = fresh_pid()
    original = he.psutil.Process
    try:
        he.psutil.Process = lambda p: type("F", (), {"create_time": lambda self: 100.0, "name": lambda self: "old.exe"})()
        engine._add_score(pid, 50, "first process")
        assert engine.process_scores[pid] == 50

        he.psutil.Process = lambda p: type("F", (), {"create_time": lambda self: 200.0, "name": lambda self: "new.exe"})()
        engine._add_score(pid, 10, "different process, same PID")
        assert engine.process_scores[pid] == 10, "a PID reused by a new OS process must not inherit the old score"
    finally:
        he.psutil.Process = original


# ---- Threshold -> mitigate() wiring, and mitigate() itself ----------------

def test_threshold_crossing_calls_mitigate_and_resets():
    engine = HeuristicEngine()
    pid = fresh_pid()  # doesn't correspond to a real process
    engine._add_score(pid, 85, "over the mitigation threshold")
    assert engine.process_scores[pid] == 0, "mitigate() should reset the score even though the fake PID can't really be killed"


def test_mitigate_refuses_protected_pid():
    engine = HeuristicEngine()
    engine.mitigate(4)  # must not raise, must not touch anything


def test_mitigate_refuses_protected_name():
    engine = HeuristicEngine()
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    try:
        original = he.psutil.Process
        he.psutil.Process = lambda p: type("F", (), {"name": lambda self: "csrss.exe"})()
        try:
            engine.mitigate(proc.pid)
        finally:
            he.psutil.Process = original
        assert psutil.pid_exists(proc.pid), "a process merely reported as csrss.exe must never actually be touched"
    finally:
        proc.terminate()
        proc.wait(timeout=5)


def test_mitigate_actually_terminates_a_real_disposable_process():
    engine = HeuristicEngine()
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    time.sleep(0.3)
    engine.mitigate(proc.pid)
    proc.wait(timeout=5)
    assert not psutil.pid_exists(proc.pid)


# ---- known-good hash allowlist ---------------------------------------------

def test_allowlisted_hash_suppresses_static_score():
    engine = HeuristicEngine(known_good_hashes={"deadbeef": {"reason": "verified vendor installer"}})
    engine.add_static_score("deadbeef", 90, "should be ignored")
    assert "deadbeef" not in engine.static_scores


def test_non_allowlisted_hash_scores_normally():
    engine = HeuristicEngine(known_good_hashes={"deadbeef": {"reason": "test"}})
    engine.add_static_score("cafebabe", 40, "unrelated finding")
    assert engine.static_scores["cafebabe"] == 40


def test_allowlist_suppresses_across_multiple_findings_for_the_same_hash():
    # The allowlist check lives in add_static_score() itself, so it must
    # suppress every call for that hash, not just the first.
    engine = HeuristicEngine(known_good_hashes={"deadbeef": {"reason": "test"}})
    engine.add_static_score("deadbeef", 30, "finding one")
    engine.add_static_score("deadbeef", 40, "finding two")
    engine.add_static_score("deadbeef", 50, "finding three")
    assert "deadbeef" not in engine.static_scores


def test_is_allowlisted_helper():
    engine = HeuristicEngine(known_good_hashes={"deadbeef": {"reason": "test"}})
    assert engine.is_allowlisted("deadbeef") is True
    assert engine.is_allowlisted("cafebabe") is False


def test_default_engine_has_no_allowlist_entries():
    # data/known_good_hashes.json won't exist in a normal checkout/test run
    # - the loader must fail open to an empty allowlist, not crash and not
    # suppress everything.
    engine = HeuristicEngine()
    assert engine.known_good_hashes == {}
    engine.add_static_score("anyhash", 30, "must still score normally")
    assert engine.static_scores["anyhash"] == 30


def test_load_known_good_hashes_missing_file_returns_empty():
    import os
    import tempfile
    missing_path = os.path.join(tempfile.gettempdir(), "definitely_does_not_exist_xyz.json")
    assert he._load_known_good_hashes(missing_path) == {}


def test_load_known_good_hashes_malformed_file_returns_empty():
    import tempfile
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        f.write("{not valid json")
        path = f.name
    try:
        assert he._load_known_good_hashes(path) == {}
    finally:
        import os
        os.unlink(path)


# ---- evaluate_etw_process_start (ETW Kernel-Process sensor) ---------------

def test_etw_process_start_scores_staging_dir_rule():
    engine = HeuristicEngine()
    pid = fresh_pid()
    engine.evaluate_etw_process_start(pid, parent_pid=1, image_name=r"C:\Users\bob\AppData\Local\Temp\evil.exe")
    assert engine.process_scores[pid] == 30


def test_etw_process_start_counts_toward_heartbeat():
    engine = HeuristicEngine()
    before = engine.total_events_seen
    engine.evaluate_etw_process_start(fresh_pid(), parent_pid=1, image_name=r"C:\Windows\System32\notepad.exe")
    assert engine.total_events_seen == before + 1
    assert engine.last_event_time is not None


def test_etw_process_start_respects_protected_floor():
    engine = HeuristicEngine()
    engine.evaluate_etw_process_start(4, parent_pid=1, image_name=r"C:\Users\bob\AppData\Local\Temp\evil.exe")
    assert 4 not in engine.process_scores


def test_etw_process_start_tags_source():
    # _dispatch's on_event hook is how Process Explorer would see this -
    # confirm the '_source' tag a dashboard needs is actually present.
    seen = []
    engine = HeuristicEngine()
    engine.on_event = lambda event_id, data: seen.append(data)
    engine.evaluate_etw_process_start(fresh_pid(), parent_pid=1, image_name=r"C:\Windows\System32\notepad.exe")
    assert len(seen) == 1
    assert seen[0]['_source'] == 'etw'


def test_etw_process_start_cannot_fire_command_line_dependent_rules():
    # The real, permanent capability gap versus Sysmon: raw kernel
    # ProcessStart has no CommandLine, so a command-line rule structurally
    # cannot match - this is the documented boundary, verified as a test,
    # not just a comment.
    engine = HeuristicEngine()
    pid = fresh_pid()
    engine.evaluate_etw_process_start(
        pid, parent_pid=1,
        image_name=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    )
    assert pid not in engine.process_scores, "no CommandLine was ever supplied, so Defender-tamper/PowerShell-abuse cannot fire"


def test_evaluate_etw_process_start_never_raises_on_bad_input():
    engine = HeuristicEngine()
    engine.evaluate_etw_process_start(None, parent_pid=None, image_name=None)  # must not raise


# ---- _dispatch regression: evaluate_event behavior is unchanged -----------

def test_dispatch_extraction_preserves_evaluate_event_behavior():
    # Same scenario as test_execution_from_staging_directory, run through
    # the real XML entry point - proves the _dispatch extraction didn't
    # change evaluate_event()'s observable behavior.
    engine = HeuristicEngine()
    pid = fresh_pid()
    engine.evaluate_event(event(1, ProcessId=pid, Image=r"C:\Users\bob\AppData\Local\Temp\evil.exe"))
    assert engine.process_scores[pid] == 30


def test_dispatch_extraction_preserves_heartbeat_even_without_event_data():
    # Original evaluate_event() increments the heartbeat as soon as
    # EventID parses, *before* checking whether EventData exists - this
    # locks that exact ordering in so a future refactor can't silently
    # move the heartbeat "inside" _dispatch and stop counting this case.
    engine = HeuristicEngine()
    before = engine.total_events_seen
    xml = f'<Event xmlns="{NS}"><System><EventID>1</EventID></System></Event>'  # no EventData at all
    engine.evaluate_event(xml)
    assert engine.total_events_seen == before + 1


# ---- dedup guard (_score_once) --------------------------------------------

def test_score_once_with_no_dedup_key_behaves_exactly_like_add_score():
    engine = HeuristicEngine()
    pid = fresh_pid()
    scored = engine._score_once(None, 'some_check', pid, 25, 'test')
    assert scored is True
    assert engine.process_scores[pid] == 25


def test_score_once_deduplicates_same_check_and_key():
    engine = HeuristicEngine()
    pid = fresh_pid()
    key = (pid, 12345.6)
    first = engine._score_once(key, 'staging_dir', pid, 30, 'first dispatch')
    second = engine._score_once(key, 'staging_dir', pid, 30, 'second dispatch of the same event')
    assert first is True
    assert second is False
    assert engine.process_scores[pid] == 30, "the duplicate must not add another 30"


def test_score_once_allows_a_different_check_under_the_same_key():
    # This is the actual point of keying by (dedup_key, check_id) rather
    # than dedup_key alone: the fused dispatch's NEW command-line-dependent
    # finding must still score even though the provisional dispatch already
    # scored a different (path-based) check under the same key. Scores
    # are chosen to stay under the critical threshold so this test isn't
    # confounded by mitigate()'s reset-to-0 (see test_handle_process_create_dedup_end_to_end
    # for a case that deliberately crosses it).
    engine = HeuristicEngine()
    pid = fresh_pid()
    key = (pid, 12345.6)
    engine._score_once(key, 'staging_dir', pid, 30, 'provisional: path-based')
    scored = engine._score_once(key, 'powershell_abuse', pid, 45, 'fused: command-line-based')
    assert scored is True
    assert abs(engine.process_scores[pid] - 75) < 0.01, "decay between back-to-back calls is expected to shave a negligible fraction"


def test_score_once_different_keys_are_independent():
    engine = HeuristicEngine()
    pid = fresh_pid()
    engine._score_once((pid, 1.0), 'staging_dir', pid, 30, 'event A')
    scored = engine._score_once((pid, 2.0), 'staging_dir', pid, 30, 'event B - different create_time, different real event')
    assert scored is True
    assert abs(engine.process_scores[pid] - 60) < 0.01


def test_handle_process_create_dedup_end_to_end():
    # Simulates the correlator's provisional-then-fused pair for the same
    # real event via the actual _handle_process_create path, not just
    # _score_once directly.
    engine = HeuristicEngine()
    pid = fresh_pid()
    dedup_key = (pid, 999.9)
    # A PowerShell host running from a staging dir: staging_dir needs the
    # path, powershell_abuse needs a PowerShell image (see POWERSHELL_HOSTS).
    image = r'C:\Users\bob\AppData\Local\Temp\powershell.exe'
    provisional = {'ProcessId': pid, 'Image': image, '_dedup_key': dedup_key}
    fused = {'ProcessId': pid, 'Image': image,
             'CommandLine': 'powershell -enc aGVsbG8=', '_dedup_key': dedup_key}
    engine._handle_process_create(provisional)
    engine._handle_process_create(fused)
    # staging_dir (30) once + powershell_abuse (45) once = 75, NOT 30+30+45
    assert abs(engine.process_scores[pid] - 75) < 0.01


# ---- Score Breakdown: attribution of every point ---------------------------

def test_score_breakdown_attributes_components():
    engine = HeuristicEngine()
    pid = fresh_pid()
    # Two distinct checks on one PID (no dedup key: plain dispatches).
    # Image names are kept basename-portable ('powershell.exe' has no path)
    # so the rule's host-name match works on both Windows and POSIX test
    # hosts - the point here is breakdown attribution, not path matching.
    engine._handle_process_create({'ProcessId': pid, 'Image': r'C:\Temp\evil.exe'})
    engine._handle_process_create({'ProcessId': pid, 'Image': 'powershell.exe',
                                   'CommandLine': 'powershell -enc aGk='})
    breakdown = engine.score_breakdown(pid)
    assert breakdown is not None
    by_id = {c['check_id']: c for c in breakdown['components']}
    assert by_id['staging_dir']['points'] == 30
    assert by_id['powershell_abuse']['points'] == 45
    # Live total = sum of the raw contributions on a fresh engine (no decay
    # has elapsed yet), and the shares must sum to ~100%.
    assert abs(breakdown['total'] - 75) < 0.01
    assert abs(sum(c['share'] for c in breakdown['components']) - 100.0) < 0.1
    assert breakdown['raw_sum'] == 75
    # Every component carries its most recent reason text.
    assert 'staging directory' in by_id['staging_dir']['context']
    assert breakdown['activity_span_seconds'] is not None


def test_score_breakdown_repeated_hits_accumulate_points_and_hits():
    engine = HeuristicEngine()
    pid = fresh_pid()
    engine._add_score(pid, 10, 'benign-ish repeated signal', check_id='repeat_probe')
    engine._add_score(pid, 10, 'benign-ish repeated signal', check_id='repeat_probe')
    engine._add_score(pid, 10, 'benign-ish repeated signal', check_id='repeat_probe')
    breakdown = engine.score_breakdown(pid)
    (component,) = breakdown['components']
    assert component['points'] == 30  # merged, not three rows
    assert component['hits'] == 3


def test_score_breakdown_unknown_pid_returns_none():
    engine = HeuristicEngine()
    assert engine.score_breakdown(fresh_pid()) is None


def test_score_breakdown_survives_total_decay():
    # Components are HISTORY: even after the live score decays to ~0, the
    # breakdown still explains where the points came from - that is the
    # 'analysts never see an unexplained number' contract.
    engine = HeuristicEngine(config={'thresholds': {'warning': 10 ** 9, 'critical': 10 ** 9},
                                     'decay_points_per_second': 1000.0,
                                     'ransomware': {'file_event_window_seconds': 20, 'file_event_threshold': 60},
                                     'correlator': {'fuse_window_seconds': 2.0},
                                     'self_test': {'interval_seconds': 300, 'timeout_seconds': 15}})
    pid = fresh_pid()
    engine._add_score(pid, 30, 'staging dir', check_id='staging_dir')
    time.sleep(0.02)  # let the aggressive decay window elapse
    # Decay is LAZY in this engine - it is applied on the next scoring
    # event for the PID, not by a background timer (see _apply_decay's
    # docstring). Trigger the real decay path the way a real event would.
    engine._apply_decay(pid)
    breakdown = engine.score_breakdown(pid)
    assert breakdown['total'] < 30  # decayed
    assert breakdown['components'][0]['points'] == 30  # history intact
    assert breakdown['components'][0]['check_id'] == 'staging_dir'


def test_components_cleared_on_pid_reuse():
    engine = HeuristicEngine()
    pid = fresh_pid()
    engine._add_score(pid, 30, 'staging dir', check_id='staging_dir')
    # Simulate the OS handing this PID to a different process.
    real_create = psutil.Process
    class _NewProc:
        @staticmethod
        def create_time():
            return 1.5
    psutil.Process = lambda p: _NewProc()
    try:
        engine._pid_start_times[pid] = 0.0  # different start time -> reuse
        engine._reset_score_if_pid_reused(pid)
        assert pid not in engine.score_components
        assert pid not in engine.score_first_seen
    finally:
        psutil.Process = real_create


def test_components_cleared_after_mitigation_snapshot_survives():
    engine = HeuristicEngine()
    pid = fresh_pid()
    engine._add_score(pid, 90, 'Defender tampering', check_id='defender_tamper')
    # +90 crossed critical: snapshot taken, mitigation no-ops on the fake
    # PID, live state cleared, forensic evidence retained.
    assert pid in engine.forensic_snapshots
    snapshot = engine.forensic_snapshots[pid]
    assert snapshot['trigger'] == 'critical_threshold'
    assert snapshot['score_at_capture'] == 90
    assert snapshot['components_at_capture'][0]['check_id'] == 'defender_tamper'
    assert pid not in engine.score_components


# ---- Memory Ancestry Graph: detection-time forensic snapshots --------------

def _fake_ancestry(pid):
    return {
        'pid': pid,
        'nodes': [
            {'pid': 1, 'ppid': None, 'image': r'C:\Windows\explorer.exe', 'command_line': None,
             'user': None, 'spawn_time': None, 'first_seen': 1.0, 'alive': True,
             'env_vars': None, 'env_note': None},
            {'pid': pid, 'ppid': 1, 'image': r'C:\Temp\evil.exe', 'command_line': 'evil.exe',
             'user': 'bob', 'spawn_time': None, 'first_seen': 2.0, 'alive': True,
             'env_vars': {'PATH': 'x'}, 'env_note': None},
        ],
        'edges': [{'from': 1, 'to': pid, 'label': 'EXEC'}],
        'incomplete': False,
    }


def test_forensic_snapshot_captured_at_warning_threshold():
    engine = HeuristicEngine(config={'thresholds': {'warning': 25, 'critical': 80},
                                     'decay_points_per_second': 0.0,
                                     'ransomware': {'file_event_window_seconds': 20, 'file_event_threshold': 60},
                                     'correlator': {'fuse_window_seconds': 2.0},
                                     'self_test': {'interval_seconds': 300, 'timeout_seconds': 15}})
    engine.ancestry_provider = _fake_ancestry
    pid = fresh_pid()
    engine._add_score(pid, 30, 'staging dir exec', check_id='staging_dir')
    snapshot = engine.forensic_snapshots[pid]
    assert snapshot['trigger'] == 'warning_threshold'
    assert snapshot['ancestry']['nodes'][0]['image'] == r'C:\Windows\explorer.exe'
    assert snapshot['chain_summary'] == 'explorer.exe -> evil.exe'
    assert snapshot['ancestry_note'] is None
    assert snapshot['activity_span_seconds'] is not None


def test_forensic_snapshot_first_wins_not_overwritten_on_escalation():
    engine = HeuristicEngine()
    engine.ancestry_provider = _fake_ancestry
    pid = fresh_pid()
    # 30 (below warning) + 30 again (same check, fresh dispatch) crosses
    # the warning tier -> first snapshot; then +90 crosses critical.
    engine._add_score(pid, 30, 'staging dir exec', check_id='staging_dir_a')
    engine._add_score(pid, 30, 'staging dir exec 2', check_id='staging_dir_b')   # warning @ 60
    engine._add_score(pid, 90, 'Defender tampering', check_id='defender_tamper')  # critical @ 150
    # The escalation must NOT have replaced the evidence: one snapshot per
    # PID, the first capture wins.
    assert engine.forensic_snapshots[pid]['trigger'] == 'warning_threshold'
    assert engine.forensic_snapshots[pid]['score_at_capture'] == 60


def test_mitigate_captures_snapshot_when_none_exists():
    engine = HeuristicEngine()
    engine.ancestry_provider = _fake_ancestry
    pid = fresh_pid()
    engine.mitigate(pid)  # direct dashboard-style request, no prior score
    assert engine.forensic_snapshots[pid]['trigger'] == 'mitigation_requested'


def test_forensic_snapshot_without_provider_degrades_honestly():
    engine = HeuristicEngine()
    pid = fresh_pid()
    engine._add_score(pid, 90, 'tamper', check_id='defender_tamper')
    snapshot = engine.forensic_snapshots[pid]
    assert snapshot['ancestry'] is None
    assert 'no lineage tracker' in snapshot['ancestry_note']


def test_forensic_snapshot_provider_failure_degrades_not_raises():
    engine = HeuristicEngine()
    def _boom(pid):
        raise RuntimeError('tracker exploded')
    engine.ancestry_provider = _boom
    pid = fresh_pid()
    engine._add_score(pid, 90, 'tamper', check_id='defender_tamper')  # must not raise
    snapshot = engine.forensic_snapshots[pid]
    assert snapshot['ancestry'] is None
    assert 'failed' in snapshot['ancestry_note']


def test_process_access_edge_labels_the_snapshot():
    # The Windows analog of the MMAP(RWX) edge: an untrusted process
    # opening LSASS with dangerous rights records an access edge, and the
    # actor's forensic snapshot carries it as trigger_edge.
    engine = HeuristicEngine()
    engine.ancestry_provider = _fake_ancestry
    actor = fresh_pid()
    engine._handle_process_access({
        'SourceProcessId': actor, 'SourceImage': r'C:\Temp\mimikatz.exe',
        'TargetProcessId': 700, 'TargetImage': 'c:\\windows\\system32\\lsass.exe',
        'GrantedAccess': '0x143A',
    })
    assert actor in engine.forensic_snapshots  # +70 crosses warning(50)
    edge = engine.forensic_snapshots[actor]['trigger_edge']
    # The handler lowercases GrantedAccess with the rest of the event
    # fields (same normalization every rule matches against), so the edge
    # label carries the lowercased mask - identical text to what the
    # finding's context string shows the analyst.
    assert edge['label'] == 'OpenProcess(0x143a)'
    assert edge['to'] == 700
    # And the breakdown panel attributes the points to the right check.
    by_id = {c['check_id']: c for c in engine.score_breakdown(actor)['components']}
    assert by_id['lsass_access']['points'] == 70


def test_component_store_is_bounded():
    engine = HeuristicEngine()
    pid = fresh_pid()
    for i in range(he.MAX_COMPONENTS_PER_PID + 10):
        engine._add_score(pid, 0.1, f'check {i}', check_id=f'check_{i}')
    assert len(engine.score_components[pid]) <= he.MAX_COMPONENTS_PER_PID


def test_static_breakdown_attributes_checks():
    engine = HeuristicEngine()
    engine.add_static_score('a' * 64, 30, 'RWX section', check_id='rwx_section')
    engine.add_static_score('a' * 64, 45, 'AMSI bypass', check_id='amsi_bypass_iat')
    breakdown = engine.static_breakdown('a' * 64)
    by_id = {c['check_id']: c for c in breakdown['components']}
    assert by_id['rwx_section']['points'] == 30
    assert by_id['amsi_bypass_iat']['points'] == 45
    assert abs(breakdown['total'] - 75) < 0.01
    assert abs(sum(c['share'] for c in breakdown['components']) - 100.0) < 0.1
    assert engine.static_breakdown('b' * 64) is None


if __name__ == "__main__":
    tests = [v for k, v in list(globals().items()) if k.startswith("test_") and callable(v)]
    for t in tests:
        t()
        print(f"  ok  {t.__name__}")
    print(f"OK ({len(tests)} checks)")
