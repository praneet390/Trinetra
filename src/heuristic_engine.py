import os
import json
import time
import psutil
import logging
from collections import defaultdict, OrderedDict

from detection_config import load_config

# Known-good SHA-256 -> {"reason": ..., "source": ..., "added": ...}, checked
# in add_static_score() before any static finding (hardcoded rule, imphash
# match, or custom rule_engine.py hit) is allowed to accumulate score.
# Mirrors ClamAV's .fp/.sfp false-positive-suppression hash database:
# a human-vetted, unconditional override sitting in front of detection,
# not another rule competing for weight inside it. Absent by default, same
# as data/known_imphashes.json - deleting/never creating this file changes
# nothing.
DEFAULT_KNOWN_GOOD_HASHES_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'known_good_hashes.json')


def _load_known_good_hashes(path):
    try:
        with open(path, 'r') as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {}

# Commands/args consistent with an attacker (or malware with local admin)
# disabling Windows Defender out-of-band. Found necessary because a live
# audit of this host showed Tamper Protection is OFF - nothing in Defender
# itself alerts when its own protections get turned off, so this compensates
# for that gap independently of the AV.
DEFENDER_TAMPER_PATTERNS = (
    'set-mppreference', 'disablerealtimemonitoring', 'disableantispyware',
    'disableantivirus', 'disablebehaviormonitoring', 'disableioavprotection',
    'add-mppreference -exclusionpath', 'remove-mppreference',
    'sc stop windefend', 'sc.exe stop windefend', 'sc config windefend', 'sc.exe config windefend',
    'net stop windefend', 'net.exe stop windefend', 'net1 stop windefend', 'net1.exe stop windefend',
    'taskkill /im msmpeng.exe', 'taskkill /f /im msmpeng.exe',
    'taskkill.exe /im msmpeng.exe', 'taskkill.exe /f /im msmpeng.exe',
)


def _normalize_command_line(command_line):
    """Drop double quotes and collapse whitespace, so the same command matches
    however its launcher spelled it. Sysmon records the launcher's exact text:
    `sc stop windefend` typed at a prompt but `"C:\\WINDOWS\\system32\\sc.exe" stop
    windefend` when PowerShell launches it - the quote after `sc.exe` defeated
    the substring patterns above. Used only for pattern matching, never logged."""
    return ' '.join(command_line.replace('"', ' ').split())

# Classic PowerShell/LOLBin obfuscation and download-execute markers - the
# post-exploitation technique ASR rules would normally block, compensating
# for the fact that this host has zero ASR rules configured.
POWERSHELL_ABUSE_PATTERNS = (
    '-enc ', '-encodedcommand', '-e ', 'frombase64string', 'downloadstring',
    'downloadfile', 'iex(', 'invoke-expression', '-windowstyle hidden',
    '-w hidden', '-executionpolicy bypass', '-ep bypass', '-noprofile -nop',
)

# The patterns above are PowerShell syntax, so they are only evidence on a
# PowerShell host's own command line. Matched against every process they
# false-positived on unrelated tools - the bare '-e ' (PowerShell's
# -EncodedCommand shorthand) hit any lowercased `grep -E`, `sed -e`,
# `node -e`, and any wrapper (e.g. `bash -c "... grep -E ..."`) whose command
# line merely contained one of these words. rules/sigma.yml already scopes
# the same detection to powershell.exe/pwsh.exe; the engine now matches it.
# Compared against both the image name and Sysmon's OriginalFileName (the
# name baked into the PE header), so a renamed copy of powershell.exe still
# counts; 'pwsh.dll' is what PowerShell 7's pwsh.exe reports there.
POWERSHELL_HOSTS = ('powershell.exe', 'pwsh.exe', 'pwsh.dll', 'powershell_ise.exe')

# The Defender-tamper patterns are only evidence on the command line of a
# process that *executes* such a command: an interpreter (PowerShell, cmd) or
# the utility the pattern names (sc, net/net1, taskkill, reg). Matched against
# every process this rule was the one way the engine could kill an innocent
# tool - a single +90 hit crosses the 80 mitigation threshold on its own - and
# it did for anything whose command line merely *contained* the text: `grep`,
# `git commit -m`, `python -c`, an editor, a `bash -c` wrapper. Launchers that
# only pass a command along (wmic, schtasks, mshta, python...) are still caught
# through the interpreter/utility process they spawn. Same image-or-
# OriginalFileName matching as POWERSHELL_HOSTS, so a renamed copy still counts.
DEFENDER_TAMPER_HOSTS = POWERSHELL_HOSTS + (
    'cmd.exe', 'sc.exe', 'net.exe', 'net1.exe', 'taskkill.exe', 'reg.exe',
)

# Office apps spawning a shell/scripting interpreter is the classic
# macro-dropper chain - exactly what an ASR "Block Office applications
# from creating child processes" rule blocks. This host has no ASR rules,
# so this parent/child heuristic compensates for that specific gap.
OFFICE_PARENTS = ('winword.exe', 'excel.exe', 'powerpnt.exe', 'outlook.exe', 'mspub.exe')
LOLBIN_CHILDREN = ('cmd.exe', 'powershell.exe', 'pwsh.exe', 'wscript.exe',
                    'cscript.exe', 'mshta.exe', 'rundll32.exe', 'regsvr32.exe')

# Ransomware-style behavior: one process creating/renaming a large number
# of files in a short window. Compensates for Controlled Folder Access
# being disabled on this host (no ransomware folder guarding at all).
#
# Live-fire testing killed VS Code (twice) under this rule: a bare file-
# creation rate has no way to distinguish encryption from an IDE indexing
# a workspace, git status, npm install, or a build. Scoped down to match
# what Controlled Folder Access itself actually protects by default (the
# user's document-type folders, not arbitrary project/cache directories),
# plus an explicit exclusion for common dev-tool/sync-client processes
# that legitimately churn many files fast.
RANSOMWARE_FILE_EVENT_WINDOW_SECONDS = 20
RANSOMWARE_FILE_EVENT_THRESHOLD = 60
RANSOMWARE_MONITORED_DIRS = (
    '\\desktop\\', '\\documents\\', '\\pictures\\', '\\music\\',
    '\\videos\\', '\\downloads\\', '\\favorites\\',
)
RANSOMWARE_EXCLUDED_PROCESSES = (
    'code.exe', 'code - insiders.exe', 'devenv.exe', 'git.exe', 'node.exe',
    'python.exe', 'pythonw.exe', 'dotnet.exe', 'msbuild.exe', 'java.exe',
    'explorer.exe', 'onedrive.exe', 'dropbox.exe', 'searchindexer.exe',
    'msedge.exe', 'chrome.exe', 'firefox.exe', 'docker.exe', 'svchost.exe',
    'trustedinstaller.exe', 'werfault.exe',
)

# All process_scores decay over time rather than accumulating forever.
# Live-fire testing showed a repeating, individually-benign low-severity
# signal (trusted-path svchost.exe access, +15 every ~30-90s) climbing
# 15->30->45->60->75 purely from patience, heading straight for a false
# CRITICAL mitigation given enough runtime. Decaying means only signals
# that actually compound *quickly* - the real shape of an attack chain -
# can cross the mitigation threshold.
SCORE_DECAY_PER_SECOND = 1.0 / 3.0  # ~20 points/minute

# Individual PROCESS_* access rights (winnt.h). Bits actually needed to read
# or tamper with another process's memory/threads - i.e. rights that matter
# for hollowing/credential-dumping. Deliberately excludes
# PROCESS_QUERY_LIMITED_INFORMATION (0x1000), PROCESS_QUERY_INFORMATION
# (0x0400), SYNCHRONIZE (0x100000) and READ_CONTROL (0x20000): those alone
# are what nearly every process on the system requests just to check "is
# this PID still alive" and are not, by themselves, evidence of anything.
PROCESS_CREATE_THREAD = 0x0002
PROCESS_VM_OPERATION = 0x0008
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_DUP_HANDLE = 0x0040
PROCESS_ALL_ACCESS = 0x1FFFFF

# LSASS: reading its memory *is* the credential-theft primitive (that's
# literally what MiniDumpWriteDump/Mimikatz do) - no write capability
# needed, so VM_READ alone is genuine signal here. DUP_HANDLE is included
# too (indirect handle-theft, e.g. via seclogon).
LSASS_DANGEROUS_BITS = (
    PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_READ
    | PROCESS_VM_WRITE | PROCESS_DUP_HANDLE
)

# Process hollowing requires *writing* a replacement payload into the
# target and redirecting its execution - VM_READ alone proves nothing.
# Live-fire testing showed WmiPrvSE.exe (Windows' own WMI provider host)
# routinely opens svchost.exe with VM_READ as part of completely normal
# Win32_Process/Win32_Service queries; including VM_READ here caused it to
# be repeatedly (and wrongly) auto-terminated. Require actual write/thread
# capability instead.
HOLLOWING_DANGEROUS_BITS = (
    PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE
)

# Processes whose suspend/termination can hang or crash the ENTIRE OS, not
# just misbehave - traced directly to a real incident: this engine
# mitigated (suspend+terminate) a false-positive score against a core
# Windows subsystem process and froze the whole machine solid (blank
# screen, zero keyboard/mouse input, required a hard reboot). csrss.exe in
# particular is why Task Manager and Process Explorer both hard-refuse to
# end or suspend it - it IS the Win32 subsystem; suspending it halts every
# session on the box. This is an unconditional, hard-coded floor: no
# heuristic, no matter how it's scored or how confident it looks, ever
# gets to suspend or terminate anything in this set. "Trusted-path" in the
# rules above only ever *reduces* score - it was never true immunity, and
# that gap is exactly what let this happen.
PROTECTED_PROCESS_NAMES = frozenset({
    'csrss.exe', 'wininit.exe', 'winlogon.exe', 'services.exe', 'smss.exe',
    'lsass.exe', 'svchost.exe', 'dwm.exe', 'explorer.exe',
    'system', 'system idle process', 'registry', 'memcompression',
})
# PID 0 (System Idle Process) and 4 (System) are always these processes
# regardless of what psutil.Process(pid).name() would report or whether
# that call even succeeds - check by number first, before touching psutil.
PROTECTED_PIDS = frozenset({0, 4})

# Bound on _recent_check_dedup (see HeuristicEngine._score_once) - same
# bounded-eviction spirit as ProcessTracker's own cap, so a correlator
# running for a long time can't grow this dict without limit.
DEDUP_MAX_ENTRIES = 2000

# ---------------------------------------------------------------------------
# Detection-forensics bounds. Both stores below follow the same bounded-
# eviction discipline as every other buffer in this codebase - a long-lived
# engine must never grow without limit, no matter how noisy the host is.
# ---------------------------------------------------------------------------

# Forensic ancestry snapshots (see _capture_forensic_snapshot): one per PID
# that ever crossed the warning or critical threshold. Snapshots are
# evidence - they are deliberately kept AFTER mitigation/death so the
# analyst can still see the attack chain of a process that no longer exists
# - but only the most recent ones, oldest evicted first.
MAX_FORENSIC_SNAPSHOTS = 100

# Recent process-access edges (see _handle_process_access): "which process
# opened which OTHER process with which rights, recently". These label the
# non-parental connection edges in a forensic snapshot - the Windows analog
# of the ancestry graph's MMAP(RWX)-style edge: parentage says how a
# process was BORN, an access edge says what it TOUCHED. The syscall label
# on such an edge (see _record_access_edge) names the connection primitive
# the granted rights imply - MMAP(RWX) for rights that allow executable
# memory to be mapped into the victim, CREATETHREAD for remote-thread
# injection, OpenProcess(mask) for anything less specific.
MAX_ACCESS_EDGES = 200


def _humanize_span(seconds):
    """'1d 4h 12m'-style rendering for activity-span / evidence-age values.
    Kept next to the scoring state it describes so the engine and the
    dashboard render identical durations from identical numbers."""
    seconds = max(0, int(seconds))
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes = rem // 60
    if days:
        return f"{days}d {hours}h {minutes}m"
    if hours:
        return f"{hours}h {minutes}m"
    return f"{minutes}m"


def _parse_granted_access(raw):
    """Sysmon's GrantedAccess field as an int, or 0 if unparseable."""
    try:
        return int(raw, 16)
    except (TypeError, ValueError):
        return 0


def _is_dangerous_access(access_int, dangerous_bits):
    """True if the mask carries any of the given dangerous right(s), or is
    PROCESS_ALL_ACCESS. Bitwise, not substring - a naive '0x10' substring
    check on the hex string wrongly matched PROCESS_QUERY_LIMITED_INFORMATION
    (0x1000) as if it were PROCESS_VM_READ, and live-fire testing confirmed
    it was auto-terminating harmless processes as a result."""
    if access_int == 0:
        return False
    return access_int == PROCESS_ALL_ACCESS or bool(access_int & dangerous_bits)


class HeuristicEngine:
    def __init__(self, rule_engine=None, config=None, known_good_hashes=None):
        # Optional additive YAML rule pack (src/rule_engine.py) - evaluated
        # after every hardcoded rule below, routed through the same
        # _add_score() every hardcoded rule uses, so a custom rule inherits
        # the protected-process floor and decay for free. None (the
        # default) is the exact behavior this engine had before rule packs
        # existed.
        self.rule_engine = rule_engine
        # Numeric tunables (decay rate, thresholds, ransomware window/count)
        # - see detection_config.py. Deliberately does NOT cover the safety
        # floor below (PROTECTED_PROCESS_NAMES, access-mask bitmasks,
        # pattern lists) - those stay hardcoded so a config file can never
        # loosen them. A missing/malformed config file yields the exact
        # hardcoded values this engine always used.
        self.config = config if config is not None else load_config()
        # Known-good SHA-256 allowlist (data/known_good_hashes.json by
        # default) - see add_static_score(). Unlike config/rule_engine
        # above, this is meant to be hand-edited by a human vetting a
        # specific false positive, the same trust model as this engine's
        # other operator-editable inputs.
        self.known_good_hashes = known_good_hashes if known_good_hashes is not None else _load_known_good_hashes(DEFAULT_KNOWN_GOOD_HASHES_PATH)
        self.process_scores = {}
        self.static_scores = {}
        # pid -> list of recent FileCreate timestamps, for the ransomware
        # rate detector in _handle_file_create.
        self._file_event_timestamps = defaultdict(list)
        # pid -> that process's OS start time, so a score accumulated
        # against a short-lived process doesn't get inherited by a
        # completely different, later process that Windows happens to
        # reuse the same PID for. Live-fire testing showed WmiPrvSE.exe
        # instances (very short-lived, frequently recreated) repeatedly
        # reusing one PID, which compounded a benign per-instance access
        # pattern into a runaway score and a mitigate() loop.
        self._pid_start_times = {}
        # pid -> monotonic time of last score change, for the decay applied
        # in _add_score.
        self._last_score_time = {}
        self._own_pid = os.getpid()
        # Raw telemetry heartbeat, independent of scoring: every Sysmon
        # event that reaches evaluate_event() increments this, whether or
        # not any heuristic below fires on it. Most process/file/registry
        # activity on a normal machine matches none of the suspicious
        # patterns in this file by design, so it produces no score and no
        # log line - which looks identical to "the subscription is dead"
        # from the outside. This counter is what a dashboard should watch
        # to tell those two situations apart.
        self.total_events_seen = 0
        self.last_event_time = None
        # Optional callable(event_id, data_dict) invoked for every raw
        # Sysmon event regardless of scoring - lets an external observer
        # (e.g. the web dashboard's Process Explorer) see all activity
        # without this engine taking on any storage/rendering concerns of
        # its own, and without changing what gets scored.
        self.on_event = None
        # Optional ProcessCorrelator (process_correlator.py) - None by
        # default, meaning evaluate_event's event_id 1 path goes straight to
        # _dispatch exactly as it always has (every single-sensor test in
        # this file relies on that). When main.py/web_server.py set this
        # after construction (same after-the-fact-wiring pattern as
        # on_event above), a ProcessCreate event is handed to the
        # correlator's submit_sysmon() instead, so it can be fused with a
        # matching ETW ProcessStart observed for the same pid.
        self.correlator = None
        # dedup_key -> set(check_id already scored for it) - see
        # _score_once(). Only ever populated when a caller supplies a
        # '_dedup_key' (the ProcessCorrelator does, for its provisional/
        # fused pair of dispatches representing one real process-create
        # event); plain single-sensor Sysmon dispatches never set this key,
        # so _score_once() falls through to unconditional scoring for them
        # - zero behavior change for the existing single-sensor path.
        self._recent_check_dedup = OrderedDict()

        # -----------------------------------------------------------------
        # Detection-forensics state. Everything below is ADDITIVE: it never
        # changes what gets scored or mitigated, only what evidence is
        # recorded about the scores the engine already produces.
        # -----------------------------------------------------------------

        # pid -> monotonic time of this PID's FIRST score contribution.
        # Together with _last_score_time it bounds how long suspicious
        # activity from this PID has been compounding - an evidence-derived
        # "activity span" reported in forensic snapshots instead of a guess
        # from log timestamps.
        self.score_first_seen = {}
        # Optional callable(pid) -> ancestry dict (process_tracker.py's
        # get_ancestry). Set by the entrypoints (main.py / web_server.py)
        # after construction, same after-the-fact wiring pattern as
        # on_event/correlator above. The engine deliberately does not own a
        # ProcessTracker itself: detection must keep working headless with
        # no tracker, so _capture_forensic_snapshot degrades to an honest
        # "ancestry unavailable" note when this is None.
        self.ancestry_provider = None
        # pid -> forensic snapshot (see _capture_forensic_snapshot). Taken
        # at the moment a PID first crosses the warning or critical
        # threshold, and deliberately retained after mitigation/death - the
        # whole point is that the evidence outlives the process. Bounded,
        # oldest evicted first.
        self.forensic_snapshots = OrderedDict()
        # actor_pid -> recent process-access edge ("this process opened that
        # other process with these rights") - see _handle_process_access.
        # These are the non-parental, injection-shaped edges that label WHO
        # an actor touched, as opposed to who its parent was.
        self._recent_access_edges = OrderedDict()

        logging.basicConfig(level=logging.INFO, format='[*] %(message)s')

    def _is_protected(self, pid):
        """True if `pid` must never be scored or mitigated - core OS
        processes (see PROTECTED_PROCESS_NAMES) plus this agent's own PID."""
        if pid in PROTECTED_PIDS or pid == self._own_pid:
            return True
        try:
            name = psutil.Process(pid).name().lower()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return False
        return name in PROTECTED_PROCESS_NAMES

    def is_allowlisted(self, file_hash):
        """True if `file_hash` is in the known-good allowlist - callers
        (e.g. static_scanner.py's clone-detection log line) that need to
        check this ahead of calling add_static_score() use this instead of
        reaching into known_good_hashes directly."""
        return file_hash in self.known_good_hashes

    def add_static_score(self, file_hash, score, context, check_id=None):
        """Record one static finding for a sample hash. `check_id` (optional)
        names WHICH static check contributed - it rides along on the log
        line so a finding's origin is always attributable from the record
        alone. The allowlist gate below still runs FIRST: a known-good hash
        never accumulates score."""
        if file_hash in self.known_good_hashes:
            # Single choke point every static finding already routes
            # through - hardcoded rules, imphash-family matches, and
            # rule_engine.py's static_pe hits alike - so allowlisting a
            # hash here suppresses all of them uniformly, unconditionally,
            # before any score is ever recorded. Never a rule competing
            # for weight inside the scoring system, always a hard override
            # in front of it.
            entry = self.known_good_hashes[file_hash]
            reason = entry.get('reason', '?') if isinstance(entry, dict) else '?'
            logging.info(f"[ALLOWLIST] {file_hash} -> ignoring finding, hash is known-good (reason: {reason}) | Would-be: +{score} ({context})")
            return
        if file_hash not in self.static_scores:
            self.static_scores[file_hash] = 0
        self.static_scores[file_hash] += score
        logging.info(f"[STATIC] {file_hash} -> +{score} ({context}) | Total: {self.static_scores[file_hash]}")

    def evaluate_event(self, xml_content):
        """
        Parses Sysmon XML event and scores it.
        """
        import xml.etree.ElementTree as ET
        try:
            # Sysmon event namespace
            root = ET.fromstring(xml_content)

            system = root.find('{http://schemas.microsoft.com/win/2004/08/events/event}System')
            if system is None:
                return

            event_id_elem = system.find('{http://schemas.microsoft.com/win/2004/08/events/event}EventID')
            if event_id_elem is None:
                return
            event_id = int(event_id_elem.text)
            self.total_events_seen += 1
            self.last_event_time = time.time()

            event_data = root.find('{http://schemas.microsoft.com/win/2004/08/events/event}EventData')
            if event_data is None:
                return

            data_dict = {}
            for data in event_data.findall('{http://schemas.microsoft.com/win/2004/08/events/event}Data'):
                name = data.get('Name')
                value = data.text
                if name:
                    data_dict[name] = value

            if event_id == 1 and self.correlator is not None:
                # Hand off to the correlator instead of dispatching directly
                # - it decides whether this becomes an immediate sysmon-only
                # dispatch (ETW down/missed it) or gets fused with a
                # matching ETW ProcessStart for the same pid. Event IDs
                # 10/11/13 are untouched - they always go straight to
                # _dispatch, exactly as before the correlator existed.
                self.correlator.submit_sysmon(data_dict, data_dict.get('UtcTime'))
            else:
                self._dispatch(event_id, data_dict)

        except Exception as e:
            logging.error(f"[ERROR] Parsing event XML failed: {e}")

    def evaluate_etw_process_start(self, pid, parent_pid, image_name, create_time=None):
        """Entry point for the ETW Kernel-Process sensor (etw_monitor.py) -
        the ETW-native counterpart to evaluate_event()'s Sysmon EventID 1
        path. The raw kernel ProcessStart event only ever carries
        ProcessID/ParentProcessID/ImageName/CreateTime (empirically
        confirmed via Get-WinEvent -ListProvider) - no CommandLine, no
        parent *image path* (only a parent PID). CommandLine/ParentImage
        are set to None rather than omitted, so every existing
        command-line-dependent check (which already treats a missing/None
        field as "does not match" - see rule_engine.py's _field_matches
        and the plain `pattern in ''` checks below) correctly and
        structurally cannot fire on this thin data, with no special-casing
        required anywhere else."""
        try:
            self.total_events_seen += 1
            self.last_event_time = time.time()
            data = {
                'ProcessId': pid,
                'ParentProcessId': parent_pid,
                'Image': image_name,
                'ParentImage': None,
                'CommandLine': None,
                'CreateTime': create_time,
                '_source': 'etw',
            }
            self._dispatch(1, data)
        except Exception as e:
            logging.error(f"[ERROR] Handling ETW process-start event failed: {e}")

    def evaluate_kernel_lsass_access(self, requestor_pid, target_pid, desired_access):
        """Entry point for the kernel sensor's LSASS-ACCESS event
        (driver/sensor/sensor.c's ObRegisterCallbacks observation,
        delivered via kernel_sensor.py). Mirrors _handle_process_access's
        existing LSASS check (same LSASS_DANGEROUS_BITS, same trusted-path
        discount) rather than replacing it - this is an INDEPENDENT,
        corroborating sensor, not a dedup of the Sysmon one. The two can
        legitimately both fire for the same real attempt (that is
        corroboration, not double-counting - see heuristic_engine's
        general stance that independent sensors agreeing is evidence, not
        noise) or only one can, if PPL or a missing Sysmon config stops
        the other from ever seeing it. check_id is distinct
        ('kernel_lsass_access') so either can be read back on its own.

        Only ever called for a desired_access that already carries a
        LSASS_DANGEROUS_BITS bit - the driver's own pre-operation callback
        already did that filtering before this was ever queued, so no
        re-check is needed here."""
        try:
            self.total_events_seen += 1
            self.last_event_time = time.time()

            try:
                source_image = psutil.Process(requestor_pid).exe().lower()
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                # Resolution failure fails CLOSED (treated as untrusted/full
                # score) - the same posture as "can't verify, so don't
                # discount" everywhere else safety-relevant in this engine.
                source_image = ''
            trusted_callers = ('\\windows\\system32\\', '\\windows\\syswow64\\')
            is_trusted_path = any(source_image.startswith(p) or f'c:{p}' in source_image for p in trusted_callers)

            access_hex = f"0x{int(desired_access):x}"
            score = 30 if is_trusted_path else 70
            context = (
                f"{'Trusted-path' if is_trusted_path else 'Untrusted'} process access to LSASS "
                f"(Access: {access_hex}) - Potential credential dumping [kernel-observed]"
            )
            self._record_access_edge(requestor_pid, target_pid, 'lsass.exe', access_hex)
            self._add_score(requestor_pid, score, context, check_id='kernel_lsass_access')
        except Exception as e:
            logging.error(f"[ERROR] Handling kernel LSASS-access event failed: {e}")

    def evaluate_kernel_driver_load(self, pid, image_name, image_base):
        """Entry point for the kernel sensor's DRIVER-LOAD event
        (driver/sensor/sensor.c's PsSetLoadImageNotifyRoutine, filtered to
        kernel-mode images only - see that file's header comment). A new
        kernel driver loading mid-session is rare on an ordinary endpoint
        and genuinely worth surfacing, but is not on its own strong enough
        evidence to score like a confirmed technique (legitimate Windows
        Update/Plug-and-Play driver installs are the common case) - scored
        low, like sedebugprivilege_iat's precursor-signal weight, so it
        compounds with other findings rather than driving mitigation alone."""
        try:
            self.total_events_seen += 1
            self.last_event_time = time.time()
            self._add_score(
                pid, 20,
                f"Kernel-mode driver loaded: {image_name} (base=0x{int(image_base):x}) [kernel-observed]",
                check_id='kernel_driver_load'
            )
        except Exception as e:
            logging.error(f"[ERROR] Handling kernel driver-load event failed: {e}")

    def _dispatch(self, event_id, data_dict):
        """Shared tail for every event source (Sysmon XML, ETW) once it's
        been normalized into a plain dict: observer hook, hardcoded
        handler routing, then the additive rule pack. Heartbeat counting
        happens in each entry point above, not here - see
        evaluate_etw_process_start's docstring for why."""
        if self.on_event:
            try:
                self.on_event(event_id, data_dict)
            except Exception:
                pass  # an observer's bug must never break detection

        if event_id == 1:
            self._handle_process_create(data_dict)
        elif event_id == 10:
            self._handle_process_access(data_dict)
        elif event_id == 11:
            self._handle_file_create(data_dict)
        elif event_id == 13:
            self._handle_registry_event(data_dict)

        if self.rule_engine:
            self.rule_engine.evaluate_behavioral(event_id, data_dict, self)

    def _score_once(self, dedup_key, check_id, pid, score, context):
        """Routes through _add_score exactly once per (dedup_key, check_id)
        pair. dedup_key is None for every plain single-sensor dispatch
        (the overwhelming majority - Sysmon-only, or ETW-only with no
        correlator in front of it), in which case this is a transparent
        pass-through to _add_score with no behavior change whatsoever.
        Only the ProcessCorrelator's provisional+fused pair of dispatches
        for one real process-create event supplies a dedup_key, to stop a
        non-command-line check (e.g. the staging-directory rule) from
        scoring the same real event twice - once per dispatch.

        Returns True if this call actually scored (vs. being suppressed as
        a duplicate) - callers that track their own hit counters (e.g.
        rule_engine.py) use this to avoid inflating a count on a
        deduped-away second dispatch of the same real event."""
        if dedup_key is None:
            # Plain single-sensor dispatch: transparent pass-through. The
            # check_id rides along so the log line always names the check
            # that produced the points.
            self._add_score(pid, score, context, check_id=check_id)
            return True

        if dedup_key not in self._recent_check_dedup:
            self._recent_check_dedup[dedup_key] = set()
        else:
            self._recent_check_dedup.move_to_end(dedup_key)
        while len(self._recent_check_dedup) > DEDUP_MAX_ENTRIES:
            self._recent_check_dedup.popitem(last=False)

        seen = self._recent_check_dedup[dedup_key]
        if check_id in seen:
            logging.info(f"[DEDUP] Skipping duplicate '{check_id}' for PID {pid} - already scored by an earlier dispatch of this same event")
            return False
        seen.add(check_id)
        self._add_score(pid, score, context, check_id=check_id)
        return True

    def _add_score(self, pid, score, context, check_id=None):
        """The single choke point every per-PID behavioral finding flows
        through. `check_id` (optional) names the contributing check - all
        internal callers pass one so the log line always shows which rule
        produced the points, and None degrades gracefully for any future
        caller that doesn't."""
        if self._is_protected(pid):
            # Never even accumulate score for a protected process - no
            # heuristic gets to push this PID toward mitigate(), full stop.
            logging.warning(f"[PROTECTED] Ignoring score for PID {pid} - protected core OS process, never auto-scored/mitigated. Would-be reason: {context}")
            return

        self._reset_score_if_pid_reused(pid)
        self._apply_decay(pid)

        if pid not in self.process_scores:
            self.process_scores[pid] = 0
        # Anchor the activity span on the FIRST contribution this PID ever
        # made - 'how long has this been going on' is evidence, derived
        # here from the same clock the scoring itself uses (monotonic, so
        # wall-clock adjustments can't bend it).
        if pid not in self.score_first_seen:
            self.score_first_seen[pid] = time.monotonic()

        self.process_scores[pid] += score
        self._last_score_time[pid] = time.monotonic()
        current_score = self.process_scores[pid]

        logging.info(f"[TELEMETRY] PID {pid} -> +{score} ({context}) | Total Score: {round(current_score, 1)}")

        self._check_threshold(pid)

    def _apply_decay(self, pid):
        """Fade this PID's score by elapsed time since its last update, so
        only signal that compounds quickly - not slow, spaced-out benign
        activity - can reach the mitigation threshold."""
        last_time = self._last_score_time.get(pid)
        if last_time is None or pid not in self.process_scores:
            return
        elapsed = time.monotonic() - last_time
        decayed = self.process_scores[pid] - (elapsed * self.config['decay_points_per_second'])
        self.process_scores[pid] = max(0.0, decayed)

    def _reset_score_if_pid_reused(self, pid):
        """If the live process currently holding `pid` isn't the same OS
        process we last scored under that PID, its accumulated score
        belongs to a process that's already gone - start that PID fresh."""
        try:
            current_start = psutil.Process(pid).create_time()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            # Already exited (common for short-lived hosts like
            # WmiPrvSE.exe) - nothing to compare against, leave as-is.
            return

        last_start = self._pid_start_times.get(pid)
        if last_start is not None and last_start != current_start:
            self.process_scores[pid] = 0
            # The old process's forensic state is not this process's: its
            # activity-span anchor describes a process that no longer
            # exists. (Forensic SNAPSHOTS are deliberately NOT cleared
            # here - they are evidence about the past, and overwriting one
            # only happens if the new process also crosses a threshold, at
            # which point the newer evidence wins.)
            self.score_first_seen.pop(pid, None)
        self._pid_start_times[pid] = current_start

    def _check_threshold(self, pid):
        score = self.process_scores.get(pid, 0)
        critical = self.config['thresholds']['critical']
        warning = self.config['thresholds']['warning']
        if score >= critical:
            # Forensic snapshot BEFORE any mitigation action: at the moment
            # of detection the ancestry is captured once, automatically,
            # with no analyst effort - and it stays even after the process
            # is terminated and gone (see _capture_forensic_snapshot).
            self._capture_forensic_snapshot(pid, 'critical_threshold', score)
            logging.warning(f"[CRITICAL THREAT] PID {pid} crossed mitigation threshold (Score {score}). Mitigating...")
            self.mitigate(pid)
            self.process_scores[pid] = 0 # reset after mitigation
            # The just-mitigated process is gone; its live activity anchor
            # describes something that can no longer accumulate. The
            # forensic snapshot above deliberately survives this cleanup -
            # that is the evidence copy.
            self.score_first_seen.pop(pid, None)
        elif score >= warning:
            # Same snapshot at the warning tier - a warning is the analyst's
            # first look at this PID, and the chain should already be there
            # when they look. _capture_forensic_snapshot only records the
            # FIRST snapshot per PID, so an escalating PID (warning ->
            # critical) keeps its earliest chain and the critical tier adds
            # the mitigation record on top, it does not silently overwrite.
            self._capture_forensic_snapshot(pid, 'warning_threshold', score)
            logging.warning(f"[WARNING] PID {pid} score >= {warning}. Taking memory snapshot... (Simulated)")

    def _capture_forensic_snapshot(self, pid, trigger, score):
        """Capture the Memory Ancestry Graph evidence for `pid` at the
        moment of detection: the full process ancestry (PID, PPID, command
        line, user, spawn time per ancestor - and environment variables for
        still-alive ancestors when a provider is wired), parent->child
        edges labeled with the syscall family that created each link
        (EXEC), and any recent process-ACCESS edge this PID originated
        (the injection-shaped 'who it touched' connection, syscall-labeled
        MMAP(RWX)/CREATETHREAD from the granted rights - see
        _record_access_edge).

        Deliberate behaviors:
        - ONE snapshot per PID: the first threshold crossing wins. An
          escalating PID (warning -> critical) keeps its earliest chain;
          the analyst sees the chain as it stood when the alert was born,
          not a rewritable record. Re-capture only happens for a NEW PID
          (or after eviction of the old snapshot).
        - Snapshots outlive the process on purpose: by the time a human
          opens the alert, mitigate() may long since have terminated it,
          and the ancestry of a dead process is unrecoverable from psutil.
        - ancestry_provider being None (headless CLI without a tracker) is
          not an error: the snapshot still records score/trigger/span and
          an explicit 'ancestry unavailable' note, so evidence is never
          silently absent.
        - The trigger_edge (process-access connection) is attached only
          when it actually involves this PID as the actor - the ancestry
          walk describes how the process was BORN, the access edge
          describes what it TOUCHED; neither claims to be the other. When
          present, the access edge is ALSO merged into the ancestry's edge
          list (kind='access') so the complete reconstructed attack chain
          - births AND injections - is one graph, not two artifacts.
        """
        if pid in self.forensic_snapshots:
            return

        ancestry = None
        ancestry_note = None
        if self.ancestry_provider is not None:
            try:
                ancestry = self.ancestry_provider(pid)
                if ancestry is None:
                    ancestry_note = ('process itself was never observed by the lineage tracker - '
                                     'ancestry cannot be reconstructed for this PID')
            except Exception as e:
                # An observer's bug must never break detection or mitigation:
                # degrade to an honest note, exactly like on_event does.
                ancestry = None
                ancestry_note = f'ancestry provider failed ({e.__class__.__name__})'
        else:
            ancestry_note = 'no lineage tracker wired into this entrypoint'

        trigger_edge = self._access_edge_for(pid)
        first_seen = self.score_first_seen.get(pid)
        activity_span = (time.monotonic() - first_seen) if first_seen is not None else None
        if isinstance(ancestry, dict):
            try:
                chain_summary = self._chain_summary_from_ancestry(ancestry)
            except Exception:
                chain_summary = None
            # Merge the access edge into the ancestry graph when this PID
            # both has a chain and TOUCHED another process: the graph then
            # reads as the complete attack chain (birth edges + the
            # injection edge), which is the whole point of capturing it
            # automatically at detection time. The edge keeps kind='access'
            # so consumers can tell it apart from parentage ('EXEC') edges
            # and render/weight it accordingly - never silently as
            # parentage.
            if trigger_edge is not None:
                merged = dict(trigger_edge)
                merged['kind'] = 'access'
                ancestry.setdefault('edges', []).append(merged)
        else:
            chain_summary = None

        snapshot = {
            'pid': pid,
            'taken_at': time.time(),
            'trigger': trigger,
            'score_at_capture': round(score, 1),
            'activity_span_seconds': round(activity_span, 1) if activity_span is not None else None,
            'activity_span_human': _humanize_span(activity_span) if activity_span is not None else None,
            'chain_summary': chain_summary,
            'ancestry': ancestry,
            'ancestry_note': ancestry_note,
            'trigger_edge': trigger_edge,
        }
        self.forensic_snapshots[pid] = snapshot
        self.forensic_snapshots.move_to_end(pid)
        while len(self.forensic_snapshots) > MAX_FORENSIC_SNAPSHOTS:
            self.forensic_snapshots.popitem(last=False)

        # The forensic log line IS an alert (AlertStore ingests it), so it
        # must carry the complete reconstruction itself: chain + the
        # syscall-labeled connection edge, requiring zero analyst effort
        # and zero extra queries to read the attack chain.
        edge_note = ''
        if trigger_edge is not None:
            target_text = trigger_edge.get('target_image') or f"pid {trigger_edge.get('to')}"
            edge_note = f" | connection edge: {trigger_edge.get('syscall')} -> {target_text}"
        logging.warning(
            f"[FORENSIC] PID {pid} ancestry captured at {trigger} "
            f"(chain: {chain_summary or 'unavailable'}){edge_note}"
        )

    @staticmethod
    def _chain_summary_from_ancestry(ancestry):
        """'a.exe -> b.exe -> evil.exe'-style one-liner from an ancestry dict
        (the structure process_tracker.get_ancestry returns). Uses the same
        dual-separator basename logic as the tracker so Windows paths render
        correctly regardless of host OS."""
        def _short(path_or_name):
            if not isinstance(path_or_name, str):
                return str(path_or_name)
            return path_or_name.replace('\\', '/').rsplit('/', 1)[-1]
        names = [_short(node.get('image') or f"pid:{node.get('pid')}") for node in ancestry.get('nodes', [])]
        summary = ' -> '.join(names)
        if ancestry.get('incomplete'):
            summary += ' (partial)'
        return summary

    def _record_access_edge(self, actor_pid, target_pid, target_image, granted_access_raw):
        """Remember one process-access connection (actor -> target with the
        granted rights mask) so a later forensic snapshot for the actor can
        label the injection-shaped edge.

        The edge carries TWO labels:
        - 'label': the raw observation, OpenProcess(<mask>) - what Sysmon
          literally recorded.
        - 'syscall': the connection primitive the mask implies, in the
          ancestry graph's syscall-label vocabulary:
            MMAP(RWX)    - the mask lets the actor map/write executable
                           memory into the victim (VM_WRITE or
                           ALL_ACCESS; the Windows analog of mmap'ing a
                           RWX page into another process's space).
            CREATETHREAD - remote-thread injection capability (the
                           CreateRemoteThread primitive) without an
                           accompanying write right.
            OpenProcess(mask) - the mask alone implies nothing injective.
        Bounded LRU, same as every other engine store."""
        access_int = _parse_granted_access(granted_access_raw)
        if access_int == PROCESS_ALL_ACCESS or (access_int & PROCESS_VM_WRITE):
            syscall_label = 'MMAP(RWX)'
        elif access_int & PROCESS_CREATE_THREAD:
            syscall_label = 'CREATETHREAD'
        else:
            syscall_label = f'OpenProcess({granted_access_raw})' if granted_access_raw else 'OpenProcess'
        self._recent_access_edges[actor_pid] = {
            'from': actor_pid,
            'to': target_pid,
            'target_image': target_image,
            'label': f'OpenProcess({granted_access_raw})' if granted_access_raw else 'OpenProcess',
            'syscall': syscall_label,
            'ts': time.time(),
        }
        self._recent_access_edges.move_to_end(actor_pid)
        while len(self._recent_access_edges) > MAX_ACCESS_EDGES:
            self._recent_access_edges.popitem(last=False)

    def _access_edge_for(self, pid):
        """The most recent access edge this PID originated, or None."""
        return self._recent_access_edges.get(pid)

    def _handle_process_create(self, data):
        # Event ID 1: Flag execution from staging directories
        pid = int(data.get('ProcessId', 0))
        image = (data.get('Image') or '').lower()
        parent_image = (data.get('ParentImage') or '').lower()
        command_line = (data.get('CommandLine') or '').lower()
        original_name = (data.get('OriginalFileName') or '').lower()
        dedup_key = data.get('_dedup_key')
        child_name = os.path.basename(image)

        # Kernel-verified PPID spoofing (driver/sensor/sensor.c's PROC-CREATE
        # event, routed here via process_correlator.submit_kernel). Sysmon/
        # ETW's ParentProcessId is only ever a CLAIM - a caller can legally
        # set it to any running process via PROC_THREAD_ATTRIBUTE_PARENT_
        # PROCESS, and neither of those two sensors can see past that. The
        # kernel driver can: it reads the real creator from
        # PsSetCreateProcessNotifyRoutineEx's CreatingThreadId field, which
        # that attribute cannot influence. This is a fundamentally stronger
        # signal than the existing [TELEMETRY_CONTRADICTION] log (which only
        # proves Sysmon and ETW disagree with EACH OTHER about the claim,
        # never whether the claim itself is true) - scored high enough to
        # cross the critical mitigation threshold on its own, the same way
        # defender_tamper already does, because kernel ground truth has no
        # realistic false-positive path the way a text-pattern match does.
        if data.get('_source') == 'kernel' and data.get('_kernel_ppid_spoof_detected'):
            real_creator = data.get('_kernel_real_creator_pid')
            claimed_parent = data.get('ParentProcessId')
            self._score_once(
                dedup_key, 'kernel_ppid_spoof', pid, 80,
                f"Kernel-verified PPID spoofing: process claims parent PID {claimed_parent} but "
                f"was actually created by PID {real_creator} (PROC_THREAD_ATTRIBUTE_PARENT_PROCESS "
                f"or equivalent) - unspoofable kernel ground truth, not a cross-sensor inference"
            )

        if 'temp' in image or 'users\\public' in image:
            self._score_once(dedup_key, 'staging_dir', pid, 30, f"Execution from staging directory: {image}")

        is_defender_tamper_host = child_name in DEFENDER_TAMPER_HOSTS or original_name in DEFENDER_TAMPER_HOSTS
        if is_defender_tamper_host:
            tamper_line = _normalize_command_line(command_line)
            if any(pattern in tamper_line for pattern in DEFENDER_TAMPER_PATTERNS):
                self._score_once(dedup_key, 'defender_tamper', pid, 90, f"Attempted Defender tampering: {command_line}")

        is_powershell_host = child_name in POWERSHELL_HOSTS or original_name in POWERSHELL_HOSTS
        if is_powershell_host and any(pattern in command_line for pattern in POWERSHELL_ABUSE_PATTERNS):
            self._score_once(dedup_key, 'powershell_abuse', pid, 45, f"Obfuscated/download-execute command line: {command_line}")

        parent_name = os.path.basename(parent_image)
        if parent_name in OFFICE_PARENTS and child_name in LOLBIN_CHILDREN:
            self._score_once(dedup_key, 'office_lolbin', pid, 60, f"Office app '{parent_name}' spawned LOLBin '{child_name}' - likely macro dropper")

    def _handle_process_access(self, data):
        # Event ID 10: Suspicious memory access (PROCESS_VM_WRITE to svchost.exe)
        source_pid = int(data.get('SourceProcessId', 0))
        source_image = data.get('SourceImage', '').lower()
        target_image = data.get('TargetImage', '').lower()
        granted_access = data.get('GrantedAccess', '').lower()

        access_int = _parse_granted_access(granted_access)
        trusted_callers = ('\\windows\\system32\\', '\\windows\\syswow64\\')
        is_trusted_path = any(source_image.startswith(p) or f'c:{p}' in source_image for p in trusted_callers)

        if 'svchost.exe' in target_image and _is_dangerous_access(access_int, HOLLOWING_DANGEROUS_BITS):
            # Signed System32 tools (SCM, WMI, admin utilities) routinely
            # request elevated rights against svchost.exe for legitimate
            # reasons - only score at full severity for untrusted sources.
            score = 15 if is_trusted_path else 50
            context = f"{'Trusted-path' if is_trusted_path else 'Untrusted'} access to {target_image} (Access: {granted_access}) - Potential Process Hollowing"
            # The access mask itself becomes an ancestry-graph edge label:
            # "actor opened svchost with THESE rights" is the Windows analog
            # of the classic MMAP(RWX) edge - how a tool connected to its
            # victim, as opposed to how the tool was born.
            self._record_access_edge(source_pid, int(data.get('TargetProcessId', 0) or 0), target_image, granted_access)
            self._add_score(source_pid, score, context, check_id='hollowing_access')

        # LSASS credential-access detection, modeled on Fibratus's
        # credential_access_suspicious_lsass_process_access /
        # credential_access_remote_thread_creation_into_lsass rules: flag
        # OpenProcess handles to lsass.exe carrying rights that let a tool
        # actually read/write its memory or duplicate a handle to it - the
        # capability Mimikatz/procdump-style LSASS dumpers need, regardless
        # of which specific combined mask (0x1010, 0x1410, 0x1438, 0x1fffff,
        # etc.) a given tool happens to request.
        if 'lsass.exe' in target_image and _is_dangerous_access(access_int, LSASS_DANGEROUS_BITS):
            # Signed, known-good tools (Task Manager, Process Explorer/
            # System Informer, WerFault) legitimately open LSASS for
            # diagnostics - only score this when the source isn't one
            # of the well-known OS/AV callers, to keep false positives down.
            score = 30 if is_trusted_path else 70
            context = f"{'Trusted-path' if is_trusted_path else 'Untrusted'} process access to LSASS (Access: {granted_access}) - Potential credential dumping"
            # Same edge-labeling as the hollowing rule above: the access
            # mask is the label on the actor->victim connection.
            self._record_access_edge(source_pid, int(data.get('TargetProcessId', 0) or 0), target_image, granted_access)
            self._add_score(source_pid, score, context, check_id='lsass_access')

    def _handle_file_create(self, data):
        # Event ID 11: Ransomware-style rate detector - a burst of file
        # creates/renames from one PID within a short window. Sysmon fires
        # FileCreate on rename-in-place too, which is exactly how most
        # ransomware "writes" (encrypt-to-new-name, delete original).
        #
        # Scoped to known dev-tool/sync-client processes excluded, and to
        # only the document-type folders Controlled Folder Access itself
        # protects by default - a bare rate counter over the whole
        # filesystem can't tell encryption apart from an IDE indexing a
        # workspace, git status, or a build, and live-fire testing proved
        # it: this rule killed VS Code twice before this scoping was added.
        pid = int(data.get('ProcessId', 0))
        image_name = os.path.basename((data.get('Image') or '').lower())
        target = (data.get('TargetFilename') or '').lower()

        if image_name in RANSOMWARE_EXCLUDED_PROCESSES:
            return
        if not any(d in target for d in RANSOMWARE_MONITORED_DIRS):
            return

        window_seconds = self.config['ransomware']['file_event_window_seconds']
        threshold = self.config['ransomware']['file_event_threshold']

        now = time.monotonic()

        timestamps = self._file_event_timestamps[pid]
        timestamps.append(now)
        cutoff = now - window_seconds
        while timestamps and timestamps[0] < cutoff:
            timestamps.pop(0)

        if len(timestamps) == threshold:
            self._add_score(
                pid, 80,
                f"{len(timestamps)} file creates/renames in {window_seconds}s - "
                f"potential mass encryption (ransomware)",
                check_id='ransomware_burst'
            )

    def _handle_registry_event(self, data):
        # Event ID 13: Unauthorized writes to Run registry keys
        pid = int(data.get('ProcessId', 0))
        target_obj = data.get('TargetObject', '').lower()
        
        if '\\currentversion\\run' in target_obj:
            self._add_score(pid, 40, f"Persistence attempt in Run key: {target_obj}", check_id='run_key_persistence')

    def mitigate(self, pid):
        # Last-resort, unconditional refusal - deliberately redundant with
        # the _add_score guard above. This check must hold even if some
        # future code path ever calls mitigate() directly, bypassing
        # scoring entirely, because the failure mode on the other side of
        # this line isn't "one process dies wrongly" - it's a frozen OS.
        if pid in PROTECTED_PIDS or pid == self._own_pid:
            logging.critical(f"[REFUSED] Refusing to mitigate PID {pid} - protected system PID. Manual review required.")
            return

        # A direct mitigation request (e.g. the dashboard's Terminate
        # button) must also produce ancestry evidence: this capture runs
        # before anything is suspended, and no-ops if the threshold path
        # already snapshotted this PID (one snapshot per PID, first wins -
        # a manual request for an already-flagged process adds nothing).
        self._capture_forensic_snapshot(pid, 'mitigation_requested', self.process_scores.get(pid, 0))

        try:
            proc = psutil.Process(pid)
            name = proc.name()
        except psutil.NoSuchProcess:
            logging.info(f"[-] Process {pid} no longer exists.")
            return
        except Exception as e:
            logging.error(f"[!] Failed to inspect process {pid} before mitigation: {e}")
            return

        if name.lower() in PROTECTED_PROCESS_NAMES:
            logging.critical(
                f"[REFUSED] Refusing to suspend/terminate PID {pid} ({name}) - protected core OS "
                f"process. Suspending a process like this can freeze or crash the entire system. "
                f"Flagged for manual review instead of auto-mitigating."
            )
            return

        try:
            # Suspend before kill for forensic safety
            proc.suspend()
            proc.terminate()
            logging.info(f"[+] Successfully terminated malicious process: {name} (PID: {pid})")
        except psutil.NoSuchProcess:
            logging.info(f"[-] Process {pid} no longer exists.")
        except Exception as e:
            logging.error(f"[!] Failed to terminate process {pid}: {e}")
