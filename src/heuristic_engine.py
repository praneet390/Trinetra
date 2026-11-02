import os
import json
import time
import psutil
import logging
from collections import defaultdict, OrderedDict

from detection_config import load_config

# Human-vetted SHA-256 allowlist: unconditional override in front of scoring.
DEFAULT_KNOWN_GOOD_HASHES_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'known_good_hashes.json')


def _load_known_good_hashes(path):
    try:
        with open(path, 'r') as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {}

# Defender tamper commands - compensates for Tamper Protection being OFF on this host.
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
    """Strip quotes and collapse whitespace for pattern matching - a launcher
    may quote sc.exe as `"sc.exe" stop windefend` which defeats a bare substring."""
    return ' '.join(command_line.replace('"', ' ').split())

# PowerShell obfuscation/download-execute markers (ASR rules absent on this host).
POWERSHELL_ABUSE_PATTERNS = (
    '-enc ', '-encodedcommand', '-e ', 'frombase64string', 'downloadstring',
    'downloadfile', 'iex(', 'invoke-expression', '-windowstyle hidden',
    '-w hidden', '-executionpolicy bypass', '-ep bypass', '-noprofile -nop',
)

# Scoped to PowerShell hosts only - bare '-e ' hits grep/sed/node on any other process.
# Checks OriginalFileName too so a renamed powershell.exe still matches.
POWERSHELL_HOSTS = ('powershell.exe', 'pwsh.exe', 'pwsh.dll', 'powershell_ise.exe')

# Scoped to hosts that *execute* tamper commands; launchers (wmic, python) still get
# caught through the interpreter/utility they spawn. OriginalFileName checked too.
DEFENDER_TAMPER_HOSTS = POWERSHELL_HOSTS + (
    'cmd.exe', 'sc.exe', 'net.exe', 'net1.exe', 'taskkill.exe', 'reg.exe',
)

# Office macro-dropper heuristic (no ASR rules on this host).
OFFICE_PARENTS = ('winword.exe', 'excel.exe', 'powerpnt.exe', 'outlook.exe', 'mspub.exe')
LOLBIN_CHILDREN = ('cmd.exe', 'powershell.exe', 'pwsh.exe', 'wscript.exe',
                    'cscript.exe', 'mshta.exe', 'rundll32.exe', 'regsvr32.exe')

# Ransomware rate detector (no Controlled Folder Access on this host). Scoped
# to document-type dirs only - a bare rate counter killed VS Code twice in testing.
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

# Without decay a benign low-score signal (e.g. trusted svchost access, +15 every ~60s)
# accumulates to a false critical. Only quickly-compounding signals can cross the threshold.
SCORE_DECAY_PER_SECOND = 1.0 / 3.0  # ~20 points/minute

# PROCESS_* access rights (winnt.h) relevant to hollowing/credential-dumping.
# Excludes QUERY_LIMITED_INFORMATION/QUERY_INFORMATION/SYNCHRONIZE/READ_CONTROL:
# those are "is this PID alive" checks, not evidence.
PROCESS_CREATE_THREAD = 0x0002
PROCESS_VM_OPERATION = 0x0008
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_DUP_HANDLE = 0x0040
PROCESS_ALL_ACCESS = 0x1FFFFF

# VM_READ alone is credential-theft (MiniDumpWriteDump/Mimikatz). DUP_HANDLE included for seclogon.
LSASS_DANGEROUS_BITS = (
    PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_READ
    | PROCESS_VM_WRITE | PROCESS_DUP_HANDLE
)

# VM_READ alone excluded from hollowing - WmiPrvSE.exe opens svchost with VM_READ for
# legitimate WMI queries; including it caused repeated false auto-terminations.
HOLLOWING_DANGEROUS_BITS = (
    PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE
)

# Unconditional no-mitigation floor - suspending any of these can freeze the entire OS.
# Traced to a real incident: a false positive against a subsystem process froze the box.
# csrss.exe IS the Win32 subsystem; Task Manager also refuses to end it for the same reason.
PROTECTED_PROCESS_NAMES = frozenset({
    'csrss.exe', 'wininit.exe', 'winlogon.exe', 'services.exe', 'smss.exe',
    'lsass.exe', 'svchost.exe', 'dwm.exe', 'explorer.exe',
    'system', 'system idle process', 'registry', 'memcompression',
})
# PID 0/4 are always System/Idle regardless of psutil.name() - checked before psutil.
PROTECTED_PIDS = frozenset({0, 4})

DEDUP_MAX_ENTRIES = 2000

# Forensic snapshots kept after mitigation/death - evidence that outlives the process.
MAX_FORENSIC_SNAPSHOTS = 100
# Recent process-access edges: who touched whom with what rights (non-parental connections).
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


# Shared by every "is the actor a trusted OS caller" discount in this file
# (hollowing/LSASS access, and the kernel-sourced checks below) - a single
# definition so the four call sites can't quietly drift out of sync.
TRUSTED_SYSTEM_PATHS = ('\\windows\\system32\\', '\\windows\\syswow64\\')


def _is_trusted_system_path(image_path):
    """True if `image_path` (already lowercased by the caller) resolves
    under System32/SysWOW64 - handles both a bare NT-style path
    ('\\windows\\system32\\...') and a drive-letter path
    ('c:\\windows\\system32\\...')."""
    return any(image_path.startswith(p) or f'c:{p}' in image_path for p in TRUSTED_SYSTEM_PATHS)


class HeuristicEngine:
    def __init__(self, rule_engine=None, config=None, known_good_hashes=None):
        self.rule_engine = rule_engine
        # Config does NOT cover safety floors (PROTECTED_PROCESS_NAMES, access masks,
        # pattern lists) - those stay hardcoded so a config file can never loosen them.
        self.config = config if config is not None else load_config()
        self.known_good_hashes = known_good_hashes if known_good_hashes is not None else _load_known_good_hashes(DEFAULT_KNOWN_GOOD_HASHES_PATH)
        self.process_scores = {}
        self.static_scores = {}
        self._file_event_timestamps = defaultdict(list)
        # Prevents a short-lived PID (e.g. WmiPrvSE.exe) from inheriting score
        # when Windows reuses its PID - seen as a mitigate() loop in live testing.
        self._pid_start_times = {}
        self._last_score_time = {}
        self._own_pid = os.getpid()
        # Heartbeat independent of scoring: a silent host and a dead subscription
        # both show zero score, but this counter tells them apart.
        self.total_events_seen = 0
        self.last_event_time = None
        self.on_event = None   # optional callable(event_id, data_dict) for observers
        self.correlator = None  # optional ProcessCorrelator, wired after construction
        self._recent_check_dedup = OrderedDict()

        # First score contribution per PID - anchors the activity-span evidence field.
        self.score_first_seen = {}
        self.ancestry_provider = None  # optional callable(pid) -> ancestry dict
        self.forensic_snapshots = OrderedDict()  # retained after mitigation/death
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
            entry = self.known_good_hashes[file_hash]
            reason = entry.get('reason', '?') if isinstance(entry, dict) else '?'
            logging.info(f"[ALLOWLIST] {file_hash} -> ignoring finding, hash is known-good (reason: {reason}) | Would-be: +{score} ({context})")
            return
        if file_hash not in self.static_scores:
            self.static_scores[file_hash] = 0
        self.static_scores[file_hash] += score
        logging.info(f"[STATIC] {file_hash} -> +{score} ({context}) | Total: {self.static_scores[file_hash]}")

    def evaluate_event(self, xml_content):
        """Parses Sysmon XML event and scores it."""
        import xml.etree.ElementTree as ET
        try:
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
                self.correlator.submit_sysmon(data_dict, data_dict.get('UtcTime'))
            else:
                self._dispatch(event_id, data_dict)

        except Exception as e:
            logging.error(f"[ERROR] Parsing event XML failed: {e}")

    def evaluate_etw_process_start(self, pid, parent_pid, image_name, create_time=None):
        """ETW Kernel-Process sensor entry point. CommandLine/ParentImage set to None
        (thin ETW data - no CommandLine) so command-line checks structurally can't fire."""
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
        """Kernel sensor LSASS-ACCESS entry point. Independent corroboration of the Sysmon
        check - both can legitimately fire for the same attempt (corroboration, not noise).
        Already filtered by the driver's pre-operation callback to LSASS_DANGEROUS_BITS."""
        try:
            self.total_events_seen += 1
            self.last_event_time = time.time()

            try:
                source_image = psutil.Process(requestor_pid).exe().lower()
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                source_image = ''  # can't verify -> fails closed (untrusted/full score)
            is_trusted_path = _is_trusted_system_path(source_image)

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
        """Kernel DRIVER-LOAD entry point. Low score (compounds, doesn't drive mitigation alone)
        - legitimate driver installs are the common case."""
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
        """Normalized dispatch: observer hook, handler routing, rule pack."""
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
        """Score once per (dedup_key, check_id) - prevents a provisional+fused pair
        from scoring the same real event twice. None dedup_key = transparent pass-through.
        Returns True if scoring happened (False = duplicate suppressed)."""
        if dedup_key is None:
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
        """Single choke point for all per-PID behavioral findings. check_id names the contributing rule; None is accepted."""
        if self._is_protected(pid):
            # No heuristic may accumulate toward mitigate() for protected PIDs.
            logging.warning(f"[PROTECTED] Ignoring score for PID {pid} - protected core OS process, never auto-scored/mitigated. Would-be reason: {context}")
            return

        self._reset_score_if_pid_reused(pid)
        self._apply_decay(pid)

        if pid not in self.process_scores:
            self.process_scores[pid] = 0
        # Anchor on first contribution; monotonic clock so wall-clock adjustments can't bend it.
        if pid not in self.score_first_seen:
            self.score_first_seen[pid] = time.monotonic()

        self.process_scores[pid] += score
        self._last_score_time[pid] = time.monotonic()
        current_score = self.process_scores[pid]

        logging.info(f"[TELEMETRY] PID {pid} -> +{score} ({context}) | Total Score: {round(current_score, 1)}")

        self._check_threshold(pid)

    def _apply_decay(self, pid):
        """Fade score by elapsed time so only rapidly-compounding signal reaches the mitigation threshold."""
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
            return  # already exited (common for WmiPrvSE.exe) - nothing to compare

        last_start = self._pid_start_times.get(pid)
        if last_start is not None and last_start != current_start:
            self.process_scores[pid] = 0
            # Forensic snapshots are NOT cleared: they are evidence about the past process, not this new one.
            self.score_first_seen.pop(pid, None)
        self._pid_start_times[pid] = current_start

    def _check_threshold(self, pid):
        score = self.process_scores.get(pid, 0)
        critical = self.config['thresholds']['critical']
        warning = self.config['thresholds']['warning']
        if score >= critical:
            # Snapshot before mitigate: ancestry of a dead process is unrecoverable.
            self._capture_forensic_snapshot(pid, 'critical_threshold', score)
            logging.warning(f"[CRITICAL THREAT] PID {pid} crossed mitigation threshold (Score {score}). Mitigating...")
            self.mitigate(pid)
            self.process_scores[pid] = 0 # reset after mitigation
            # Activity anchor cleaned up; forensic snapshot survives as the evidence copy.
            self.score_first_seen.pop(pid, None)
        elif score >= warning:
            # Same snapshot at warning tier; _capture_forensic_snapshot no-ops for a PID already snapshotted.
            self._capture_forensic_snapshot(pid, 'warning_threshold', score)
            logging.warning(f"[WARNING] PID {pid} score >= {warning}. Taking memory snapshot... (Simulated)")

    def _capture_forensic_snapshot(self, pid, trigger, score):
        """Capture ancestry evidence for `pid` at detection time.
        One snapshot per PID: the first threshold crossing wins; an escalating PID keeps its earliest chain.
        Snapshots outlive the process: ancestry is unrecoverable from psutil after termination.
        ancestry_provider=None is not an error: the snapshot records an explicit 'unavailable' note.
        trigger_edge (birth edges + injection edge) merges into one graph with kind='access' for the injection.
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
                # An observer's bug must never break detection.
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
            # Merge injection edge (kind='access') into ancestry so birth + injection form one graph.
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

        # AlertStore ingests this line; include the full chain so zero extra queries are needed.
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
        """'a.exe -> b.exe -> evil.exe' from an ancestry dict. Dual-separator basename for Windows paths on POSIX."""
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
        """Record one actor->target access edge for forensic snapshot labeling.
        'syscall' translates the granted mask to its injection primitive:
        MMAP(RWX) for VM_WRITE/ALL_ACCESS, CREATETHREAD for CREATE_THREAD-only, else OpenProcess(mask)."""
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

    def _etw_creator_scoring_enabled(self):
        """config correlator.etw_creator_scoring (default False). Ships off: a mismatch auto-terminates
        a process, and the ETW header's meaning on this provider is unconfirmed live.
        Enable once the /api/summary agreement counters show the header matching the kernel driver."""
        try:
            return bool(self.config.get('correlator', {}).get('etw_creator_scoring', False))
        except AttributeError:
            return False

    def _score_ppid_spoof(self, dedup_key, pid, claimed_parent, real_creator, via_etw_header):
        """Score one PPID-spoof finding. Check id is 'kernel_ppid_spoof' for both kernel and ETW
        sources so two sensors on the same real event score once, not twice."""
        try:
            creator_image = psutil.Process(int(real_creator)).exe().lower()
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, TypeError, ValueError):
            creator_image = ''  # can't verify -> fails closed (untrusted/full score)
        is_trusted_creator = _is_trusted_system_path(creator_image)
        score = 20 if is_trusted_creator else 80
        if via_etw_header:
            label = 'Trusted-broker' if is_trusted_creator else 'ETW-header'
            evidence = ("the ETW event header names the creating process - corroborating evidence, "
                        "independent of the kernel driver")
        else:
            label = 'Trusted-broker' if is_trusted_creator else 'Kernel-verified'
            evidence = "unspoofable kernel ground truth, not a cross-sensor inference"
        context = (
            f"{label} PPID spoofing: process "
            f"claims parent PID {claimed_parent} but was actually created by PID {real_creator} "
            f"(PROC_THREAD_ATTRIBUTE_PARENT_PROCESS or equivalent) - {evidence}"
            + (" (real creator resolves to a trusted System32/SysWOW64 broker - likely benign "
               "packaged-app/COM activation reparenting, not an attack)" if is_trusted_creator else "")
        )
        self._score_once(dedup_key, 'kernel_ppid_spoof', pid, score, context)

    def _handle_process_create(self, data):
        # Event ID 1: Flag execution from staging directories
        pid = int(data.get('ProcessId', 0))
        image = (data.get('Image') or '').lower()
        parent_image = (data.get('ParentImage') or '').lower()
        command_line = (data.get('CommandLine') or '').lower()
        original_name = (data.get('OriginalFileName') or '').lower()
        dedup_key = data.get('_dedup_key')
        child_name = os.path.basename(image)

        # Kernel-verified PPID spoof: reads real creator from PsSetCreateProcessNotifyRoutineEx,
        # which PROC_THREAD_ATTRIBUTE_PARENT_PROCESS cannot influence. Sysmon/ETW ParentProcessId
        # is only a claim. False-positive path: COM activation (RuntimeBroker, dllhost surrogate,
        # svchost/DcomLaunch) legitimately reparents via that attribute for taskbar grouping.
        # Live-fire: auto-killed Outlook (olk.exe, olkFullTrustExecutor.exe) three times.
        # Full severity when real creator doesn't resolve to System32/SysWOW64; discounted when it does.
        if data.get('_source') == 'kernel' and data.get('_kernel_ppid_spoof_detected'):
            self._score_ppid_spoof(dedup_key, pid, data.get('ParentProcessId'),
                                   data.get('_kernel_real_creator_pid'), via_etw_header=False)
        elif data.get('_source') == 'etw' and self._etw_creator_scoring_enabled():
            # ETW header pid vs. claimed parent: same check id as kernel branch so one real spoof scores once.
            # Off by default - see _etw_creator_scoring_enabled.
            etw_creator = data.get('_etw_creator_pid')
            claimed_parent = data.get('ParentProcessId')
            try:
                spoofed = etw_creator is not None and int(claimed_parent) != int(etw_creator)
            except (TypeError, ValueError):
                spoofed = False  # no usable claimed parent -> nothing to compare, never guess
            if spoofed:
                self._score_ppid_spoof(dedup_key, pid, claimed_parent, etw_creator, via_etw_header=True)

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
        is_trusted_path = _is_trusted_system_path(source_image)

        if 'svchost.exe' in target_image and _is_dangerous_access(access_int, HOLLOWING_DANGEROUS_BITS):
            score = 15 if is_trusted_path else 50
            context = f"{'Trusted-path' if is_trusted_path else 'Untrusted'} access to {target_image} (Access: {granted_access}) - Potential Process Hollowing"
            self._record_access_edge(source_pid, int(data.get('TargetProcessId', 0) or 0), target_image, granted_access)
            self._add_score(source_pid, score, context, check_id='hollowing_access')

        # LSASS credential-access: flag OpenProcess carrying rights Mimikatz/procdump need to dump credentials.
        if 'lsass.exe' in target_image and _is_dangerous_access(access_int, LSASS_DANGEROUS_BITS):
            score = 30 if is_trusted_path else 70
            context = f"{'Trusted-path' if is_trusted_path else 'Untrusted'} process access to LSASS (Access: {granted_access}) - Potential credential dumping"
            self._record_access_edge(source_pid, int(data.get('TargetProcessId', 0) or 0), target_image, granted_access)
            self._add_score(source_pid, score, context, check_id='lsass_access')

    def _handle_file_create(self, data):
        # Ransomware rate detector: Sysmon FileCreate fires on rename-in-place, which is how most
        # ransomware "writes". Scoped to document dirs only - a bare rate counter killed VS Code
        # twice before this scoping was added.
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
        pid = int(data.get('ProcessId', 0))
        target_obj = data.get('TargetObject', '').lower()
        
        if '\\currentversion\\run' in target_obj:
            self._add_score(pid, 40, f"Persistence attempt in Run key: {target_obj}", check_id='run_key_persistence')

    def mitigate(self, pid):
        # Deliberately redundant with the _add_score guard: mitigate() may be called directly.
        # The failure mode isn't "one process dies wrongly" - it's a frozen OS.
        if pid in PROTECTED_PIDS or pid == self._own_pid:
            logging.critical(f"[REFUSED] Refusing to mitigate PID {pid} - protected system PID. Manual review required.")
            return

        # Capture ancestry before suspend; no-ops if the threshold path already snapshotted this PID.
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
