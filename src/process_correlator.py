"""
Fuses matching Sysmon + ETW process-create events for the same real process: ETW dispatches a
provisional finding immediately (low latency, thin fields) and Sysmon's richer fields produce a
fused dispatch shortly after. Each sensor operates independently; the other still works if one is down.

Join key: pid alone, not (pid, create_time). ETW's CreateTime is a locale-formatted datetime string
(TDH_OUTTYPE_DATETIME has no entry in pywintrace's TDH_CONVERTER_LOOKUP, confirmed by reading the
source); Sysmon's UtcTime is a different fixed format. Cross-sensor timestamp comparison would
silently fail to match. Keying on pid + fuse_window GC is correct and needs no timestamp parsing.
Accepted edge case: a PID reused within fuse_window could wrongly fuse (same as _reset_score_if_pid_reused).
"""

import logging
import threading
import time
from collections import OrderedDict

DEFAULT_FUSE_WINDOW_SECONDS = 2.0
DEFAULT_GC_INTERVAL_SECONDS = 5

# ---------------------------------------------------------------------------
# Witness-gap detection (see ProcessCorrelator.enable_witness_check).
#
# The kernel driver and ETW Kernel-Process are two independent, unfiltered
# witnesses to every process creation. If one reports a creation the other
# never does, the silent one is blinded (session stopped, provider disabled,
# EtwEventWrite patched), dropping events, or lagging - which is detectable
# per event, long before sensor_health.py's 60s heartbeat staleness would
# notice. Sysmon is deliberately NOT a witness here: its config excludes
# images on purpose (tools/sysmon/config.xml) and its delivery lag is not
# measured, so its silence is expected, not evidence.
# ---------------------------------------------------------------------------

# How long after the FIRST witness of a process creation we wait for the
# other one before calling it unreported. The kernel driver is polled every
# 0.1s and ETW real-time delivery is sub-second to ~1s, so 5s is a wide
# margin; it is also the floor on detection latency (plus up to one GC
# interval, because records are only examined when the GC loop runs).
DEFAULT_WITNESS_WINDOW_SECONDS = 5.0

# Ignore process creations seen this soon after the check was armed: the
# sensors do not all start at the same instant, so a process created while
# one was still coming up is not evidence of anything.
WITNESS_STARTUP_GRACE_SECONDS = 10.0

# Bound on both the open-record and recently-closed tables, so a long-lived
# correlator on a busy host cannot grow without limit.
MAX_WITNESS_RECORDS = 5000

# A sensor that stays blind produces one gap per process creation; log the
# first immediately and then at most one aggregate line per interval.
GAP_SUMMARY_INTERVAL_SECONDS = 60.0

WITNESS_SENSORS = ('etw', 'kernel')
BLINDSPOT_TAG = '[SENSOR-BLINDSPOT]'
_SENSOR_LABELS = {'etw': 'ETW', 'kernel': 'kernel driver'}


def _coerce_pid(value):
    """A non-negative int pid, or None if `value` is not one. Unlike
    _normalize_pid this never passes an unparseable value through: it is
    used for fields (creator pids) where "unknown" must stay distinguishable
    from any real pid."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, float) and not value.is_integer():  # int(1.5) would silently become pid 1
        return None
    try:
        pid = int(value)
    except (TypeError, ValueError, OverflowError):
        return None
    return pid if pid >= 0 else None


def _normalize_pid(pid):
    """Canonicalize a pid to int so all three sensors use the same dict key.
    The three sensors give inconsistent Python types for the same numeric pid:
    kernel=int (struct.unpack), Sysmon=str (XML .text, never cast),
    ETW=str in practice (pywintrace's int() converter is a no-op because
    TdhFormatProperty returns a str, confirmed by reading etw/etw.py._parseExtendedData).
    Without this: int 1234 != str '1234' means no fusion and double-scoring.
    Confirmed live: kernel-observed staging_dir process was scored twice after the
    submit_kernel _dedup_key fix, because int 1234 != str '1234' bypassed dedup."""
    try:
        return int(pid)
    except (TypeError, ValueError, OverflowError):
        return pid  # unparseable - preserve old (also-broken) behavior rather than guess


class ProcessCorrelator:
    def __init__(self, engine, fuse_window=DEFAULT_FUSE_WINDOW_SECONDS, gc_interval=DEFAULT_GC_INTERVAL_SECONDS,
                 witness_window=DEFAULT_WITNESS_WINDOW_SECONDS, clock=time.monotonic):
        self.engine = engine
        self.fuse_window = fuse_window
        self.gc_interval = gc_interval
        # A non-positive/garbage value (e.g. from a hand-edited config file)
        # falls back to the default rather than disabling the window.
        self.witness_window = (witness_window if isinstance(witness_window, (int, float))
                               and not isinstance(witness_window, bool) and witness_window > 0
                               else DEFAULT_WITNESS_WINDOW_SECONDS)
        self._clock = clock
        self._lock = threading.Lock()
        # key -> {'etw': {...} or None, 'sysmon': {...} or None, 'first_seen': monotonic}
        self._pending = {}

        # ---- witness-gap state (all guarded by self._lock) ----
        # pid -> {'first_seen', 'etw', 'kernel' (bool: has that sensor
        # reported it), 'etw_creator', 'kernel_creator', 'image'}. Insertion
        # order == first_seen order, which _gc_witness relies on.
        self._witness = OrderedDict()
        # pid -> settled time. A late arrival within 2*witness_window is for a creation already judged,
        # not a new one: prevents a lagging ETW event from counting as "ETW missed it" then re-opening.
        self._closed = OrderedDict()
        self._witness_gate = None       # callable(sensor_name) -> bool; None == check disabled
        self._witness_armed_at = None
        self._witness_grace = WITNESS_STARTUP_GRACE_SECONDS
        self._gap_counts = {s: 0 for s in WITNESS_SENSORS}
        self._gap_state = {s: {'active': False, 'episode': 0, 'suppressed': 0, 'last_report': 0.0}
                           for s in WITNESS_SENSORS}
        # ETW-header creator vs kernel-driver real creator, for processes
        # both reported. How often they agree is the live evidence for
        # whether the ETW header really identifies the creating process.
        self._creator_agreement = {'agree': 0, 'disagree': 0}

    def submit_etw(self, pid, parent_pid, image_name, create_time, creator_pid=None):
        """ETW's fields arrive first (it's the faster sensor) - dispatch a
        provisional finding immediately, unconditionally, so latency never
        waits on Sysmon. Also record it so a same-pid Sysmon arrival within
        fuse_window can be merged into a richer, fused dispatch by the GC.

        `creator_pid` is the process ID in the ETW event HEADER, i.e. the
        process that generated the event - for a ProcessStart, the creating
        process (the same field Fibratus uses for its `real_ppid`, and
        Velociraptor's Windows.ETW.KernelProcess artifact uses as the
        parent). It is distinct from the payload's ParentProcessID, which
        is only the claimed parent. None when the event carried no header
        pid. It rides on the dispatch as `_etw_creator_pid` (only when
        known) and feeds the creator-agreement counters; whether it SCORES
        is decided by HeuristicEngine (config: correlator.etw_creator_scoring)."""
        pid_key = _normalize_pid(pid)
        creator = _coerce_pid(creator_pid)
        fields = {
            'ProcessId': pid,
            'ParentProcessId': parent_pid,
            'Image': image_name,
            'CreateTime': create_time,
        }
        with self._lock:
            record = self._pending.setdefault(pid_key, {'etw': None, 'sysmon': None, 'first_seen': time.monotonic()})
            record['etw'] = fields
            self._note_witness_locked(pid_key, 'etw', image_name, creator)

        data = {
            **fields,
            'ParentImage': None,
            'CommandLine': None,
            '_source': 'etw',
            '_provisional': True,
            '_dedup_key': pid_key,
        }
        if creator is not None:
            data['_etw_creator_pid'] = creator
        self.engine._dispatch(1, data)

    def submit_kernel(self, pid, claimed_parent_pid, real_creator_pid, image_name, ppid_spoof_detected):
        """Kernel-sourced process-create (driver/sensor/sensor.c's
        PROC-CREATE event, delivered over the comms channel by
        kernel_sensor.py). Dispatched immediately and independently, like
        ETW's provisional dispatch - deliberately NOT merged into the
        pending etw/sysmon fusion dict. The driver has already computed the
        one thing cross-sensor fusion would otherwise try to re-derive
        (claimed vs real parent) from PsSetCreateProcessNotifyRoutineEx's
        CreatingThreadId, which a caller cannot influence - doing it again
        here from timestamp-matched user-mode records would only be less
        reliable than what the kernel already knows for certain. See
        HeuristicEngine._handle_process_create's kernel_ppid_spoof check for
        where the flag actually scores.

        Like ETW, the kernel event carries no CommandLine and no parent
        image path - ParentImage/CommandLine are None so every
        command-line-dependent rule structurally cannot fire on it.

        '_dedup_key' is set to _normalize_pid(pid) - found missing
        during evasion-matrix testing (reports/evasion_matrix.md): without it,
        HeuristicEngine._score_once() reads a missing key as "no
        correlator in front of this dispatch" and scores every
        _score_once-routed check (staging_dir, defender_tamper,
        powershell_abuse, office_lolbin) unconditionally, a SECOND time,
        for every real process this sensor and ETW/Sysmon both observe -
        which is the normal case for literally every process on the
        system whenever the kernel driver is running, not an edge case.
        Confirmed live: a single staging-dir execution was scored +30
        twice before this fix. kernel_ppid_spoof is unaffected either
        way - it's gated to only ever run on this dispatch, so it was
        never double-scored, and now simply participates in the same
        per-pid dedup bucket ETW/Sysmon already share instead of
        bypassing it."""
        pid_key = _normalize_pid(pid)
        with self._lock:
            self._note_witness_locked(pid_key, 'kernel', image_name, _coerce_pid(real_creator_pid))
        self.engine._dispatch(1, {
            'ProcessId': pid,
            'ParentProcessId': claimed_parent_pid,
            'Image': image_name,
            'ParentImage': None,
            'CommandLine': None,
            '_source': 'kernel',
            '_kernel_real_creator_pid': real_creator_pid,
            '_kernel_ppid_spoof_detected': bool(ppid_spoof_detected),
            '_dedup_key': pid_key,
        })

    def submit_sysmon(self, data_dict, create_time):
        """Sysmon's fields arrive second (richer, slower). Not dispatched
        immediately - recorded so the GC can give a same-pid ETW arrival
        its fuse_window chance to merge first."""
        pid_key = _normalize_pid(data_dict.get('ProcessId'))
        with self._lock:
            record = self._pending.setdefault(pid_key, {'etw': None, 'sysmon': None, 'first_seen': time.monotonic()})
            record['sysmon'] = dict(data_dict)
            record['sysmon']['CreateTime'] = create_time

    def _gc_once(self):
        """Pop and dispatch every pending record older than fuse_window.
        Never holds the lock across a _dispatch() call - _dispatch can run
        arbitrary rule/hardcoded-check logic and must not block submit_etw/
        submit_sysmon on another thread."""
        now = time.monotonic()
        to_dispatch = []
        with self._lock:
            for key, record in list(self._pending.items()):
                if now - record['first_seen'] >= self.fuse_window:
                    del self._pending[key]
                    to_dispatch.append((key, record))

        for key, record in to_dispatch:
            etw_fields, sysmon_fields = record['etw'], record['sysmon']
            if sysmon_fields is None:
                continue  # ETW-only: already dispatched provisionally at submission time.
            if etw_fields is not None:
                try:
                    self._check_ancestry_contradiction(key, etw_fields, sysmon_fields)
                except Exception as e:
                    logging.error(f"[CORRELATOR] Contradiction check failed for {key}: {e}")
                data = {**sysmon_fields, '_source': 'fused', '_provisional': False, '_dedup_key': key}
            else:
                data = {**sysmon_fields, '_source': 'sysmon', '_dedup_key': key}
            try:
                self.engine._dispatch(1, data)
            except Exception as e:
                logging.error(f"[CORRELATOR] Dispatch failed for {key}: {e}")

        # Independent of the fusion above: a failure here must never be able
        # to stop pending Sysmon/ETW records from being dispatched.
        try:
            self._gc_witness()
        except Exception as e:
            logging.error(f"[CORRELATOR] Witness GC failed: {e}")

    # ------------------------------------------------------------------
    # Witness-gap detection.
    # ------------------------------------------------------------------
    def enable_witness_check(self, gate, startup_grace=WITNESS_STARTUP_GRACE_SECONDS):
        """Arm per-event witness-gap detection. Until this is called the
        correlator only keeps its (bounded) witness records and the
        creator-agreement counters; it never reports a gap.

        `gate(sensor_name)` is called, only when a creation was seen by one
        of 'etw'/'kernel' but not the other, with the name of the sensor
        that did NOT report it. It must return True only if that silence is
        unexplained - i.e. the sensor is expected to be working. The
        entrypoints return False for a sensor that never came up
        ('unavailable') or is already known to be dropping events
        ('lossy'): both explain a miss without any tampering. A gate that
        raises is treated as False (no finding)."""
        with self._lock:
            self._witness_gate = gate
            self._witness_armed_at = self._clock()
            self._witness_grace = startup_grace

    def witness_stats(self):
        """Snapshot for /api/summary: whether the check is armed, the gap
        counts per sensor, which sensors are currently in a gap episode,
        and how often the ETW-header creator agreed with the kernel
        driver's real creator."""
        with self._lock:
            return {
                'enabled': self._witness_gate is not None,
                'window_seconds': self.witness_window,
                'gaps': dict(self._gap_counts),
                'active_gaps': [s for s in WITNESS_SENSORS if self._gap_state[s]['active']],
                'creator_agreement': dict(self._creator_agreement),
            }

    def _note_witness_locked(self, pid_key, sensor, image, creator):
        """Record that `sensor` reported the creation of `pid_key`. Caller
        must hold self._lock."""
        # A non-int key means the sensor handed over no usable pid; pooling
        # all such events under one key would fabricate a gap.
        if not isinstance(pid_key, int):
            return
        now = self._clock()
        closed_at = self._closed.get(pid_key)
        if closed_at is not None:
            if now - closed_at < 2 * self.witness_window:
                return  # late arrival for a creation already judged
            del self._closed[pid_key]
        record = self._witness.get(pid_key)
        if record is None:
            record = {'first_seen': now, 'etw': False, 'kernel': False,
                      'etw_creator': None, 'kernel_creator': None, 'image': None}
            self._witness[pid_key] = record
            while len(self._witness) > MAX_WITNESS_RECORDS:
                self._witness.popitem(last=False)
        record[sensor] = True
        if image:
            record['image'] = image
        if creator is not None:
            record[f'{sensor}_creator'] = creator

    def _gc_witness(self):
        """Settle every witness record older than witness_window. Records
        are examined in first_seen order and the scan stops at the first
        one still inside the window. The (arbitrary, caller-supplied) gate
        and all logging run outside the lock."""
        settled = []
        with self._lock:
            now = self._clock()
            while self._witness:
                key, record = next(iter(self._witness.items()))
                if now - record['first_seen'] < self.witness_window:
                    break
                del self._witness[key]
                self._closed.pop(key, None)
                self._closed[key] = now
                settled.append((key, record))
            while len(self._closed) > MAX_WITNESS_RECORDS:
                self._closed.popitem(last=False)
            gate, armed_at, grace = self._witness_gate, self._witness_armed_at, self._witness_grace

        for key, record in settled:
            try:
                self._settle_witness_record(key, record, gate, armed_at, grace)
            except Exception as e:
                logging.error(f"[CORRELATOR] Witness check failed for {key}: {e}")

    def _settle_witness_record(self, pid, record, gate, armed_at, grace):
        both_reported = record['etw'] and record['kernel']

        if both_reported and record['etw_creator'] is not None and record['kernel_creator'] is not None:
            with self._lock:
                outcome = 'agree' if record['etw_creator'] == record['kernel_creator'] else 'disagree'
                self._creator_agreement[outcome] += 1

        if gate is None or armed_at is None:
            return
        if record['first_seen'] < armed_at + grace:
            return  # created while sensors were still starting up

        if both_reported:
            self._note_witnessing_again()
            return

        reporter = 'etw' if record['etw'] else 'kernel'
        silent = 'kernel' if reporter == 'etw' else 'etw'
        try:
            unexplained = bool(gate(silent))
        except Exception as e:
            logging.error(f"[CORRELATOR] Witness gate failed for {silent}: {e}")
            return
        if unexplained:
            self._report_gap(silent, reporter, pid, record.get('image'))

    def _report_gap(self, silent, reporter, pid, image):
        now = self._clock()
        summary_count = None
        with self._lock:
            self._gap_counts[silent] += 1
            state = self._gap_state[silent]
            state['episode'] += 1
            first_in_episode = not state['active']
            if first_in_episode:
                state['active'] = True
                state['suppressed'] = 0
                state['last_report'] = now
            else:
                state['suppressed'] += 1
                if now - state['last_report'] >= GAP_SUMMARY_INTERVAL_SECONDS:
                    summary_count = state['suppressed']
                    state['suppressed'] = 0
                    state['last_report'] = now

        silent_label, reporter_label = _SENSOR_LABELS[silent], _SENSOR_LABELS[reporter]
        if first_in_episode:
            logging.warning(
                f"{BLINDSPOT_TAG} {silent_label} did not report a process creation that the {reporter_label} "
                f"observed (PID {pid}, image {image or 'unknown'}) - the {silent_label} sensor may be blinded, "
                f"stopped, dropping events at the OS level, or lagging. Process visibility is reduced until it "
                f"reports again."
            )
        elif summary_count:
            logging.warning(
                f"{BLINDSPOT_TAG} {silent_label} is still missing process creations: {summary_count} more "
                f"unreported since the last report (latest: PID {pid}, image {image or 'unknown'})"
            )

    def _note_witnessing_again(self):
        """A creation both sensors reported: any sensor in a gap episode is
        reporting again."""
        recovered = []
        with self._lock:
            for sensor in WITNESS_SENSORS:
                state = self._gap_state[sensor]
                if state['active']:
                    recovered.append((sensor, state['episode']))
                    state.update(active=False, episode=0, suppressed=0)
        for sensor, episode in recovered:
            logging.info(
                f"{BLINDSPOT_TAG} {_SENSOR_LABELS[sensor]} is reporting process creations again "
                f"({episode} unreported during the gap)"
            )

    def _check_ancestry_contradiction(self, pid, etw_fields, sysmon_fields):
        """Both sensors observed the same real PID independently - if they
        disagree about who its parent was, that disagreement is itself
        security-relevant (a PID-reuse race, a spoofed parent, or one
        sensor being fed doctored data) and must never be silently resolved
        by whichever field the fused-event merge above happens to keep.
        Logged as its own [TELEMETRY_CONTRADICTION] line (which the
        dashboard categorizes and surfaces distinctly - see
        dashboard_data.CATEGORY_RULES) rather than folded into the fused
        dispatch, so the discrepancy can't get lost inside a normal-looking
        process-create event.

        Scoped to parent-PID ancestry only, the one field both independent
        kernel sensors actually carry today (see etw_monitor.py's docstring
        on the raw ETW event's thin field set) - extend to other fields
        (module state, file/network activity) once a sensor for those feeds
        the correlator."""
        etw_ppid, sysmon_ppid = etw_fields.get('ParentProcessId'), sysmon_fields.get('ParentProcessId')
        if etw_ppid is None or sysmon_ppid is None:
            return
        try:
            etw_ppid, sysmon_ppid = int(etw_ppid), int(sysmon_ppid)
        except (TypeError, ValueError):
            return
        if etw_ppid != sysmon_ppid:
            logging.warning(
                f"[TELEMETRY_CONTRADICTION] PID {pid}: independent sensors disagree on parent "
                f"process - ETW reports parent PID {etw_ppid}, Sysmon reports parent PID {sysmon_ppid}"
            )

    def gc_loop(self):
        while True:
            time.sleep(self.gc_interval)
            try:
                self._gc_once()
            except Exception as e:
                logging.error(f"[CORRELATOR] GC pass failed: {e}")

    def start(self):
        threading.Thread(target=self.gc_loop, daemon=True).start()
