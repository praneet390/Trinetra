"""
Fuses matching Sysmon + ETW process-create events for the same real OS
process so detection gets ETW's low latency immediately (a *provisional*
dispatch, thin fields) and Sysmon's richer fields shortly after (a *fused*
dispatch), while neither sensor's independent operation depends on the
other - if one sensor is down, the other's events still reach the engine
on their own.

Join key: pid alone, not (pid, create_time) as originally sketched. Each
sensor's create_time arrives in a different, not reliably comparable
shape - confirmed by reading pywintrace's source: every ETW field is
decoded through TdhFormatProperty, and TDH_OUTTYPE_DATETIME (the out-type
for a FILETIME field like CreateTime) has no entry in tdh.py's
TDH_CONVERTER_LOOKUP, so it comes back as a locale-formatted datetime
*string*, not a number - while Sysmon's UtcTime is a same-process fixed
format but a different one. Rounding-and-comparing two unverified string
formats across sensors would either crash outright or silently fail to
match. Keying on pid alone, with a per-pid `first_seen` timer that bounds
how long a pending record waits before GC, correlates two near-simultaneous
arrivals for the same real process correctly and needs no cross-sensor
timestamp parsing at all. This accepts the same order-of-magnitude
PID-reuse race window (bounded by fuse_window, default 2s) that
heuristic_engine.py's _reset_score_if_pid_reused already documents as a
known, accepted edge case elsewhere in this codebase - a PID reused by an
unrelated process *within* fuse_window of the first process's exit could
wrongly fuse; a PID reused after GC has already popped the record (the
common case, one full fuse_window later) correctly starts a fresh record.
"""

import logging
import threading
import time

DEFAULT_FUSE_WINDOW_SECONDS = 2.0
DEFAULT_GC_INTERVAL_SECONDS = 5


def _normalize_pid(pid):
    """Canonicalizes a pid to int for use as _pending's dict key and as
    _dedup_key. Found necessary during evasion-matrix testing (reports/
    evasion_matrix.md), one level deeper than the missing-_dedup_key bug
    that testing also found on submit_kernel (fixed separately, below):
    the THREE sensors hand this correlator inconsistent Python types for
    the exact same real numeric pid.

    - kernel_sensor.py's struct.unpack always gives a genuine int.
    - HeuristicEngine.evaluate_event()'s XML parsing reads 'ProcessId'
      straight from an ElementTree Data element's .text - always a str,
      never cast.
    - etw_monitor.py's pywintrace-decoded 'ProcessID' LOOKS like it should
      be an int (tdh.py's TDH_CONVERTER_LOOKUP maps the UNSIGNEDINT out-
      type to int()) but isn't in practice: etw.py's own conversion site
      only calls that converter when `type(data) == int` already - a
      no-op precondition, since TdhFormatProperty itself returns a
      formatted str, so the "conversion" to int never actually fires.
      Confirmed by reading etw/etw.py's _parseExtendedData in this
      project's own .venv.

    Without normalizing, int 1234 and str '1234' are different dict
    keys - two _pending records for the SAME real process that never
    fuse (silently reverting every process-create to two independent
    etw-provisional + sysmon-only dispatches instead of one fused one,
    and skipping _check_ancestry_contradiction entirely for that pid),
    and two separate _score_once dedup buckets that never dedupe each
    other. In practice ETW and Sysmon's values happen to both be str
    today (so ETW/Sysmon fusion mostly still works, by accident, riding
    on pywintrace's own bug above - fragile, not something to rely on),
    while the kernel sensor's genuine int never matched either of them -
    confirmed live: a kernel-observed process also matching a
    Sysmon-only rule (e.g. staging_dir) was scored twice even after
    submit_kernel's _dedup_key fix, because int 1234 != str '1234'."""
    try:
        return int(pid)
    except (TypeError, ValueError):
        return pid  # unparseable - preserve old (also-broken) behavior rather than guess


class ProcessCorrelator:
    def __init__(self, engine, fuse_window=DEFAULT_FUSE_WINDOW_SECONDS, gc_interval=DEFAULT_GC_INTERVAL_SECONDS):
        self.engine = engine
        self.fuse_window = fuse_window
        self.gc_interval = gc_interval
        self._lock = threading.Lock()
        # key -> {'etw': {...} or None, 'sysmon': {...} or None, 'first_seen': monotonic}
        self._pending = {}

    def submit_etw(self, pid, parent_pid, image_name, create_time):
        """ETW's fields arrive first (it's the faster sensor) - dispatch a
        provisional finding immediately, unconditionally, so latency never
        waits on Sysmon. Also record it so a same-pid Sysmon arrival within
        fuse_window can be merged into a richer, fused dispatch by the GC."""
        pid_key = _normalize_pid(pid)
        fields = {
            'ProcessId': pid,
            'ParentProcessId': parent_pid,
            'Image': image_name,
            'CreateTime': create_time,
        }
        with self._lock:
            record = self._pending.setdefault(pid_key, {'etw': None, 'sysmon': None, 'first_seen': time.monotonic()})
            record['etw'] = fields

        self.engine._dispatch(1, {
            **fields,
            'ParentImage': None,
            'CommandLine': None,
            '_source': 'etw',
            '_provisional': True,
            '_dedup_key': pid_key,
        })

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
        self.engine._dispatch(1, {
            'ProcessId': pid,
            'ParentProcessId': claimed_parent_pid,
            'Image': image_name,
            'ParentImage': None,
            'CommandLine': None,
            '_source': 'kernel',
            '_kernel_real_creator_pid': real_creator_pid,
            '_kernel_ppid_spoof_detected': bool(ppid_spoof_detected),
            '_dedup_key': _normalize_pid(pid),
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
