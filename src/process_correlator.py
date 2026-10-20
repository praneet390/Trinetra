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
        fields = {
            'ProcessId': pid,
            'ParentProcessId': parent_pid,
            'Image': image_name,
            'CreateTime': create_time,
        }
        with self._lock:
            record = self._pending.setdefault(pid, {'etw': None, 'sysmon': None, 'first_seen': time.monotonic()})
            record['etw'] = fields

        self.engine._dispatch(1, {
            **fields,
            'ParentImage': None,
            'CommandLine': None,
            '_source': 'etw',
            '_provisional': True,
            '_dedup_key': pid,
        })

    def submit_sysmon(self, data_dict, create_time):
        """Sysmon's fields arrive second (richer, slower). Not dispatched
        immediately - recorded so the GC can give a same-pid ETW arrival
        its fuse_window chance to merge first."""
        pid = data_dict.get('ProcessId')
        with self._lock:
            record = self._pending.setdefault(pid, {'etw': None, 'sysmon': None, 'first_seen': time.monotonic()})
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
