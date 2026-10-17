"""
Active process/module provenance sweep, inspired by System Informer's
process/module enumeration view (winsiderss/systeminformer): where the
Sysmon-driven telemetry_monitor.py is passive/event-driven, this module
periodically walks the *current* process table and inspects what's already
mapped into each process, catching injected modules that loaded before
monitoring started or that Sysmon config doesn't cover.

Dwell time (new): the sweep is also the agent's only direct witness of
*when a suspicious module first appeared*, so it maintains a bounded
first-seen ledger for every suspicious-path module it observes. When a
module is flagged, the finding reports how long that module has been
resident - evidence-derived ("we first saw it N ago on this host"), not a
guess from log timestamps. A module first seen 18 days ago and flagged
today yields an honest 18-day dwell figure; nothing more is invented about
what happened before the agent started (that limitation is stated, not
hidden, by the dwell source field).
"""

import logging
import time
from collections import OrderedDict

import psutil

# Paths a legitimate, unpacked DLL should basically never load from.
# Modules mapped into a process from here are consistent with a dropper
# staging a payload and DLL-injecting/side-loading it into a running
# process, rather than a compiler-emitted, installed dependency.
#
# ProgramData was in this list originally but live-fire testing pulled it
# in three unrelated legitimate cases in a single run (Windows Defender's
# own platform DLLs, Visual Studio's installer component, and Windows
# Terminal's MSIX AppRepository packaged-COM proxy DLL - the last one even
# crossed the WARNING threshold). Unlike Temp/Public, ProgramData is
# routinely and legitimately used by installers, MSIX package machinery,
# and OEM vendor software for exactly this kind of shared component, so it
# isn't a good staging-directory signal on its own - dropped rather than
# chasing an endless per-vendor allowlist.
SUSPICIOUS_MODULE_DIRS = (
    '\\appdata\\local\\temp\\',
    '\\windows\\temp\\',
    '\\users\\public\\',
    '\\recycle.bin\\',
)

# System processes worth extra scrutiny if they carry modules from the
# paths above - these are exactly the "living off the land" hollowing/
# injection targets Fibratus's defense-evasion rules watch (svchost.exe,
# explorer.exe, lsass.exe, spoolsv.exe, taskhostw.exe, etc).
HIGH_VALUE_TARGETS = (
    'svchost.exe', 'explorer.exe', 'lsass.exe', 'spoolsv.exe',
    'taskhostw.exe', 'winlogon.exe', 'services.exe', 'dwm.exe',
)

# Bound on the first-seen dwell ledger: one entry per suspicious-path
# (pid, module) pair this agent has EVER observed. Suspicious-path modules
# are rare on a healthy host, so a few thousand entries is generous; the
# OrderedDict LRU eviction keeps a pathological host from growing this
# without limit, evicting the least-recently-RE-observed pair first (the
# ones whose processes are almost certainly long gone).
MAX_DWELL_ENTRIES = 5000


def _humanize_dwell(seconds):
    """'18d 3h 4m'-style rendering for module residency. Seconds granularity
    is deliberately dropped: a sweep runs every 30s, so anything finer than
    a minute is sweep-timer noise, not measurement."""
    seconds = max(0, int(seconds))
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes = rem // 60
    if days:
        return f"{days}d {hours}h {minutes}m"
    if hours:
        return f"{hours}h {minutes}m"
    return f"{minutes}m"


class ModuleInspector:
    def __init__(self, engine, clock=time.time):
        self.engine = engine
        # (pid, module_path) pairs already scored, so a repeated sweep
        # doesn't re-flag (and re-mitigate-threshold) the same finding.
        self._seen = set()
        # (pid, module_path) -> wall-clock time this agent FIRST observed
        # the module resident. Recorded for every suspicious-path module on
        # its very first sweep sighting - BEFORE it is ever flagged - so a
        # module observed benign-looking for days and flagged later reports
        # its true residency, not just "since it got flagged". The clock is
        # injectable so tests can age entries deterministically.
        self._first_seen = OrderedDict()
        self._clock = clock
        # (pid, module_path) -> dwell record, populated when a module is
        # first FLAGGED (see _handle_suspicious_module). Initialized here,
        # not lazily, so the API accessor never depends on call order.
        self.dwell_by_module = {}

    def sweep(self):
        for proc in psutil.process_iter(['pid', 'name', 'exe']):
            try:
                self._inspect_process(proc)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    def _inspect_process(self, proc):
        pid = proc.info['pid']
        name = (proc.info['name'] or '').lower()

        try:
            maps = proc.memory_maps()
        except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
            return

        for m in maps:
            path = (m.path or '').lower()
            if not path or not path.endswith('.dll'):
                continue

            if any(bad_dir in path for bad_dir in SUSPICIOUS_MODULE_DIRS):
                self._handle_suspicious_module(pid, name, path)

    def _handle_suspicious_module(self, pid, name, path):
        """Track dwell for (and flag once) one suspicious-path module.

        Ordering is load-bearing: the first-seen ledger is updated BEFORE
        the dedup check, and the dwell record is refreshed on EVERY
        sighting (not just the flagged one) - so the API always reports the
        module's current residency, while the score itself stays exactly
        once-per-module to avoid re-mitigating a known finding every 30s."""
        key = (pid, path)
        now = self._clock()

        if key not in self._first_seen:
            self._first_seen[key] = now
            self._first_seen.move_to_end(key)
            while len(self._first_seen) > MAX_DWELL_ENTRIES:
                self._first_seen.popitem(last=False)
        else:
            # Re-observed alive on this sweep: refresh LRU recency WITHOUT
            # touching the first-seen value - recency is about eviction,
            # first-seen is about evidence, and conflating them would
            # quietly reset every dwell figure on every sweep.
            self._first_seen.move_to_end(key)

        # Refresh the dwell record on every sighting so the dashboard/API
        # shows current residency, not a stale snapshot from flag time.
        dwell_seconds = now - self._first_seen[key]
        dwell_human = _humanize_dwell(dwell_seconds)
        self.dwell_by_module[key] = {
            'first_seen': self._first_seen[key],
            'dwell_seconds': round(dwell_seconds, 1),
            'dwell_human': dwell_human,
            # Honest provenance for the dwell figure: it starts when THIS
            # agent first observed the module, which bounds - but does not
            # equal - the module's true load time (the agent may have
            # started late). Stating the source keeps the number defensible
            # instead of overclaimed.
            'dwell_source': 'agent_first_observation',
        }

        if key in self._seen:
            return
        self._seen.add(key)

        is_high_value = name in HIGH_VALUE_TARGETS
        score = 60 if is_high_value else 35
        context = (
            f"{'High-value target' if is_high_value else 'Process'} "
            f"'{name}' (PID {pid}) has module loaded from staging path: {path} "
            f"- resident for {dwell_human}"
        )
        logging.warning(f"[MODULE] {context}")
        self.engine._add_score(pid, score, context, check_id='module_staging')

    def module_dwell(self, pid=None):
        """Dwell ledger access for the dashboard/API. With `pid`, returns
        just that process's entries (matched by the pid half of the key);
        with None, returns everything. Sorted oldest-first by first-seen
        time so long-resident modules - the interesting ones - read first."""
        rows = [
            {
                'pid': k_pid,
                'module_path': k_path,
                **entry,
            }
            for (k_pid, k_path), entry in self.dwell_by_module.items()
            if pid is None or k_pid == pid
        ]
        rows.sort(key=lambda r: r['first_seen'])
        return rows
