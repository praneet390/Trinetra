"""
Active process/module provenance sweep: where telemetry_monitor.py is passive/event-driven,
this periodically walks the live process table and inspects already-mapped modules, catching
injection that loaded before monitoring started or outside Sysmon config.

Maintains bounded first-seen ledgers for two evidence types:
- Suspicious-path modules: records when THIS agent first observed the module, so a module
  flagged after days of quiet residence reports its true dwell, not time-since-flagging.
- Anonymous executable memory regions: dwell clock starts when the region first became
  executable (not when it happened to be RWX at sweep time), because the stealth shape is
  VirtualAlloc(RW) -> write -> VirtualProtect(RX), so the region is never RWX at rest.
  RX-only regions are tracked but never scored; JIT runtimes keep anonymous RX pages
  legitimately and scoring them outright would flood the feed.
"""

import logging
import time
from collections import OrderedDict

import psutil

# Staging paths a legitimate DLL should never load from. ProgramData was here
# but live-fire testing hit three legit cases in one run (Defender DLLs,
# VS installer, Windows Terminal MSIX proxy) - removed rather than allowlisting every vendor.
SUSPICIOUS_MODULE_DIRS = (
    '\\appdata\\local\\temp\\',
    '\\windows\\temp\\',
    '\\users\\public\\',
    '\\recycle.bin\\',
)

HIGH_VALUE_TARGETS = (
    'svchost.exe', 'explorer.exe', 'lsass.exe', 'spoolsv.exe',
    'taskhostw.exe', 'winlogon.exe', 'services.exe', 'dwm.exe',
)

# LRU-bounded ledgers (least-recently-observed evicted first).
MAX_DWELL_ENTRIES = 5000
MAX_REGION_LEDGER_ENTRIES = 4000

# Linux psutil names anonymous mappings; Windows reports them as empty paths.
ANONYMOUS_PATH_PREFIXES = ('[anon', '[heap]', '[stack]')


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


def _is_anonymous_path(path):
    """True when a memory map's path says the region has NO file backing.
    Windows psutil reports private/anonymous regions as an empty path;
    Linux psutil names them '[anon]', '[anon:...]', '[heap]', '[stack]'.
    Both are the same forensic fact: nothing on disk produced this memory.
    """
    if not path:
        return True  # Windows: pathless == MEM_PRIVATE / anonymous
    return path.startswith(ANONYMOUS_PATH_PREFIXES)


def _region_perms(mapping):
    """Lowercase rwx-style permission string for a memory map, tolerating
    maps that carry no perms field (psutil's namedtuple layouts differ per
    platform; 'perms' is present on both Windows and Linux, but tests and
    future psutil versions are not bound to that)."""
    return (getattr(mapping, 'perms', '') or '').lower()


def _region_addr(mapping):
    """Stable per-region identity within a process: the map's start address
    as psutil reports it (hex string on Windows, 'start-end' range on
    Linux). Combined with the PID it forms the dwell ledger key - the same
    allocation keeps the same key across sweeps, which is exactly what
    makes 'how long has this region been here' measurable."""
    return getattr(mapping, 'addr', None)


def _region_size(mapping):
    """Region size in bytes when the platform exposes one (Windows psutil
    carries 'bsize'; Linux's richer namedtuple does not - None there, and
    the finding simply omits the size rather than inventing it)."""
    return getattr(mapping, 'bsize', None)


class ModuleInspector:
    def __init__(self, engine, clock=time.time):
        self.engine = engine
        self._seen = set()
        # First-seen is recorded on first sighting, before any flagging, so dwell
        # is true residency. Clock is injectable for deterministic tests.
        self._first_seen = OrderedDict()
        self._clock = clock
        self.dwell_by_module = {}
        self._region_first_seen = OrderedDict()
        self._seen_regions = set()
        self.dwell_by_region = {}

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
                # Not a file-backed DLL - but it may still be an anonymous
                # region worth dwell-tracking (the shellcode case). Fall
                # through to the anonymous-region check before skipping.
                if _is_anonymous_path(path):
                    self._observe_anonymous_region(pid, name, m)
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
            # Refresh LRU recency only; first-seen is evidence and must not reset.
            self._first_seen.move_to_end(key)

        dwell_seconds = now - self._first_seen[key]
        dwell_human = _humanize_dwell(dwell_seconds)
        self.dwell_by_module[key] = {
            'first_seen': self._first_seen[key],
            'dwell_seconds': round(dwell_seconds, 1),
            'dwell_human': dwell_human,
            # Bounds, but does not equal, true load time (agent may have started late).
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

    def _observe_anonymous_region(self, pid, name, mapping):
        """Track first-seen (and flag, when shellcode-shaped) one anonymous
        memory region observed in `pid`.

        Ordering is load-bearing: first-seen ledger updated BEFORE the flag
        decision, dwell refreshed on every sighting - measured residency, not
        time-since-flagging. Only RWX regions are scored; writability separates
        shellcode (needs a write stage) from legitimate JIT code pages (RX only).
        """
        perms = _region_perms(mapping)
        if 'x' not in perms:
            # Non-executable regions would exhaust the bounded ledger for no finding.
            return
        addr = _region_addr(mapping)
        if addr is None:
            # No stable identity, so dwell figures would be garbage.
            return

        key = (pid, addr)
        now = self._clock()

        if key not in self._region_first_seen:
            self._region_first_seen[key] = now
            self._region_first_seen.move_to_end(key)
            while len(self._region_first_seen) > MAX_REGION_LEDGER_ENTRIES:
                self._region_first_seen.popitem(last=False)
        else:
            self._region_first_seen.move_to_end(key)

        dwell_seconds = now - self._region_first_seen[key]
        size_bytes = _region_size(mapping)
        self.dwell_by_region[key] = {
            'first_seen': self._region_first_seen[key],
            'dwell_seconds': round(dwell_seconds, 1),
            'dwell_human': _humanize_dwell(dwell_seconds),
            'dwell_source': 'agent_first_observation',
            'addr': addr,
            'perms': perms,
            'size_bytes': size_bytes,
        }

        if 'w' not in perms:
            return  # executable, anonymous, but read-only: JIT-shaped, not flagged

        if key in self._seen_regions:
            return
        self._seen_regions.add(key)

        is_high_value = name in HIGH_VALUE_TARGETS
        score = 60 if is_high_value else 35
        size_text = f" ({size_bytes} bytes)" if size_bytes else ''
        context = (
            f"{'High-value target' if is_high_value else 'Process'} "
            f"'{name}' (PID {pid}) has shellcode-style anonymous RWX memory region "
            f"at {addr}{size_text} - resident for {_humanize_dwell(dwell_seconds)}"
        )
        logging.warning(f"[MEMORY] {context}")
        self.engine._add_score(pid, score, context, check_id='anonymous_rwx_region')

    def memory_region_dwell(self, pid=None):
        """Dwell ledger access for anonymous memory regions - the read side
        of the Attacker Dwell Time Calculator. With `pid`, returns just that
        process's region records; with None, everything. Sorted oldest-first
        by first-seen so the longest-resident regions - the ones most
        consistent with a pre-existing implant, as opposed to something the
        current session just spawned - read first."""
        rows = [
            {
                'pid': k_pid,
                **entry,
            }
            for (k_pid, k_addr), entry in self.dwell_by_region.items()
            if pid is None or k_pid == pid
        ]
        rows.sort(key=lambda r: r['first_seen'])
        return rows
