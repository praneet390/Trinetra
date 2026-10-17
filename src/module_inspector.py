"""
Active process/module provenance sweep, inspired by System Informer's
process/module enumeration view (winsiderss/systeminformer): where the
Sysmon-driven telemetry_monitor.py is passive/event-driven, this module
periodically walks the *current* process table and inspects what's already
mapped into each process, catching injected modules that loaded before
monitoring started or that Sysmon config doesn't cover.

Dwell time (new): the sweep is also the agent's only direct witness of
*when a suspicious thing first appeared*, so it maintains bounded
first-seen ledgers for both kinds of evidence it observes:

1. MODULE RESIDENCY - every suspicious-path module it observes. When a
   module is flagged, the finding reports how long that module has been
   resident - evidence-derived ("we first saw it N ago on this host"), not
   a guess from log timestamps. A module first seen 18 days ago and flagged
   today yields an honest 18-day dwell figure; nothing more is invented
   about what happened before the agent started (that limitation is
   stated, not hidden, by the dwell source field).

2. ANONYMOUS MEMORY REGIONS (the Attacker Dwell Time Calculator) - every
   EXECUTABLE anonymous (file-backing-free) region in every process it
   sweeps. Anonymous executable memory is where shellcode lives: there is
   no file, no module, no on-disk artifact - just private memory marked
   executable (Windows MEM_PRIVATE + PAGE_EXECUTE_*; psutil reports those
   as pathless maps with 'x' perms on both Windows and Linux). For each
   such region the ledger records the wall-clock time THIS agent first
   observed it, before the region is ever flagged, so the age reported
   when a detection fires is measurement, not reconstruction: shellcode
   caught in a region first seen eighteen days ago reports an 18-day dwell
   figure mathematically derived from the ledger (now - first_seen), which
   is the form that survives a legal proceeding - the provenance of the
   number is the agent's own observation record, not a log-timestamp
   inference.

   WHY TRACK EVERY EXECUTABLE ANON REGION, NOT JUST RWX ONES: a region's
   protection is not static. The classic stealth shape is VirtualAlloc
   (RW, no execute) -> write shellcode -> VirtualProtect to RX before
   jumping to it, so the region is never RWX while the agent happens to be
   looking. First-seening every executable anon region on sight means the
   dwell clock starts when the region first became a shellcode candidate,
   not when it happened to be RWX at sweep time.

   WHY RX-ALONE IS TRACKED BUT NEVER FLAGGED: modern JIT runtimes (V8,
   .NET, the JVM) legitimately keep anonymous RX code pages at rest, so
   flagging executable-anonymous regions outright would drown the finding
   in false positives within one sweep of a normal desktop. Only the
   shellcode-shaped combination - anonymous AND writable AND executable
   (RWX) - is scored, and the flag reports the region's age from the
   ledger. This is the same documented-tradeoff spirit as
   SUSPICIOUS_MODULE_DIRS below.
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

# Bound on the anonymous-memory-region first-seen ledger (the Attacker
# Dwell Time Calculator's store). Every executable anonymous region on the
# host gets one entry per (pid, address) - a normal desktop carries a few
# thousand executable JIT/anon regions across all processes, so 4000 is a
# workable ceiling that keeps the sweep O(host) rather than unbounded, with
# the same least-recently-RE-observed eviction discipline as the module
# ledger above (long-gone processes evict first).
MAX_REGION_LEDGER_ENTRIES = 4000

# Linux psutil names its anonymous mappings; Windows psutil reports them
# as empty paths. Both shapes mean the same thing forensically: NO file
# backs this memory, so there is no on-disk artifact, no signature to scan
# and no module to attribute - the shellcode-detection problem in one
# tuple. '[heap]'/'[stack]' are included: they are anonymous mappings too
# (no file backing), and neither is ever executable in practice, so
# including them costs ledger space only in the rare degenerate case.
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
        # ---- Attacker Dwell Time Calculator (anonymous memory regions) ----
        # (pid, region_addr) -> wall-clock time this agent FIRST observed
        # the executable anonymous region. Recorded for EVERY executable
        # anon region on its first sighting - BEFORE any flagging decision
        # - so a region that sat quiet for days before becoming RWX (the
        # alloc-RW/write/reprotect-RX stealth shape) still reports its true
        # age, not age-since-it-looked-suspicious. Same injectable-clock
        # determinism as the module ledger above.
        self._region_first_seen = OrderedDict()
        # (pid, region_addr) pairs already scored, so a repeated sweep
        # doesn't re-flag (and re-mitigate-threshold) the same region.
        self._seen_regions = set()
        # (pid, region_addr) -> dwell record for anonymous regions,
        # refreshed on EVERY sighting so API consumers always see current
        # residency. Same init-eagerly discipline as dwell_by_module.
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

    # ------------------------------------------------------------------
    # Attacker Dwell Time Calculator: anonymous executable memory regions.
    # ------------------------------------------------------------------
    def _observe_anonymous_region(self, pid, name, mapping):
        """Track first-seen (and flag, when shellcode-shaped) one anonymous
        memory region observed in `pid`.

        Ordering mirrors _handle_suspicious_module and is load-bearing for
        the same reason: the first-seen ledger is updated BEFORE the flag
        decision, and the dwell record is refreshed on EVERY sighting - so
        a region's reported age is measured residency, never
        time-since-flagging, and the ledger keeps accumulating honestly
        even for regions that never get flagged (RX-at-rest JIT pages sit
        in the ledger as benign reference points).

        Detection contract (deliberately narrow - see module docstring):
        only anonymous AND writable AND executable (RWX) regions are
        scored. Writability is what makes anonymous executable memory an
        active threat rather than a JIT code page: shellcode needs its
        stage written (self-modifying decoders, downloaded second stage,
        injected blobs from a parent process) before it can run.
        """
        perms = _region_perms(mapping)
        if 'x' not in perms:
            # Not executable -> not shellcode territory, not monitored.
            # Tracking every anonymous heap/stack region would exhaust the
            # bounded ledger with entries that can never produce a finding.
            return
        addr = _region_addr(mapping)
        if addr is None:
            # psutil variant without an address field: no stable identity,
            # so no ledger entry is possible - an unidentifiable region
            # would make dwell figures garbage (two sweeps could conflate
            # different regions). Skip honestly rather than guess.
            return

        key = (pid, addr)
        now = self._clock()

        if key not in self._region_first_seen:
            self._region_first_seen[key] = now
            self._region_first_seen.move_to_end(key)
            while len(self._region_first_seen) > MAX_REGION_LEDGER_ENTRIES:
                self._region_first_seen.popitem(last=False)
        else:
            # Re-observed: refresh eviction recency WITHOUT touching the
            # first-seen value - identical discipline to the module ledger,
            # because conflating 'last seen' with 'first seen' would reset
            # every dwell figure on every sweep.
            self._region_first_seen.move_to_end(key)

        # Refresh the dwell record on every sighting so API consumers see
        # current residency. This is the Attacker Dwell Time Calculator's
        # output: age = now - first_seen, both measured by this agent.
        dwell_seconds = now - self._region_first_seen[key]
        size_bytes = _region_size(mapping)
        self.dwell_by_region[key] = {
            'first_seen': self._region_first_seen[key],
            'dwell_seconds': round(dwell_seconds, 1),
            'dwell_human': _humanize_dwell(dwell_seconds),
            # Same honest provenance as the module ledger: the clock starts
            # when THIS agent first observed the region, which bounds - but
            # does not equal - the region's true age (the agent may have
            # started late). Stating the source keeps the figure defensible
            # instead of overclaimed.
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
