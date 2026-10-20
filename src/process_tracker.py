"""
In-memory parent/child process lineage + FULL ANCESTRY tracker.

Two capabilities live in this module, one data structure:

1. LINEAGE (original capability, Velociraptor's process-tracker pattern,
   simplified): built incrementally from ProcessCreate events, resolving a
   PID's ancestor chain by PID linkage (ParentProcessId) rather than by
   parent image path. Feeds the web dashboard's Process Explorer "Lineage"
   column via lineage_string(). Purely additive and display-only.

2. ANCESTRY GRAPH (new): the same parent/child map, but resolved into
   full evidence records instead of a display string. For every node in a
   process's ancestry it captures - when the data exists -
   PID, PPID, image path, command line, user, spawn time, the time this
   agent first observed it, and (best-effort, live processes only) its
   environment variables. Every parent->child edge is labeled with the
   observation that connects the two (EXEC for a process-create link),
   which is the reconstruction side of "the syscall that connected each
   parent to child is labeled on the edge".

WHY BOTH SHARE ONE STRUCTURE: the lineage column and the ancestry snapshot
are the same graph at two fidelity levels. Splitting them would mean two
trackers silently drifting out of sync; instead, lineage_string() is a thin
projection of the same records get_ancestry() walks.

DESIGN NOTES
------------
- Records are built from whatever the event source carries. Sysmon Event ID 1
  is rich (CommandLine, User, ParentImage); raw ETW ProcessStart is thin
  (PID/PPID/Image/CreateTime only - see etw_monitor.py). Missing fields are
  stored as None, never guessed: an ancestry node with command_line=None is
  an honest "ETW-only observation", not a bug.
- Environment variables are read LAZILY, only when get_ancestry() is asked
  for them (include_env=True), and only for processes that are still alive:
  a process's environment lives in its address space, and once the process
  exits it is unrecoverable. The result is cached per-PID (an env block
  doesn't meaningfully change after startup), the cache is bounded, and any
  psutil error (AccessDenied on protected/elevated processes, NoSuchProcess
  on dead ones) degrades to env_vars=None plus a human-readable env_note -
  an ancestry node must never fail to build because one ancestor was locked.
- Bounded memory throughout: process entries and the env cache both evict
  least-recently-updated entries past their caps, same ring-buffer spirit
  as AlertStore/ProcessActivityStore in web_server.py.
- Purely additive and display-only - never scores anything, never touches
  HeuristicEngine scoring. The ENGINE decides when an ancestry snapshot is
  forensic evidence (see heuristic_engine._capture_forensic_snapshot); this
  module only answers questions when asked.
"""

import os
import time
from collections import OrderedDict

import psutil

DEFAULT_MAX_ENTRIES = 2000
DEFAULT_MAX_DEPTH = 10
# Bound on the lazily-populated environment-variable cache. A live desktop
# can have hundreds of processes; only ones that ever appear in an ancestry
# query ever get an entry, so a few hundred entries is already generous.
DEFAULT_MAX_ENV_CACHE = 512


def _process_environ(pid):
    """Read one live process's environment variables via psutil.

    Isolated at module level so tests can monkeypatch it without spinning
    real OS processes. Callers must treat this as BEST-EFFORT: it raises for
    exited processes (NoSuchProcess) and for processes this account cannot
    open (AccessDenied - elevated/protected processes on Windows), and both
    are normal, expected outcomes that get_ancestry() reports honestly
    instead of hiding."""
    return psutil.Process(pid).environ()


def _humanize_age(seconds):
    """'18d 4h 12m'-style age rendering for first-seen timestamps."""
    seconds = max(0, int(seconds))
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes = rem // 60
    if days:
        return f"{days}d {hours}h {minutes}m"
    if hours:
        return f"{hours}h {minutes}m"
    return f"{minutes}m"


class ProcessTracker:
    def __init__(self, max_entries=DEFAULT_MAX_ENTRIES, max_env_cache=DEFAULT_MAX_ENV_CACHE):
        self.max_entries = max_entries
        # pid -> evidence record. See add() for the record shape. OrderedDict
        # so a bounded eviction can drop the least-recently-updated entry
        # first, same "bounded ring buffer" spirit as AlertStore/
        # ProcessActivityStore in web_server.py.
        self._entries = OrderedDict()
        # pid -> environment-variable dict, populated lazily by
        # get_ancestry(include_env=True). Bounded separately from the
        # process records because env blocks are large (hundreds of vars).
        self._env_cache = OrderedDict()
        self.max_env_cache = max_env_cache

    # ------------------------------------------------------------------
    # Ingestion - one fan-in point for every ProcessCreate observation,
    # whichever sensor delivered it (Sysmon Event ID 1, the correlator's
    # fused dispatch, or an ETW-only provisional dispatch).
    # ------------------------------------------------------------------
    def add(self, event_id, data):
        """Record one ProcessCreate observation. Event IDs other than 1
        (ProcessCreate) are ignored - this tracker is a process-tree map,
        not a general event log. Fields the sensor didn't carry are stored
        as None: an ETW-only dispatch has no CommandLine, and pretending
        otherwise would poison the ancestry evidence."""
        if event_id != 1:  # ProcessCreate only
            return
        try:
            pid = int(data.get('ProcessId', 0))
        except (TypeError, ValueError):
            return

        ppid_raw = data.get('ParentProcessId')
        try:
            ppid = int(ppid_raw) if ppid_raw is not None else None
        except (TypeError, ValueError):
            ppid = None

        # Spawn time: prefer the OS-provided creation timestamp (ETW carries
        # CreateTime; Sysmon's UtcTime is the event's own timestamp, close
        # enough to spawn for ancestry-display purposes and the best Sysmon
        # offers). Stored raw - the two sources use different formats, and
        # this module renders rather than computes on it.
        spawn_time = data.get('CreateTime') or data.get('UtcTime')

        # Update-in-place on re-observation: a PID seen first via thin ETW
        # and then via rich Sysmon (the correlator's provisional->fused
        # sequence) ends up with the richer record. Per-field fill-in, so
        # the fused dispatch upgrades exactly the fields it actually has
        # instead of clobbering known values with None.
        existing = self._entries.get(pid)
        if existing is None:
            record = {
                'image': data.get('Image'),
                'ppid': ppid,
                'ts': time.time(),  # first-seen by this agent (wall clock)
                'command_line': data.get('CommandLine'),
                'user': data.get('User'),
                'spawn_time': spawn_time,
                'source': data.get('_source', 'sysmon'),
            }
            self._entries[pid] = record
        else:
            # First-seen time (`ts`) is deliberately NOT refreshed on
            # re-observation: it records when this agent first saw the
            # process, which is exactly the dwell-time anchor downstream
            # consumers want. Everything else may upgrade in place. Note
            # the source-key mapping: record fields are lowercase, but the
            # event data keys are the Sysmon-style originals - using the
            # lowercase names here would silently find nothing and leave
            # every ETW-first record permanently thin (caught by
            # test_thin_etw_dispatch_upgraded_by_rich_sysmon_later).
            upgrade_sources = {
                'image': data.get('Image'),
                'command_line': data.get('CommandLine'),
                'user': data.get('User'),
                'spawn_time': data.get('CreateTime') or data.get('UtcTime'),
            }
            for field, new_value in upgrade_sources.items():
                if new_value is not None and existing.get(field) is None:
                    existing[field] = new_value
            if existing.get('ppid') is None and ppid is not None:
                existing['ppid'] = ppid
            # Richer source wins for display (fused > etw > sysmon alone is
            # not strictly ordered, so just prefer the fused label, which
            # by construction carries the most fields).
            if data.get('_source') == 'fused':
                existing['source'] = 'fused'
            self._entries.move_to_end(pid)

        while len(self._entries) > self.max_entries:
            self._entries.popitem(last=False)

    # ------------------------------------------------------------------
    # Resolution - two projections of the same parent/child map.
    # ------------------------------------------------------------------
    def get_chain(self, pid, max_depth=DEFAULT_MAX_DEPTH):
        """Image names from the oldest known ancestor down to `pid` itself
        (inclusive), stopping at an untracked ancestor, a cycle, or
        max_depth. Empty list if `pid` itself was never observed.

        Backward-compatible projection: the dashboard's Lineage column and
        the engine's compact chain-summary log line both consume this."""
        chain = []
        current = pid
        seen = set()
        for _ in range(max_depth):
            if current is None or current in seen:
                break
            seen.add(current)
            entry = self._entries.get(current)
            if entry is None:
                break
            chain.append(entry['image'] or f'pid:{current}')
            current = entry['ppid']
        chain.reverse()
        return chain

    def lineage_string(self, pid, max_depth=DEFAULT_MAX_DEPTH):
        """'explorer.exe -> cmd.exe -> evil.exe'-style summary for display,
        basenames only (full paths would make the dashboard column
        unreadably wide). Uses a separator-aware basename (Windows paths
        use backslashes; this must render correctly wherever the dashboard
        code runs, so split on BOTH separators rather than trusting
        os.sep)."""
        names = [self._short_name(c) for c in self.get_chain(pid, max_depth=max_depth)]
        return ' -> '.join(names)

    def get_ancestry(self, pid, max_depth=DEFAULT_MAX_DEPTH, include_env=False):
        """FULL ancestry evidence for `pid`: every known ancestor from the
        oldest down to the process itself, as node records, plus the
        labeled edges that connect them.

        Returns:
            {
              'pid': <pid>,
              'nodes': [ node, ... oldest-first, child LAST ],
              'edges': [ {'from': <ppid>, 'to': <child pid>, 'label': 'EXEC'}, ... ],
              'incomplete': <bool>  - True when the walk stopped early
                                     (untracked ancestor / cycle / depth cap),
                                     so consumers never mistake a partial
                                     chain for a complete one.
            }
            None if `pid` itself was never observed.

        Edge labels: every parent->child link in this tracker comes from a
        ProcessCreate observation, so the honest label is 'EXEC' (the
        creating syscall family). Injection-style connections (a process
        OPENING another process's memory) are not parentage and are labeled
        by the engine's forensic snapshot instead - see
        heuristic_engine._capture_forensic_snapshot's trigger_edge.

        include_env=True additionally best-effort-reads each still-alive
        ancestor's environment block (see _process_environ). Dead ancestors
        get env_vars=None + env_note explaining why - environment is process
        memory, unrecoverable after exit."""
        if pid not in self._entries:
            return None

        nodes = []
        edges = []
        current = pid
        seen = set()
        incomplete = False

        # Walk child -> oldest ancestor collecting nodes, then reverse so
        # the list reads oldest-first (attack chains read top-down).
        while True:
            if current is None or current in seen:
                incomplete = current is not None  # None = clean stop at root
                break
            seen.add(current)
            entry = self._entries.get(current)
            if entry is None:
                incomplete = True  # untracked ancestor: chain is partial
                break

            node = {
                'pid': current,
                'ppid': entry.get('ppid'),
                'image': entry.get('image'),
                'command_line': entry.get('command_line'),
                'user': entry.get('user'),
                'spawn_time': entry.get('spawn_time'),
                'first_seen': entry.get('ts'),
                'alive': self._is_alive(current),
                'env_vars': None,
                'env_note': None,
            }
            if include_env:
                node['env_vars'], node['env_note'] = self._env_for(current)
            nodes.append(node)

            parent = entry.get('ppid')
            if parent is None:
                break  # tracked root with no known parent - a complete chain
            edges.append({'from': parent, 'to': current, 'label': 'EXEC'})
            if len(seen) >= max_depth:
                incomplete = True
                break
            current = parent

        nodes.reverse()
        edges.reverse()
        return {'pid': pid, 'nodes': nodes, 'edges': edges, 'incomplete': incomplete}

    def chain_summary(self, pid, max_depth=DEFAULT_MAX_DEPTH):
        """Compact human-readable chain for log lines and forensic
        snapshots: 'a.exe -> b.exe -> evil.exe' with a '(partial)' suffix
        when the walk could not reach a tracked root. Basenames via the
        separator-aware shortener, same as lineage_string()."""
        ancestry = self.get_ancestry(pid, max_depth=max_depth)
        if ancestry is None:
            return None
        names = [self._short_name(node['image'] or f"pid:{node['pid']}") for node in ancestry['nodes']]
        summary = ' -> '.join(names)
        if ancestry['incomplete']:
            summary += ' (partial)'
        return summary

    def first_seen_of(self, pid):
        """Wall-clock time this agent first observed `pid`, or None.
        The anchor for 'how long has this thing been running here' evidence
        reported alongside detections."""
        entry = self._entries.get(pid)
        return entry.get('ts') if entry else None

    # ------------------------------------------------------------------
    # Internals.
    # ------------------------------------------------------------------
    @staticmethod
    def _short_name(path_or_name):
        """Basename that understands BOTH Windows('\\') and POSIX('/')
        separators. os.path.basename alone silently returns the whole
        'C:\\a\\b.exe' string on POSIX, which would leak full paths into
        the Lineage column and chain summaries depending on the OS this
        code runs on."""
        if not isinstance(path_or_name, str):
            return path_or_name
        return path_or_name.replace('\\', '/').rsplit('/', 1)[-1]

    @staticmethod
    def _is_alive(pid):
        """Cheap liveness probe. True also for processes this account can't
        inspect (AccessDenied means it EXISTS, which is the only fact this
        method reports); NoSuchProcess is the definitive 'gone'."""
        try:
            psutil.Process(pid)
            return True
        except psutil.NoSuchProcess:
            return False
        except psutil.AccessDenied:
            return True
        except Exception:
            return False  # e.g. pid 0/4 oddities on some platforms

    def _env_for(self, pid):
        """Best-effort environment block for one pid, cached. Returns
        (env_dict_or_None, note_or_None) - the note is shown to the analyst
        whenever env_vars is None so 'missing' always says WHY (dead vs
        access-denied vs unavailable)."""
        if pid in self._env_cache:
            self._env_cache.move_to_end(pid)
            env = self._env_cache[pid]
            if env is not None:
                return env, None
            # Cached failure: the note that explained it was transient
            # (e.g. process died mid-read) may have changed - re-derive
            # cheaply rather than cache a stale excuse forever.
            del self._env_cache[pid]

        try:
            env = _process_environ(pid)
        except psutil.AccessDenied:
            return None, 'environment unavailable: access denied (elevated/protected process)'
        except psutil.NoSuchProcess:
            return None, 'environment unrecoverable: process has exited'
        except Exception as e:
            return None, f'unavailable ({e.__class__.__name__})'

        self._env_cache[pid] = env
        while len(self._env_cache) > self.max_env_cache:
            self._env_cache.popitem(last=False)
        return env, None
