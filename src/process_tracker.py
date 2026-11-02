"""
In-memory parent/child process lineage and full ancestry tracker.

lineage_string() and get_ancestry() are two projections of one graph: keeping
them in one structure prevents silent drift. Records are built from whatever
the event source carries (Sysmon Event ID 1 is rich; raw ETW is thin - see
etw_monitor.py); missing fields are None, never guessed. Environment variables
are read lazily per get_ancestry(include_env=True) and cached; they live in
process address space and are unrecoverable after exit. Purely additive:
never scores anything; HeuristicEngine decides when to ask for a snapshot.
"""

import os
import time
from collections import OrderedDict

import psutil

DEFAULT_MAX_ENTRIES = 2000
DEFAULT_MAX_DEPTH = 10
DEFAULT_MAX_ENV_CACHE = 512


def _process_environ(pid):
    """Isolated at module level so tests can monkeypatch without real OS processes.
    Raises NoSuchProcess (exited) or AccessDenied (elevated); both are expected."""
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
        self._entries = OrderedDict()
        self._env_cache = OrderedDict()
        self.max_env_cache = max_env_cache

    def add(self, event_id, data):
        """Record one ProcessCreate (Event ID 1) observation; all others ignored.
        Fields the sensor didn't carry are stored as None, never guessed."""
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

        # ETW carries CreateTime; Sysmon carries UtcTime. Stored raw - formats differ.
        spawn_time = data.get('CreateTime') or data.get('UtcTime')

        # Re-observation upgrades thin ETW records with richer Sysmon fields.
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
            # `ts` (first-seen) is never refreshed; it anchors dwell time.
            # Keys use Sysmon-style originals (e.g. 'Image'), not lowercase field names.
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
            if data.get('_source') == 'fused':
                existing['source'] = 'fused'
            self._entries.move_to_end(pid)

        while len(self._entries) > self.max_entries:
            self._entries.popitem(last=False)

    def get_chain(self, pid, max_depth=DEFAULT_MAX_DEPTH):
        """Image names oldest-first down to `pid`, stopping at an untracked ancestor,
        cycle, or max_depth. Empty list if `pid` was never observed."""
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
        """'explorer.exe -> cmd.exe -> evil.exe' for dashboard display, basenames only."""
        names = [self._short_name(c) for c in self.get_chain(pid, max_depth=max_depth)]
        return ' -> '.join(names)

    def get_ancestry(self, pid, max_depth=DEFAULT_MAX_DEPTH, include_env=False):
        """Full ancestry evidence for `pid`: nodes oldest-first, labeled EXEC edges.
        'incomplete' is True when the walk stopped early (untracked ancestor / cycle
        / depth cap). include_env=True best-effort reads live environment blocks."""
        if pid not in self._entries:
            return None

        nodes = []
        edges = []
        current = pid
        seen = set()
        incomplete = False

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

    @staticmethod
    def _short_name(path_or_name):
        """Basename splitting on both '\\' and '/' - os.path.basename alone
        returns the full path on POSIX for Windows-style paths."""
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
            del self._env_cache[pid]  # re-derive; cached failures can become stale

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
