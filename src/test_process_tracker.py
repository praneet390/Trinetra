"""Self-check for process_tracker.py. Run: python test_process_tracker.py"""

from process_tracker import ProcessTracker


def _create(pid, ppid, image):
    return (1, {'ProcessId': str(pid), 'ParentProcessId': str(ppid) if ppid is not None else None, 'Image': image})


def test_chain_resolves_three_generations():
    t = ProcessTracker()
    t.add(*_create(1, None, r'C:\Windows\explorer.exe'))
    t.add(*_create(2, 1, r'C:\Windows\System32\cmd.exe'))
    t.add(*_create(3, 2, r'C:\Users\bob\evil.exe'))
    assert t.get_chain(3) == [r'C:\Windows\explorer.exe', r'C:\Windows\System32\cmd.exe', r'C:\Users\bob\evil.exe']


def test_lineage_string_uses_basenames():
    t = ProcessTracker()
    t.add(*_create(1, None, r'C:\Windows\explorer.exe'))
    t.add(*_create(2, 1, r'C:\Windows\System32\cmd.exe'))
    assert t.lineage_string(2) == 'explorer.exe -> cmd.exe'


def test_untracked_pid_yields_empty_chain():
    t = ProcessTracker()
    assert t.get_chain(999) == []
    assert t.lineage_string(999) == ''


def test_untracked_ancestor_truncates_chain_gracefully():
    t = ProcessTracker()
    # pid 2's parent (pid 1) was never observed - chain should stop there,
    # not crash or loop.
    t.add(*_create(2, 1, r'C:\evil.exe'))
    assert t.get_chain(2) == [r'C:\evil.exe']


def test_cycle_does_not_infinite_loop():
    t = ProcessTracker()
    t.add(*_create(1, 2, 'a.exe'))
    t.add(*_create(2, 1, 'b.exe'))  # artificial cycle: 1 <-> 2
    chain = t.get_chain(1, max_depth=10)
    assert len(chain) <= 10  # terminates rather than looping forever


def test_ignores_non_process_create_events():
    t = ProcessTracker()
    t.add(10, {'SourceProcessId': '1'})  # ProcessAccess, not ProcessCreate
    assert t.get_chain(1) == []


def test_bounded_eviction_drops_oldest():
    t = ProcessTracker(max_entries=3)
    for pid in range(1, 6):
        t.add(*_create(pid, None, f'{pid}.exe'))
    # only the 3 most recently added PIDs should remain trackable
    assert t.get_chain(1) == []
    assert t.get_chain(5) == ['5.exe']


# ---- full-record ingestion (Memory Ancestry Graph foundation) --------------

def test_add_captures_full_record_fields():
    # The ancestry graph needs more than image+ppid: command line, user,
    # spawn time and the delivering source must all survive ingestion.
    t = ProcessTracker()
    t.add(1, {
        'ProcessId': '4242', 'ParentProcessId': '1',
        'Image': r'C:\Windows\System32\cmd.exe',
        'CommandLine': 'cmd.exe /c whoami',
        'User': 'DESKTOP\\bob',
        'UtcTime': '2026-01-15 10:30:45.123',
        '_source': 'fused',
    })
    entry = t._entries[4242]
    assert entry['image'] == r'C:\Windows\System32\cmd.exe'
    assert entry['command_line'] == 'cmd.exe /c whoami'
    assert entry['user'] == 'DESKTOP\\bob'
    assert entry['spawn_time'] == '2026-01-15 10:30:45.123'
    assert entry['source'] == 'fused'
    assert isinstance(entry['ts'], float)


def test_thin_etw_dispatch_upgraded_by_rich_sysmon_later():
    # The correlator's real-world sequence: ETW arrives first with thin
    # fields, Sysmon arrives shortly after with the rich ones. The record
    # must merge in place - and the FIRST-SEEN timestamp must NOT move,
    # because downstream dwell/activity evidence anchors on it.
    t = ProcessTracker()
    t.add(1, {'ProcessId': '55', 'ParentProcessId': '1', 'Image': 'evil.exe', '_source': 'etw'})
    first_ts = t._entries[55]['ts']
    assert t._entries[55]['command_line'] is None  # honest ETW gap
    t.add(1, {'ProcessId': '55', 'ParentProcessId': '1', 'Image': 'evil.exe',
              'CommandLine': 'evil.exe --go', 'User': 'bob', '_source': 'fused'})
    entry = t._entries[55]
    assert entry['command_line'] == 'evil.exe --go'
    assert entry['user'] == 'bob'
    assert entry['source'] == 'fused'
    assert entry['ts'] == first_ts  # first-seen is never refreshed


# ---- get_ancestry: nodes, edges, ordering, partiality ----------------------

def test_get_ancestry_nodes_and_edges_oldest_first():
    t = ProcessTracker()
    t.add(*_create(1, None, r'C:\Windows\explorer.exe'))
    t.add(*_create(2, 1, r'C:\Windows\System32\cmd.exe'))
    t.add(*_create(3, 2, r'C:\Users\bob\evil.exe'))
    ancestry = t.get_ancestry(3)
    assert [n['pid'] for n in ancestry['nodes']] == [1, 2, 3]  # oldest first
    assert ancestry['edges'] == [
        {'from': 1, 'to': 2, 'label': 'EXEC'},
        {'from': 2, 'to': 3, 'label': 'EXEC'},
    ]
    assert ancestry['incomplete'] is False  # reached a tracked root
    assert ancestry['nodes'][-1]['command_line'] is None  # _create has no cmdline


def test_get_ancestry_marks_partial_chain():
    # pid 2's parent (pid 1) was never observed: the chain is honest about
    # being partial instead of silently looking complete.
    t = ProcessTracker()
    t.add(*_create(2, 1, r'C:\evil.exe'))
    ancestry = t.get_ancestry(2)
    assert [n['pid'] for n in ancestry['nodes']] == [2]
    assert ancestry['incomplete'] is True


def test_get_ancestry_none_for_untracked_pid():
    t = ProcessTracker()
    assert t.get_ancestry(999) is None


def test_get_ancestry_cycle_terminates_and_marks_incomplete():
    t = ProcessTracker()
    t.add(*_create(1, 2, 'a.exe'))
    t.add(*_create(2, 1, 'b.exe'))
    ancestry = t.get_ancestry(1, max_depth=10)
    assert len(ancestry['nodes']) <= 10
    assert ancestry['incomplete'] is True


def test_chain_summary_dual_separator_basenames():
    # The summary must render basenames of WINDOWS paths regardless of the
    # OS it runs on (os.path.basename alone fails on POSIX for 'C:\\...').
    t = ProcessTracker()
    t.add(*_create(1, None, r'C:\Windows\explorer.exe'))
    t.add(*_create(2, 1, r'C:\Temp\evil.exe'))
    assert t.chain_summary(2) == 'explorer.exe -> evil.exe'


def test_chain_summary_marks_partial():
    t = ProcessTracker()
    t.add(*_create(2, 1, r'C:\evil.exe'))
    assert t.chain_summary(2) == 'evil.exe (partial)'


# ---- environment variables (best-effort, live processes only) --------------

def test_env_captured_for_live_process(monkeypatch):
    import process_tracker as pt

    t = ProcessTracker()
    t.add(*_create(7, None, 'a.exe'))

    class _FakeLive:
        pass  # construction succeeding == "alive" for _is_alive

    monkeypatch.setattr(pt.psutil, 'Process', lambda pid: _FakeLive())
    monkeypatch.setattr(pt, '_process_environ', lambda pid: {'PATH': 'x', 'SECRET': 'y'})
    ancestry = t.get_ancestry(7, include_env=True)
    node = ancestry['nodes'][0]
    assert node['env_vars'] == {'PATH': 'x', 'SECRET': 'y'}
    assert node['env_note'] is None
    assert node['alive'] is True


def test_env_unrecoverable_for_dead_process(monkeypatch):
    import process_tracker as pt

    t = ProcessTracker()
    t.add(*_create(8, None, 'a.exe'))

    def _dead(pid):
        raise pt.psutil.NoSuchProcess(pid)

    monkeypatch.setattr(pt.psutil, 'Process', _dead)
    ancestry = t.get_ancestry(8, include_env=True)
    node = ancestry['nodes'][0]
    assert node['env_vars'] is None
    assert 'exited' in node['env_note']
    assert node['alive'] is False


def test_env_denied_reports_access(monkeypatch):
    import process_tracker as pt

    t = ProcessTracker()
    t.add(*_create(9, None, 'a.exe'))

    class _FakeLive:
        pass

    def _denied(pid):
        raise pt.psutil.AccessDenied(pid)

    monkeypatch.setattr(pt.psutil, 'Process', lambda pid: _FakeLive())
    monkeypatch.setattr(pt, '_process_environ', _denied)
    ancestry = t.get_ancestry(9, include_env=True)
    node = ancestry['nodes'][0]
    assert node['env_vars'] is None
    assert 'access denied' in node['env_note']


def test_env_not_read_unless_requested():
    # include_env=False (the default, used by detection-time snapshots)
    # must not touch other processes' address space at all.
    t = ProcessTracker()
    t.add(*_create(10, None, 'a.exe'))
    ancestry = t.get_ancestry(10)
    node = ancestry['nodes'][0]
    assert node['env_vars'] is None
    assert node['env_note'] is None


def test_env_cache_is_bounded():
    # Fill far past the cap; the cache must evict rather than grow.
    t = ProcessTracker(max_env_cache=4)
    for pid in range(20, 30):
        t._env_cache[pid] = {'K': 'v'}
        t._env_cache.move_to_end(pid)
    while len(t._env_cache) > 4:
        t._env_cache.popitem(last=False)
    assert len(t._env_cache) <= 4


def test_first_seen_of():
    t = ProcessTracker()
    assert t.first_seen_of(42) is None
    t.add(*_create(42, None, 'x.exe'))
    assert isinstance(t.first_seen_of(42), float)


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for t in tests:
        t()
        print(f"  ok  {t.__name__}")
    print(f"OK ({len(tests)} checks)")
