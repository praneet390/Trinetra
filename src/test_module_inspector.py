"""
Self-check for module_inspector.py's active sweep: monkeypatches
psutil.process_iter/memory_maps so this never depends on what's actually
running on the machine. Run: python test_module_inspector.py
"""

import module_inspector as mi
from heuristic_engine import HeuristicEngine


class _FakeMap:
    """One memory map as psutil reports it. File-backed maps carry a path;
    anonymous regions on Windows come as path='' with addr/perms/bsize
    (Linux names them '[anon]' etc and lacks bsize - both shapes are
    exercised by the tests below)."""
    def __init__(self, path, addr=None, perms='', bsize=None):
        self.path = path
        self.addr = addr
        self.perms = perms
        self.bsize = bsize


class _FakeProc:
    def __init__(self, pid, name, maps):
        self.info = {"pid": pid, "name": name, "exe": None}
        self._maps = maps

    def memory_maps(self):
        return self._maps


def _run_sweep(engine, procs):
    original = mi.psutil.process_iter
    mi.psutil.process_iter = lambda attrs=None: iter(procs)
    try:
        inspector = mi.ModuleInspector(engine)
        inspector.sweep()
        return inspector
    finally:
        mi.psutil.process_iter = original


def test_high_value_process_with_staged_module_scores_full():
    engine = HeuristicEngine()
    proc = _FakeProc(7001, "svchost.exe", [_FakeMap(r"C:\Windows\Temp\payload.dll")])
    _run_sweep(engine, [proc])
    assert engine.process_scores[7001] == 60


def test_ordinary_process_with_staged_module_scores_reduced():
    engine = HeuristicEngine()
    proc = _FakeProc(7002, "mytool.exe", [_FakeMap(r"C:\Users\Public\payload.dll")])
    _run_sweep(engine, [proc])
    assert engine.process_scores[7002] == 35


def test_module_from_normal_path_scores_nothing():
    engine = HeuristicEngine()
    proc = _FakeProc(7003, "svchost.exe", [_FakeMap(r"C:\Windows\System32\ntdll.dll")])
    _run_sweep(engine, [proc])
    assert 7003 not in engine.process_scores


def test_non_dll_paths_are_ignored():
    engine = HeuristicEngine()
    proc = _FakeProc(7004, "svchost.exe", [_FakeMap(r"C:\Windows\Temp\notes.txt")])
    _run_sweep(engine, [proc])
    assert 7004 not in engine.process_scores


def test_repeated_sweep_does_not_double_count_the_same_finding():
    engine = HeuristicEngine()
    proc = _FakeProc(7005, "svchost.exe", [_FakeMap(r"C:\Windows\Temp\payload.dll")])
    inspector = None
    original = mi.psutil.process_iter
    mi.psutil.process_iter = lambda attrs=None: iter([proc])
    try:
        inspector = mi.ModuleInspector(engine)
        inspector.sweep()
        first_score = engine.process_scores[7005]
        inspector.sweep()  # second sweep, same finding
        assert engine.process_scores[7005] == first_score, "a repeated sweep must not re-flag the same (pid, module) pair"
    finally:
        mi.psutil.process_iter = original


def test_access_denied_process_is_skipped_not_crashed():
    class _DeniedProc:
        info = {"pid": 7006, "name": "locked.exe", "exe": None}

        def memory_maps(self):
            raise mi.psutil.AccessDenied()

    engine = HeuristicEngine()
    _run_sweep(engine, [_DeniedProc()])  # must not raise
    assert 7006 not in engine.process_scores



# ---- Dwell time: evidence-derived module residency -------------------------

class _FakeClock:
    """Deterministic clock so dwell ages are exact instead of raced."""
    def __init__(self, now=1000.0):
        self.now = now
    def __call__(self):
        return self.now
    def advance(self, seconds):
        self.now += seconds


def test_dwell_reported_in_flagged_finding():
    engine = HeuristicEngine()
    proc = _FakeProc(7100, "mytool.exe", [_FakeMap(r"C:\Users\Public\payload.dll")])
    clock = _FakeClock()
    inspector = mi.ModuleInspector(engine, clock=clock)
    _run_sweep_with(inspector, [proc])
    clock.advance(3600)  # one hour passes before the flag is examined
    # The FIRST sweep flagged it (first sighting = flag time); re-flagging
    # is deduped, so force a fresh finding for a NEW module path seen after
    # the gap to prove the reported residency uses first-seen, not now.
    proc2 = _FakeProc(7101, "mytool.exe", [_FakeMap(r"C:\Users\Public\payload2.dll")])
    inspector._inspect_process(proc2)  # first sighting at t+3600
    clock.advance(1800)  # half hour more, next sweep cycle
    inspector._seen.discard((7101, r"c:\users\public\payload2.dll"))
    inspector._inspect_process(proc2)  # second sighting flags it at t+5400
    record = inspector.dwell_by_module[(7101, r"c:\users\public\payload2.dll")]
    assert record["dwell_seconds"] == 1800
    assert record["dwell_human"] == "30m"
    assert record["dwell_source"] == "agent_first_observation"


def test_first_seen_ledger_records_before_flag():
    # The very first sighting must start the residency clock even though
    # the module is flagged in that same pass - later dwell figures must
    # measure residency, not time-since-flagging.
    engine = HeuristicEngine()
    proc = _FakeProc(7102, "mytool.exe", [_FakeMap(r"C:\Windows\Temp\evil.dll")])
    clock = _FakeClock()
    inspector = mi.ModuleInspector(engine, clock=clock)
    _run_sweep_with(inspector, [proc])
    assert engine.process_scores[7102] == 35  # flagged on first sighting
    key = (7102, r"c:\windows\temp\evil.dll")
    assert key in inspector._first_seen


def test_repeated_sweeps_grow_dwell_and_never_rescore():
    engine = HeuristicEngine()
    proc = _FakeProc(7103, "mytool.exe", [_FakeMap(r"C:\Users\Public\implant.dll")])
    clock = _FakeClock()
    inspector = mi.ModuleInspector(engine, clock=clock)
    for _ in range(5):
        _run_sweep_with(inspector, [proc])
        clock.advance(30)
    # Scored exactly once (dedup) but dwell keeps accumulating honestly.
    assert engine.process_scores[7103] == 35
    record = inspector.dwell_by_module[(7103, r"c:\users\public\implant.dll")]
    assert record["dwell_seconds"] == 120  # 4 advances x 30s after first sighting
    assert record["dwell_human"] == "2m"


def test_module_dwell_api_filters_by_pid():
    engine = HeuristicEngine()
    p1 = _FakeProc(7104, "a.exe", [_FakeMap(r"C:\Users\Public\one.dll")])
    p2 = _FakeProc(7105, "b.exe", [_FakeMap(r"C:\Users\Public\two.dll")])
    inspector = mi.ModuleInspector(engine, clock=_FakeClock())
    _run_sweep_with(inspector, [p1, p2])
    rows = inspector.module_dwell(pid=7104)
    assert len(rows) == 1
    assert rows[0]["pid"] == 7104
    assert rows[0]["module_path"] == r"c:\users\public\one.dll"
    assert len(inspector.module_dwell()) == 2


def test_dwell_ledger_is_bounded():
    engine = HeuristicEngine()
    clock = _FakeClock()
    inspector = mi.ModuleInspector(engine, clock=clock)
    # Overrun the cap through the real code path (not by poking internals):
    # many distinct suspicious modules across many PIDs.
    procs = [
        _FakeProc(7200 + i, "x.exe", [_FakeMap(rf"C:\Users\Public\mod{i}.dll")])
        for i in range(60)
    ]
    _run_sweep_with(inspector, procs)
    assert len(inspector._first_seen) == 60
    assert len(inspector._first_seen) <= mi.MAX_DWELL_ENTRIES


def _run_sweep_with(inspector, procs):
    original = mi.psutil.process_iter
    mi.psutil.process_iter = lambda attrs=None: iter(procs)
    try:
        inspector.sweep()
    finally:
        mi.psutil.process_iter = original


# ---- Attacker Dwell Time Calculator: anonymous memory regions --------------

def _anon_map(addr='0x7ff0', perms='rwx', bsize=4096, path=''):
    """A Windows-shaped anonymous memory map (pathless, addr, perms, size)."""
    return _FakeMap(path, addr=addr, perms=perms, bsize=bsize)


def test_anonymous_rwx_region_flagged_with_dwell():
    engine = HeuristicEngine()
    proc = _FakeProc(7300, "mytool.exe", [_anon_map(addr='0x7ff000', perms='rwx', bsize=8192)])
    clock = _FakeClock()
    inspector = mi.ModuleInspector(engine, clock=clock)
    _run_sweep_with(inspector, [proc])
    # Flagged at the ordinary-process severity, same tier as a suspicious-
    # path module in a non-system process.
    assert engine.process_scores[7300] == 35
    # The dwell ledger recorded the region with its full identity + age.
    record = inspector.dwell_by_region[(7300, '0x7ff000')]
    assert record['dwell_seconds'] == 0
    assert record['dwell_source'] == 'agent_first_observation'
    assert record['perms'] == 'rwx'
    assert record['size_bytes'] == 8192
    assert record['addr'] == '0x7ff000'


def test_high_value_target_rwx_region_scores_full():
    engine = HeuristicEngine()
    proc = _FakeProc(7301, "svchost.exe", [_anon_map(addr='0x800000', perms='rwx')])
    inspector = mi.ModuleInspector(engine, clock=_FakeClock())
    _run_sweep_with(inspector, [proc])
    assert engine.process_scores[7301] == 60


def test_anon_rx_only_region_tracked_but_never_flagged():
    # RX-at-rest anonymous memory is the legitimate shape of JIT code
    # pages (V8/.NET/JVM), so it must be tracked in the first-seen ledger
    # (its age is evidence the moment it ever becomes writable) but must
    # NOT be scored - otherwise one sweep of a normal desktop would drown
    # the finding in false positives.
    engine = HeuristicEngine()
    proc = _FakeProc(7302, "chrome.exe", [_anon_map(addr='0x900000', perms='r-x')])
    inspector = mi.ModuleInspector(engine, clock=_FakeClock())
    _run_sweep_with(inspector, [proc])
    assert 7302 not in engine.process_scores
    assert (7302, '0x900000') in inspector._region_first_seen
    assert inspector.dwell_by_region[(7302, '0x900000')]['perms'] == 'r-x'


def test_anon_non_executable_region_not_tracked():
    # Ordinary anonymous heap/stack (rw-) is neither shellcode territory
    # nor monitorable as such - it must not consume bounded ledger space.
    engine = HeuristicEngine()
    proc = _FakeProc(7303, "mytool.exe", [_anon_map(addr='0xa00000', perms='rw-')])
    inspector = mi.ModuleInspector(engine, clock=_FakeClock())
    _run_sweep_with(inspector, [proc])
    assert 7303 not in engine.process_scores
    assert len(inspector._region_first_seen) == 0
    assert len(inspector.dwell_by_region) == 0


def test_file_backed_dll_paths_never_enter_region_ledger():
    # A file-backed map - even an EXECUTABLE one - is not an anonymous
    # region: it has an on-disk artifact and belongs to the module side of
    # the sweep, not the dwell-time-calculator's anonymous ledger.
    engine = HeuristicEngine()
    proc = _FakeProc(7304, "mytool.exe", [_FakeMap(r"C:\Windows\System32\ntdll.dll", addr='0xb00000', perms='r-x')])
    inspector = mi.ModuleInspector(engine, clock=_FakeClock())
    _run_sweep_with(inspector, [proc])
    assert len(inspector._region_first_seen) == 0


def test_region_dwell_grows_across_sweeps_and_scores_once():
    engine = HeuristicEngine()
    proc = _FakeProc(7305, "mytool.exe", [_anon_map(addr='0xc00000', perms='rwx')])
    clock = _FakeClock()
    inspector = mi.ModuleInspector(engine, clock=clock)
    for _ in range(5):
        _run_sweep_with(inspector, [proc])
        clock.advance(30)
    # Scored exactly once (dedup per (pid, addr)) but the age keeps
    # accumulating honestly - 4 advances x 30s after the first sighting.
    assert engine.process_scores[7305] == 35
    record = inspector.dwell_by_region[(7305, '0xc00000')]
    assert record['dwell_seconds'] == 120
    assert record['dwell_human'] == '2m'


def test_region_dwell_clock_starts_at_first_executable_sighting():
    # THE forensic property the dwell calculator exists for: the region is
    # first seen as RX (the alloc-RW/write/reprotect-RX stealth shape),
    # and only LATER becomes RWX. The reported age must run from the FIRST
    # executable sighting, not from the moment it finally looked scary.
    engine = HeuristicEngine()
    clock = _FakeClock()
    inspector = mi.ModuleInspector(engine, clock=clock)
    rx_proc = _FakeProc(7306, "mytool.exe", [_anon_map(addr='0xd00000', perms='r-x')])
    _run_sweep_with(inspector, [rx_proc])
    clock.advance(86400)  # one day passes - reprotect happens in between
    rwx_proc = _FakeProc(7306, "mytool.exe", [_anon_map(addr='0xd00000', perms='rwx')])
    _run_sweep_with(inspector, [rwx_proc])  # flagged now
    assert engine.process_scores[7306] == 35
    record = inspector.dwell_by_region[(7306, '0xd00000')]
    assert record['dwell_seconds'] == 86400
    assert record['dwell_human'] == '1d 0h 0m'


def test_region_dwell_api_filters_by_pid():
    engine = HeuristicEngine()
    p1 = _FakeProc(7307, "a.exe", [_anon_map(addr='0xe00000', perms='rwx')])
    p2 = _FakeProc(7308, "b.exe", [_anon_map(addr='0xe10000', perms='rwx')])
    inspector = mi.ModuleInspector(engine, clock=_FakeClock())
    _run_sweep_with(inspector, [p1, p2])
    rows = inspector.memory_region_dwell(pid=7307)
    assert len(rows) == 1
    assert rows[0]['pid'] == 7307
    assert rows[0]['addr'] == '0xe00000'
    assert len(inspector.memory_region_dwell()) == 2


def test_region_ledger_is_bounded():
    engine = HeuristicEngine()
    inspector = mi.ModuleInspector(engine, clock=_FakeClock())
    # Overrun the cap through the real code path: many distinct executable
    # anonymous regions across many PIDs.
    procs = [
        _FakeProc(7400 + i, "x.exe", [_anon_map(addr=f'0x{0xf0000 + i * 4096:x}', perms='r-x')])
        for i in range(60)
    ]
    _run_sweep_with(inspector, procs)
    assert len(inspector._region_first_seen) == 60
    assert len(inspector._region_first_seen) <= mi.MAX_REGION_LEDGER_ENTRIES


def test_region_without_addr_is_skipped_honestly():
    # A psutil variant without an address field offers no stable identity
    # - a dwell figure keyed on nothing would be garbage, so the region is
    # skipped rather than guessed at.
    engine = HeuristicEngine()
    proc = _FakeProc(7309, "mytool.exe", [_FakeMap('', perms='rwx')])  # no addr attr value
    inspector = mi.ModuleInspector(engine, clock=_FakeClock())
    _run_sweep_with(inspector, [proc])
    assert 7309 not in engine.process_scores
    assert len(inspector._region_first_seen) == 0


def test_linux_shaped_anon_regions_are_tracked_too():
    # Linux psutil names anonymous mappings '[anon]'/'[heap]' instead of
    # leaving the path empty - the same no-file-backing fact, and the
    # sweep must treat both shapes identically.
    engine = HeuristicEngine()
    proc = _FakeProc(7310, "mytool.exe", [_anon_map(path='[anon:libc_malloc]', addr='0xf00000', perms='rwx')])
    inspector = mi.ModuleInspector(engine, clock=_FakeClock())
    _run_sweep_with(inspector, [proc])
    assert engine.process_scores[7310] == 35
    assert (7310, '0xf00000') in inspector.dwell_by_region


if __name__ == "__main__":
    tests = [v for k, v in list(globals().items()) if k.startswith("test_") and callable(v)]
    for t in tests:
        t()
        print(f"  ok  {t.__name__}")
    print(f"OK ({len(tests)} checks)")
