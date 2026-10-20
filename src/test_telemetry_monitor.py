"""
Self-check for telemetry_monitor.py's event-pump/scoring decoupling.
Monkeypatches win32evtlog.EvtRender so this never needs a real Sysmon event
handle. Run: python test_telemetry_monitor.py
"""

import queue
import threading
import time

import telemetry_monitor as tm


class _FakeEngine:
    def __init__(self, on_evaluate=None):
        self.calls = []
        self.on_evaluate = on_evaluate

    def evaluate_event(self, xml_content):
        self.calls.append(xml_content)
        if self.on_evaluate:
            self.on_evaluate()


def _wait_until(predicate, timeout=2.0, interval=0.01):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return False


def test_on_sysmon_event_enqueues_rendered_xml():
    tm.win32evtlog.EvtRender = lambda handle, fmt: "<Event>fake</Event>"
    q = queue.Queue()
    tm.on_sysmon_event(tm.win32evtlog.EvtSubscribeActionDeliver, q, event_handle=object())
    assert q.get_nowait() == "<Event>fake</Event>"


def test_on_sysmon_event_ignores_non_deliver_actions():
    tm.win32evtlog.EvtRender = lambda handle, fmt: "<Event>fake</Event>"
    q = queue.Queue()
    tm.on_sysmon_event(action=999, context=q, event_handle=object())
    assert q.empty()


def test_on_sysmon_event_drops_and_does_not_raise_when_queue_full():
    tm.win32evtlog.EvtRender = lambda handle, fmt: "<Event>fake</Event>"
    q = queue.Queue(maxsize=1)
    q.put_nowait("<Event>already here</Event>")
    tm.on_sysmon_event(tm.win32evtlog.EvtSubscribeActionDeliver, q, event_handle=object())  # must not raise
    assert q.qsize() == 1
    assert q.get_nowait() == "<Event>already here</Event>"


def test_on_sysmon_event_handles_render_failure_without_raising():
    def _raise(handle, fmt):
        raise OSError("event handle invalidated")
    tm.win32evtlog.EvtRender = _raise
    q = queue.Queue()
    tm.on_sysmon_event(tm.win32evtlog.EvtSubscribeActionDeliver, q, event_handle=object())  # must not raise
    assert q.empty()


def test_scoring_worker_drains_queue_on_its_own_thread():
    engine = _FakeEngine()
    q = queue.Queue()
    q.put("<Event>one</Event>")
    threading.Thread(target=tm._scoring_worker, args=(engine, q), daemon=True).start()
    assert _wait_until(lambda: engine.calls == ["<Event>one</Event>"])


def test_slow_scoring_does_not_block_the_callback_thread():
    # The whole point of the decoupling: on_sysmon_event must return
    # immediately even if the engine consuming the queue is slow.
    release = threading.Event()

    def _slow_evaluate():
        release.wait(timeout=2)

    engine = _FakeEngine(on_evaluate=_slow_evaluate)
    q = queue.Queue()
    threading.Thread(target=tm._scoring_worker, args=(engine, q), daemon=True).start()

    tm.win32evtlog.EvtRender = lambda handle, fmt: "<Event>slow</Event>"

    start = time.monotonic()
    tm.on_sysmon_event(tm.win32evtlog.EvtSubscribeActionDeliver, q, event_handle=object())
    elapsed = time.monotonic() - start
    release.set()  # let the worker's slow evaluate_event finish so the test process can exit cleanly

    assert elapsed < 0.2, f"on_sysmon_event took {elapsed}s - it must never block on scoring"


# A structurally real rendered event: what the OS hands the callback.
_VALID_EVENT = ('<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
                '<System><EventID>1</EventID></System><EventData/></Event>')


def _deliver(rendered, queue_obj=None, **callbacks):
    """One on_sysmon_event call whose EvtRender returns `rendered`."""
    tm.win32evtlog.EvtRender = lambda handle, fmt: rendered
    q = queue_obj if queue_obj is not None else queue.Queue()
    tm.on_sysmon_event(tm.win32evtlog.EvtSubscribeActionDeliver, q, event_handle=object(), **callbacks)
    return q


def test_on_heartbeat_fires_on_successful_event():
    calls = []
    _deliver(_VALID_EVENT, on_heartbeat=lambda: calls.append(1))
    assert calls == [1]


def test_on_heartbeat_fires_even_when_queue_is_full():
    # The sensor observed a real event even though the queue couldn't take
    # it - that's a scoring-worker backlog, not a dead sensor, so the
    # heartbeat must still fire.
    q = queue.Queue(maxsize=1)
    q.put_nowait("<Event>already here</Event>")
    calls = []
    _deliver(_VALID_EVENT, q, on_heartbeat=lambda: calls.append(1))
    assert calls == [1]


def test_heartbeat_requires_a_numeric_event_id():
    # A stream of unparseable events must not keep a sensor "live". Each of
    # these is still queued (so the engine logs the parse error) - only the
    # liveness signal is withheld.
    garbage = [
        "<Event>", "not xml at all", "", "   ",
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System/></Event>',  # valid XML, no EventID
        "<Event><System><EventID>abc</EventID></System></Event>",                                # non-numeric EventID
        "<Event><System><EventID></EventID></System></Event>",                                   # empty EventID
    ]
    for rendered in garbage:
        calls = []
        q = _deliver(rendered, on_heartbeat=lambda: calls.append(1))
        assert calls == [], f"garbage counted as liveness: {rendered!r}"
        assert q.get_nowait() == rendered, "garbage must still be queued so the engine records the error"


def test_heartbeat_accepts_every_real_event_id_shape():
    # Shapes seen rendering 600 real events from four Windows channels:
    # classic providers add a Qualifiers attribute. A namespace prefix and
    # surrounding whitespace are tolerated too.
    shapes = [
        "<Event><System><EventID>1</EventID></System></Event>",
        "<Event><System><EventID Qualifiers='0'>7036</EventID></System></Event>",
        "<Event><System><EventID Qualifiers='49152'>10</EventID></System></Event>",
        "<e:Event><e:System><e:EventID>13</e:EventID></e:System></e:Event>",
        "<Event><System><EventID>\n  11 \n</EventID></System></Event>",
    ]
    for rendered in shapes:
        calls = []
        _deliver(rendered, on_heartbeat=lambda: calls.append(1))
        assert calls == [1], f"a real-shaped event was not counted as liveness: {rendered!r}"


def test_a_non_string_render_result_neither_raises_nor_counts_as_liveness():
    calls = []
    q = _deliver(b"<Event><System><EventID>1</EventID></System></Event>", on_heartbeat=lambda: calls.append(1))
    assert calls == []
    assert q.qsize() == 1


def test_on_drop_fires_when_the_queue_is_full_and_only_then():
    full = queue.Queue(maxsize=1)
    full.put_nowait("already here")
    drops = []
    _deliver(_VALID_EVENT, full, on_drop=lambda: drops.append(1))  # must not raise
    assert drops == [1]
    assert full.qsize() == 1, "the dropped event must not have displaced the queued one"

    drops = []
    _deliver(_VALID_EVENT, queue.Queue(maxsize=5), on_drop=lambda: drops.append(1))
    assert drops == [], "an accepted event is not a drop"


def test_a_dropped_event_still_counts_as_liveness():
    # Overloaded, not dead: both signals must fire for the same event.
    full = queue.Queue(maxsize=1)
    full.put_nowait("already here")
    beats, drops = [], []
    _deliver(_VALID_EVENT, full, on_heartbeat=lambda: beats.append(1), on_drop=lambda: drops.append(1))
    assert beats == [1] and drops == [1]


def test_missing_on_drop_is_a_safe_default():
    full = queue.Queue(maxsize=1)
    full.put_nowait("already here")
    _deliver(_VALID_EVENT, full)  # queue full and no on_drop: must not raise


def test_on_heartbeat_does_not_fire_on_render_failure():
    def _raise(handle, fmt):
        raise OSError("event handle invalidated")
    tm.win32evtlog.EvtRender = _raise
    q = queue.Queue()
    calls = []
    tm.on_sysmon_event(tm.win32evtlog.EvtSubscribeActionDeliver, q, event_handle=object(), on_heartbeat=lambda: calls.append(1))
    assert calls == [], "a failed render never reached the OS event, so it must not count as a heartbeat"


def test_on_heartbeat_does_not_fire_for_non_deliver_actions():
    calls = []
    tm.on_sysmon_event(action=999, context=queue.Queue(), event_handle=object(), on_heartbeat=lambda: calls.append(1))
    assert calls == []


def test_missing_on_heartbeat_is_a_safe_default():
    # Every pre-existing call site (and every test above this one) omits
    # on_heartbeat entirely - confirms that stays valid.
    tm.win32evtlog.EvtRender = lambda handle, fmt: "<Event>fake</Event>"
    q = queue.Queue()
    tm.on_sysmon_event(tm.win32evtlog.EvtSubscribeActionDeliver, q, event_handle=object())  # must not raise
    assert q.get_nowait() == "<Event>fake</Event>"


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for t in tests:
        t()
        print(f"  ok  {t.__name__}")
    print(f"OK ({len(tests)} checks)")
