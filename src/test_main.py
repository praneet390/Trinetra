"""Self-check for main.py's shutdown path: the headless entrypoint must release
the ETW session on every way out, or pywintrace's non-daemon consumer thread
keeps the process alive after Ctrl+C. main() runs with every side effect faked
(static scan, sensors, correlator, background loops, the sleep that paces the
main loop). Run: python test_main.py"""

import logging

import main as m


class _FakeSession:
    def __init__(self):
        self.stop_calls = 0

    def stop(self):
        self.stop_calls += 1


class _FakeScanner:
    def __init__(self, *args, **kwargs):
        pass

    def scan(self):
        pass


class _FakeCorrelator:
    last = None

    def __init__(self, *args, **kwargs):
        self.init_kwargs = kwargs
        self.gate = None
        _FakeCorrelator.last = self

    def start(self):
        pass

    def enable_witness_check(self, gate, **kwargs):
        self.gate = gate


def _run_main(loop_error, session):
    """Run m.main() until its 1-second pacing sleep raises `loop_error`.
    Returns whatever exception escaped main()."""

    class _Time:
        @staticmethod
        def sleep(seconds):
            raise loop_error

    names = ("StaticScanner", "start_monitor", "start_etw_monitor", "ProcessCorrelator",
             "watchdog_loop", "self_test_loop", "time")
    saved = {name: getattr(m, name) for name in names}
    root = logging.getLogger()
    saved_handlers, saved_level = root.handlers[:], root.level

    m.StaticScanner = _FakeScanner
    m.start_monitor = lambda *args, **kwargs: object()
    m.start_etw_monitor = lambda *args, **kwargs: session
    m.ProcessCorrelator = _FakeCorrelator
    m.watchdog_loop = lambda *args, **kwargs: None
    m.self_test_loop = lambda *args, **kwargs: None
    m.time = _Time
    escaped = None
    try:
        m.main()
    except BaseException as e:  # noqa: BLE001 - the test inspects exactly what escapes
        escaped = e
    finally:
        for name, value in saved.items():
            setattr(m, name, value)
        for handler in root.handlers[:]:
            root.removeHandler(handler)
        for handler in saved_handlers:
            root.addHandler(handler)
        root.setLevel(saved_level)
    return escaped


def test_ctrl_c_releases_the_etw_session():
    session = _FakeSession()
    assert _run_main(KeyboardInterrupt(), session) is None
    assert session.stop_calls == 1


def test_an_unexpected_error_in_the_main_loop_still_releases_the_etw_session():
    session = _FakeSession()
    boom = RuntimeError("module sweep exploded")
    assert _run_main(boom, session) is boom, "the error must still propagate"
    assert session.stop_calls == 1


def test_main_arms_the_witness_check_and_only_trusts_live_or_stale_sensors():
    # A sensor that is up (here: ETW, never heartbeated -> 'stale') staying
    # silent is unexplained; one that never came up ('unavailable', here the
    # kernel driver, which cannot load off-Windows) explains its own silence.
    assert _run_main(KeyboardInterrupt(), _FakeSession()) is None
    gate = _FakeCorrelator.last.gate
    assert gate is not None
    assert gate("etw") is True
    assert gate("kernel") is False
    assert _FakeCorrelator.last.init_kwargs["witness_window"] == 5.0


def test_main_gate_treats_an_etw_sensor_that_never_started_as_explained():
    assert _run_main(KeyboardInterrupt(), None) is None
    assert _FakeCorrelator.last.gate("etw") is False


def test_ctrl_c_is_clean_when_the_etw_sensor_never_started():
    # e.g. not elevated: start_etw_monitor() returned None - nothing to stop
    assert _run_main(KeyboardInterrupt(), None) is None


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for t in tests:
        t()
        print(f"  ok  {t.__name__}")
    print(f"OK ({len(tests)} checks)")
