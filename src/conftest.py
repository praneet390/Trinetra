"""Pytest bootstrap: make the Windows-coupled modules importable on a
non-Windows dev/CI machine.

WHY THIS EXISTS
---------------
This project targets Windows (Sysmon via pywin32's win32evtlog, raw kernel
telemetry via the pywintrace `etw` package, psutil for live process
inspection). Both sensor imports are module-level, so simply importing
web_server / main / failure_lab on Linux raises ModuleNotFoundError before
any test can run - even though the tests themselves never touch a real
Event Log or ETW session (they monkeypatch the sensor functions, feed
synthetic events straight into the pump/worker functions, and fake every
side effect at the boundaries).

On a real Windows machine the real modules import fine and the fakes below
are never installed - the `except ImportError` gate guarantees zero behavior
change for the project's actual live-fire environment. On Linux/macOS (CI,
contributor laptops, this repo's automated verification), the minimal
stand-ins below supply just enough surface for the import to succeed so the
whole suite - including every Windows-coupled module's tests - runs and
fails loudly if real logic regresses.

WHAT THE FAKES DO NOT DO
------------------------
They do NOT emulate Windows behavior. Any test that actually exercised
EvtSubscribe/ETW session semantics would still be Windows-only; the fakes
exist purely to satisfy `import`, matching how the existing tests already
treat these APIs (patched or bypassed entirely).
"""

import sys
import types

# ---------------------------------------------------------------------------
# win32evtlog stand-in (imported at module level by telemetry_monitor.py).
# Members below are exactly the names telemetry_monitor.py and its tests
# reference; values only need to be internally consistent (the tests read
# the constants back off the module rather than hardcoding numbers).
# ---------------------------------------------------------------------------
if "win32evtlog" not in sys.modules:
    try:  # pragma: no cover - executed only on Windows
        import win32evtlog  # noqa: F401
    except ImportError:
        _fake_win32evtlog = types.ModuleType("win32evtlog")
        # EvtSubscribe flag: deliver matching future events via callback.
        _fake_win32evtlog.EvtSubscribeToFutureEvents = 1
        # Action code the EvtSubscribe callback receives for delivered events.
        _fake_win32evtlog.EvtSubscribeActionDeliver = 2
        # EvtRender output format: full event as XML.
        _fake_win32evtlog.EvtRenderEventXml = 3
        # Functions are never called by the test suite (the subscription
        # handle path is exercised only on Windows); give them safe bodies
        # anyway so an accidental call fails loudly instead of confusingly.
        _fake_win32evtlog.EvtSubscribe = lambda *a, **k: (
            (_ for _ in ()).throw(RuntimeError("EvtSubscribe is Windows-only; test fakes must not call it"))
        )
        _fake_win32evtlog.EvtRender = lambda *a, **k: (
            (_ for _ in ()).throw(RuntimeError("EvtRender is Windows-only; test fakes must not call it"))
        )
        sys.modules["win32evtlog"] = _fake_win32evtlog

# ---------------------------------------------------------------------------
# pywintrace stand-in (imported at module level by etw_monitor.py as
# `from etw import ETW, GUID, ProviderInfo`). etw_monitor instantiates these
# only inside start_etw_monitor(), which the test suite never invokes against
# a real session - the class bodies below just make the import (and the
# module-level logging.getLogger('etw.etw') call) succeed.
# ---------------------------------------------------------------------------
if "etw" not in sys.modules:
    try:  # pragma: no cover - executed only on Windows
        import etw  # noqa: F401
    except ImportError:
        _fake_etw = types.ModuleType("etw")

        class _FakeETW:  # pragma: no cover - never constructed by tests
            def __init__(self, *args, **kwargs):
                raise RuntimeError("ETW sessions are Windows-only; test fakes must not construct one")

        class _FakeGUID:  # pragma: no cover
            def __init__(self, value):
                self.value = value

        class _FakeProviderInfo:  # pragma: no cover
            def __init__(self, name, guid, any_keywords=None):
                self.name = name
                self.guid = guid
                self.any_keywords = any_keywords

        _fake_etw.ETW = _FakeETW
        _fake_etw.GUID = _FakeGUID
        _fake_etw.ProviderInfo = _FakeProviderInfo
        sys.modules["etw"] = _fake_etw
