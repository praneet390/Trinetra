"""
Third, independent telemetry sensor: the kernel driver (driver/sensor/
sensor.c), consumed over its user-mode comms channel (a device + one
polling IOCTL, GET_EVENT - see that file's header comment for exactly
which event types it forwards and why, and why they're deliberately
scoped down from everything the driver can see under a live debugger).
Same decoupled shape as telemetry_monitor.py/etw_monitor.py: a bounded
queue between event delivery and a separate scoring-worker thread, so a
slow scoring pass can never stall event delivery - except here the
"producer" is this module's own polling thread, not an OS-delivered
callback, since the driver's comms channel is itself poll-based (a
bounded circular queue drained by IOCTL, not a pending-IRP push model -
the simpler of the two, deliberately shipped first; see sensor.c).

Unlike Sysmon/ETW, this sensor is KERNEL GROUND TRUTH for process
ancestry (PsSetCreateProcessNotifyRoutineEx's CreatingThreadId field
cannot be influenced by PROC_THREAD_ATTRIBUTE_PARENT_PROCESS the way
Sysmon/ETW's claimed-parent field can) and for LSASS handle-access
observation (ObRegisterCallbacks' pre-operation callback runs before the
OS's own access check, PPL caveats noted in sensor.c's own header) - see
heuristic_engine.py's evaluate_kernel_lsass_access/kernel_ppid_spoof
check and process_correlator.submit_kernel.

Requires the sensor.sys driver already built+signed (see driver/sensor/)
- this module does NOT build or sign it, only starts/stops the already-
registered Windows service (ensure_driver_running/stop_driver_service)
and talks to its comms channel. A missing/not-yet-loaded/untrusted
driver is a normal, non-fatal "sensor unavailable" condition here, the
same posture as Sysmon not being installed - the agent degrades, it
does not fail to start.
"""

import logging
import os
import queue
import struct
import threading

try:
    import win32file
    import win32service
    import winerror
    import pywintypes
except ImportError:  # pragma: no cover - Windows-only, see conftest.py
    win32file = win32service = winerror = pywintypes = None

DEVICE_PATH = r'\\.\malprojectsensor'
SERVICE_NAME = 'sensor'

# Mirrors the WDK's CTL_CODE macro exactly (ntddk.h) - computed, not
# re-typed as hex constants, so this can never silently drift from
# driver/sensor/sensor.c's own IOCTL_MALPROJECT_* definitions as long as
# the three inputs below (device type, function, method/access) match.
FILE_DEVICE_UNKNOWN = 0x00000022
METHOD_BUFFERED = 0
FILE_ANY_ACCESS = 0


def _ctl_code(device_type, function, method, access):
    return (device_type << 16) | (access << 14) | (function << 2) | method


IOCTL_GET_EVENT = _ctl_code(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_REGISTER_SELF = _ctl_code(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_UNREGISTER_SELF = _ctl_code(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

# Mirrors SENSOR_EVENT_TYPE in sensor.c exactly.
EVENT_TYPE_PROCESS_CREATE = 1
EVENT_TYPE_LSASS_ACCESS = 2
EVENT_TYPE_DRIVER_LOAD = 3

IMAGE_NAME_MAX_CHARS = 260

# struct layout mirrors SENSOR_EVENT in sensor.c field-for-field. '<' (no
# padding) is correct here because the C struct itself has zero padding -
# every ULONG64 already falls on an 8-byte boundary by construction (see
# that struct's own layout comment), so there is nothing for alignment
# padding to insert on either side. Q=ULONG64, I=ULONG, {n}s=raw bytes for
# the fixed WCHAR[260] buffer (decoded separately below, not as a Python
# string field, since it's UTF-16-LE and NUL-terminated mid-buffer).
_EVENT_FORMAT = f'<QIIQQQQII{IMAGE_NAME_MAX_CHARS * 2}s'
EVENT_SIZE = struct.calcsize(_EVENT_FORMAT)

EVENT_QUEUE_MAXSIZE = 2000
POLL_INTERVAL_SECONDS = 0.1
POLL_ERROR_BACKOFF_SECONDS = 1.0

# Relative to this file's own directory (src/), matching the
# driver/sensor/ layout actually in this repo.
_DRIVER_SYS_CANDIDATES = (
    os.path.join(os.path.dirname(__file__), '..', 'driver', 'sensor', 'sensor.sys'),
    os.path.join(os.path.dirname(__file__), '..', 'driver', 'sensor', 'x64', 'Debug', 'sensor.sys'),
    os.path.join(os.path.dirname(__file__), '..', 'driver', 'sensor', 'x64', 'Release', 'sensor.sys'),
)


def parse_event(raw_bytes):
    """Unpack one SENSOR_EVENT's raw bytes into a plain dict. Pure function
    (no I/O), so it's testable with synthetic bytes shaped like the real
    driver's wire format - the same way etw_monitor's _on_etw_event tests
    don't need a real ETW session. Raises struct.error on a short/malformed
    buffer; callers are expected to catch that, not this function."""
    (seq, event_type, ppid_spoof, pid, field2, field3, field4,
     name_truncated, _reserved, raw_name) = struct.unpack(_EVENT_FORMAT, raw_bytes)

    # The driver NUL-terminates ImageName; cut at the first NUL *character*
    # (a char-aligned, even-offset b'\x00\x00' pair) before decoding, so a
    # short name never carries trailing garbage from the rest of the fixed
    # buffer. A single find() is NOT enough: every ASCII WCHAR is encoded
    # as [byte, 0x00], so the LAST real character's own high byte (always
    # at an odd offset - char k occupies bytes [2k, 2k+1]) sits directly
    # next to the first padding byte, forming a spurious b'\x00\x00' at an
    # odd offset that is always found BEFORE the true, even-offset
    # boundary. Must keep searching past a misaligned match, not stop at
    # it - confirmed by a real test failure (an 8-char name's trailing
    # NUL bytes were never cut), not assumed.
    search_from = 0
    nul_index = -1
    while True:
        candidate = raw_name.find(b'\x00\x00', search_from)
        if candidate == -1:
            break
        if candidate % 2 == 0:
            nul_index = candidate
            break
        search_from = candidate + 1
    if nul_index != -1:
        raw_name = raw_name[:nul_index]
    try:
        image_name = raw_name.decode('utf-16-le', errors='replace')
    except Exception:
        image_name = ''

    return {
        'sequence_number': seq,
        'event_type': event_type,
        'ppid_spoof_detected': bool(ppid_spoof),
        'pid': pid,
        # Meaning depends on event_type - see sensor.c's own SENSOR_EVENT
        # comment for the authoritative per-type mapping:
        #   ProcessCreate: field2=claimed_parent, field3=real_creator
        #   LsassAccess:   field2=requestor_pid,  field4=desired_access
        #   DriverLoad:    field4=image_base (field2/field3 unused, 0)
        'field2': field2,
        'field3': field3,
        'field4': field4,
        'image_name_truncated': bool(name_truncated),
        'image_name': image_name,
    }


def _dispatch_event(event, correlator, engine):
    """Routes one parsed event dict to the engine/correlator. Mirrors
    etw_monitor._scoring_worker's per-event-type dispatch shape - an
    unrecognized event_type is logged and skipped, never raised, since a
    newer driver build could in principle add a type this older agent
    build doesn't know about yet."""
    event_type = event['event_type']
    if event_type == EVENT_TYPE_PROCESS_CREATE:
        correlator.submit_kernel(
            pid=event['pid'],
            claimed_parent_pid=event['field2'],
            real_creator_pid=event['field3'],
            image_name=event['image_name'],
            ppid_spoof_detected=event['ppid_spoof_detected'],
        )
    elif event_type == EVENT_TYPE_LSASS_ACCESS:
        engine.evaluate_kernel_lsass_access(
            requestor_pid=event['field2'], target_pid=event['pid'], desired_access=event['field4'],
        )
    elif event_type == EVENT_TYPE_DRIVER_LOAD:
        engine.evaluate_kernel_driver_load(
            pid=event['pid'], image_name=event['image_name'], image_base=event['field4'],
        )
    else:
        logging.warning(f"[KERNEL] Unknown event_type={event_type} from the kernel sensor - ignoring")


def _scoring_worker(engine, correlator, event_queue):
    """Drains parsed event dicts off the queue and routes them, on a
    thread separate from the poll loop - same decoupling rationale as
    every other sensor's scoring worker: a slow rule/engine pass must
    never stall the thread actually reading the driver's queue."""
    while True:
        event = event_queue.get()
        try:
            _dispatch_event(event, correlator, engine)
        except Exception as e:
            logging.error(f"[KERNEL] Scoring worker failed on an event: {e}")


def _record_sequence_gap(event, last_seq_holder, on_drop):
    """Detects a gap in SequenceNumber (the driver's own dropped-event
    signal - see sensor.c's SensorEnqueueEvent, which overwrites the
    oldest queued entry rather than blocking when its bounded buffer is
    full) and calls on_drop() once per missing sequence number, so this
    sensor's SensorHealth.record_drop() count means the same thing every
    other sensor's does: how many events were actually lost, not just
    "a drop happened at some point"."""
    seq = event['sequence_number']
    prev = last_seq_holder[0]
    if prev is not None and seq > prev + 1 and on_drop:
        gap = seq - prev - 1
        for _ in range(gap):
            on_drop()
    last_seq_holder[0] = seq


def _poll_loop(handle, event_queue, stop_event, on_heartbeat=None, on_drop=None, last_seq_holder=None):
    """Runs on its own thread: repeatedly issues the GET_EVENT IOCTL,
    waiting briefly between empty polls rather than busy-spinning. A
    0-byte/short result means "nothing queued right now" (see sensor.c's
    SensorDispatchDeviceControl) - an ordinary, expected result, not an
    error and not a reason to stop polling. An actual IOCTL failure (the
    device/driver went away) backs off further and keeps retrying, the
    same "never permanently give up" posture telemetry_monitor.py and
    etw_monitor.py already take - a sensor that stops polling after one
    transient failure would look identical to one that was never alive,
    which sensor_health.py's whole point is to distinguish."""
    while not stop_event.is_set():
        try:
            raw = win32file.DeviceIoControl(handle, IOCTL_GET_EVENT, None, EVENT_SIZE, None)
        except Exception as e:
            logging.error(f"[KERNEL] GET_EVENT IOCTL failed: {e}")
            stop_event.wait(POLL_ERROR_BACKOFF_SECONDS)
            continue

        if not raw or len(raw) < EVENT_SIZE:
            stop_event.wait(POLL_INTERVAL_SECONDS)
            continue

        try:
            event = parse_event(raw)
        except struct.error as e:
            logging.error(f"[KERNEL] Failed to parse a kernel sensor event (size mismatch?): {e}")
            continue

        if on_heartbeat:
            on_heartbeat()
        if last_seq_holder is not None:
            _record_sequence_gap(event, last_seq_holder, on_drop)

        try:
            event_queue.put_nowait(event)
        except queue.Full:
            logging.warning("[KERNEL] Event queue full - dropping a kernel sensor event because scoring is falling behind.")
            if on_drop:
                on_drop()


def start_kernel_monitor(engine, correlator, on_heartbeat=None, on_drop=None):
    """Opens the already-loaded driver's comms channel, registers this
    process as self-protected (see sensor.c's IOCTL_MALPROJECT_REGISTER_
    SELF - best-effort, logged not raised, since a failure here must not
    stop the sensor itself from coming up), and starts polling. Returns a
    truthy session object on success, None if the driver isn't loaded/
    reachable - the same "unavailable sensor" contract every other sensor
    in this project follows (see sensor_health.sensor_label: a falsy
    handle means "never came up", distinct from a live one going stale).

    Does NOT start the driver service itself - see ensure_driver_running(),
    called separately by the agent's own startup sequence before this, so
    service lifecycle and per-process comms-channel listening stay
    independently controllable."""
    if win32file is None:
        logging.error("[KERNEL] pywin32 not available - kernel sensor cannot start")
        return None
    try:
        handle = win32file.CreateFile(
            DEVICE_PATH, win32file.GENERIC_READ | win32file.GENERIC_WRITE,
            0, None, win32file.OPEN_EXISTING, 0, None
        )
    except Exception as e:
        logging.error(f"[KERNEL] Could not open {DEVICE_PATH} - driver not loaded? {e}")
        return None

    try:
        win32file.DeviceIoControl(handle, IOCTL_REGISTER_SELF, None, 0, None)
        logging.info("[KERNEL] Registered this process as protected with the kernel sensor")
    except Exception as e:
        logging.error(f"[KERNEL] Could not register self-protection with the kernel sensor: {e}")

    event_queue = queue.Queue(maxsize=EVENT_QUEUE_MAXSIZE)
    stop_event = threading.Event()
    last_seq_holder = [None]

    threading.Thread(target=_scoring_worker, args=(engine, correlator, event_queue), daemon=True).start()
    poll_thread = threading.Thread(
        target=_poll_loop, args=(handle, event_queue, stop_event),
        kwargs={'on_heartbeat': on_heartbeat, 'on_drop': on_drop, 'last_seq_holder': last_seq_holder},
        daemon=True,
    )
    poll_thread.start()

    logging.info("[+] Kernel driver sensor active. Awaiting real-time events...")
    return {'device_handle': handle, 'stop_event': stop_event, 'poll_thread': poll_thread}


def stop_kernel_monitor(session):
    """Stop the session start_kernel_monitor() returned. Safe to call with
    None (the sensor never started) and never raises - same contract as
    stop_etw_monitor(session=None)."""
    if session is None:
        return
    try:
        session['stop_event'].set()
        session['poll_thread'].join(timeout=2)
    except Exception as e:
        logging.error(f"[KERNEL] Poll thread did not stop cleanly: {e}")

    try:
        win32file.DeviceIoControl(session['device_handle'], IOCTL_UNREGISTER_SELF, None, 0, None)
    except Exception as e:
        logging.error(f"[KERNEL] Could not unregister self-protection: {e}")

    try:
        session['device_handle'].Close()
    except Exception as e:
        logging.error(f"[KERNEL] Device handle did not close cleanly: {e}")
        return
    logging.info("[*] Kernel driver sensor stopped.")


def ensure_driver_running(sys_path=None):
    """Creates (if needed) and starts the 'sensor' kernel-driver Windows
    service, idempotently - safe to call on every agent startup, the same
    "just make sure it's up" posture as Sysmon's own install-if-needed
    story in the README. Returns True if the service ends up RUNNING,
    False otherwise - never raises. A missing/unsigned/untrusted driver
    binary is a normal "sensor unavailable this run" condition, not a
    fatal agent-startup error, the same posture as Sysmon not being
    installed.

    Does NOT build or sign the driver - see driver/sensor/ for that
    one-time step (and its own cert/trust-store prerequisites). This only
    drives the already-signed binary's service lifecycle."""
    if win32service is None:
        return False
    sys_path = sys_path or next((p for p in _DRIVER_SYS_CANDIDATES if os.path.exists(p)), None)
    if sys_path is None:
        logging.warning("[KERNEL] sensor.sys not found - kernel driver unavailable this run")
        return False

    scm = None
    try:
        scm = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_ALL_ACCESS)

        svc = None
        try:
            svc = win32service.OpenService(scm, SERVICE_NAME, win32service.SERVICE_ALL_ACCESS)
        except pywintypes.error as e:
            if e.winerror != winerror.ERROR_SERVICE_DOES_NOT_EXIST:
                raise
            svc = win32service.CreateService(
                scm, SERVICE_NAME, SERVICE_NAME,
                win32service.SERVICE_ALL_ACCESS, win32service.SERVICE_KERNEL_DRIVER,
                win32service.SERVICE_DEMAND_START, win32service.SERVICE_ERROR_NORMAL,
                sys_path, None, 0, None, None, None
            )
            logging.info(f"[KERNEL] Created '{SERVICE_NAME}' service from {sys_path}")
        finally:
            if svc is not None:
                win32service.CloseServiceHandle(svc)

        svc = win32service.OpenService(scm, SERVICE_NAME, win32service.SERVICE_ALL_ACCESS)
        try:
            status = win32service.QueryServiceStatus(svc)
            if status[1] != win32service.SERVICE_RUNNING:
                win32service.StartService(svc, None)
                logging.info(f"[KERNEL] Started '{SERVICE_NAME}' service")
            return True
        finally:
            win32service.CloseServiceHandle(svc)
    except Exception as e:
        logging.error(f"[KERNEL] Could not start the kernel driver service: {e}")
        return False
    finally:
        if scm is not None:
            win32service.CloseServiceHandle(scm)


def stop_driver_service():
    """Stops (but does not delete - a clean reload stays a two-command
    `sc stop`/`sc start` away, not a full reinstall) the 'sensor' service.
    Called on clean agent shutdown, mirroring stop_etw_monitor's own
    lifecycle symmetry with its start function. Never raises."""
    if win32service is None:
        return
    scm = svc = None
    try:
        scm = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_ALL_ACCESS)
        svc = win32service.OpenService(scm, SERVICE_NAME, win32service.SERVICE_ALL_ACCESS)
        status = win32service.QueryServiceStatus(svc)
        if status[1] == win32service.SERVICE_RUNNING:
            win32service.ControlService(svc, win32service.SERVICE_CONTROL_STOP)
            logging.info(f"[KERNEL] Stopped '{SERVICE_NAME}' service")
    except Exception as e:
        logging.error(f"[KERNEL] Could not stop the kernel driver service: {e}")
    finally:
        if svc is not None:
            win32service.CloseServiceHandle(svc)
        if scm is not None:
            win32service.CloseServiceHandle(scm)
