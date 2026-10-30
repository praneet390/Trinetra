"""
Kernel driver sensor (driver/sensor/sensor.c) consumed via polling IOCTL.
Same bounded-queue/scoring-worker decoupling as telemetry_monitor.py/etw_monitor.py.

KERNEL GROUND TRUTH: PsSetCreateProcessNotifyRoutineEx's CreatingThreadId can't be
influenced by PROC_THREAD_ATTRIBUTE_PARENT_PROCESS (unlike Sysmon/ETW's claimed-parent),
and ObRegisterCallbacks pre-op runs before the OS access check (PPL caveats in sensor.c).
A missing/unsigned driver is non-fatal - agent degrades, same as Sysmon not being installed.
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

# Computed (not hex constants) to stay in sync with sensor.c's CTL_CODE definitions.
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

# Mirrors SENSOR_EVENT field-for-field. '<' (no padding): every ULONG64 falls on an
# 8-byte boundary by construction, so the C struct itself has zero padding.
# ImageName is decoded separately (UTF-16-LE, NUL-terminated mid-buffer).
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
    """Unpack one SENSOR_EVENT into a dict. Pure function - testable without a driver.
    Raises struct.error on short/malformed input; callers catch it."""
    (seq, event_type, ppid_spoof, pid, field2, field3, field4,
     name_truncated, _reserved, raw_name) = struct.unpack(_EVENT_FORMAT, raw_bytes)

    # Cut at the first even-aligned b'\x00\x00' pair (UTF-16-LE NUL character).
    # A naive single find() hits the spurious odd-offset b'\x00\x00' formed by an
    # ASCII char's high byte + first padding byte - confirmed by real test failure
    # (8-char name's NUL terminator was never found).
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
    """Route one parsed event to engine/correlator. Unknown event_type is logged and
    skipped (not raised) - a newer driver build may add types this agent doesn't know."""
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
    """Drain events from the queue on a separate thread so slow scoring never stalls polling."""
    while True:
        event = event_queue.get()
        try:
            _dispatch_event(event, correlator, engine)
        except Exception as e:
            logging.error(f"[KERNEL] Scoring worker failed on an event: {e}")


def _record_sequence_gap(event, last_seq_holder, on_drop):
    """Calls on_drop() once per gap in SequenceNumber (driver overwrites oldest
    entry when its bounded buffer is full) so the drop count matches what other
    sensors report: events actually lost, not "a drop happened"."""
    seq = event['sequence_number']
    prev = last_seq_holder[0]
    if prev is not None and seq > prev + 1 and on_drop:
        gap = seq - prev - 1
        for _ in range(gap):
            on_drop()
    last_seq_holder[0] = seq


def _poll_loop(handle, event_queue, stop_event, on_heartbeat=None, on_drop=None, last_seq_holder=None):
    """Poll GET_EVENT IOCTL on its own thread. 0-byte/short result = nothing queued,
    not an error. IOCTL failure backs off and keeps retrying - never stops permanently,
    so a transient failure doesn't make a live sensor look dead to sensor_health.py."""
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
    """Open the driver's comms channel and start polling. Returns None if the driver
    isn't loaded (non-fatal; agent degrades). Self-protection registration is best-effort
    (logged, not raised). Does NOT start the service - call ensure_driver_running() first."""
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
    """Stop the polling session. Safe with None; never raises."""
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
    """Idempotently create and start the 'sensor' kernel-driver service.
    Returns True if running, False otherwise; never raises. Does NOT build or sign
    the driver - see driver/sensor/ for that one-time step."""
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
    """Stop (not delete) the 'sensor' service. Never raises."""
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
