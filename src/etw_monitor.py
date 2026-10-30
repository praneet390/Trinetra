"""
Microsoft-Windows-Kernel-Process ETW sensor (direct, not via Sysmon/Event Log).
Bounded queue between the callback and scoring thread - slow scoring never stalls
event delivery.

Confirmed via `Get-WinEvent -ListProvider Microsoft-Windows-Kernel-Process`:
ProcessStart only carries PID/CreateTime/ParentPID/SessionID/ImageName - no
CommandLine (a real, permanent capability gap vs Sysmon). Command-line-dependent
rules structurally cannot fire on this thin data; see evaluate_etw_process_start.
"""

import logging
import queue
import threading

from etw import ETW, GUID, ProviderInfo

# pywintrace logs WARNING for every field TDH can't decode - confirmed on a live
# run that Flags/SecurityMitigations routinely fail (pywintrace handles it fine;
# neither field is used here). Left at WARNING those emit as root-logger records
# which AlertLogHandler turns into dashboard alerts. Raised to ERROR so genuine
# errors (exceptions in our own callback) still surface.
logging.getLogger('etw.etw').setLevel(logging.ERROR)

KERNEL_PROCESS_PROVIDER_NAME = "Microsoft-Windows-Kernel-Process"
# GUID confirmed via `wevtutil gp Microsoft-Windows-Kernel-Process`.
KERNEL_PROCESS_PROVIDER_GUID = "{22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716}"
# Task IDs confirmed via Get-WinEvent -ListProvider: 1=ProcessStart, 2=Stop, 3/4=Thread, 5=ImageLoad.
TASK_PROCESS_START = 1

EVENT_QUEUE_MAXSIZE = 2000

# Without this keyword filter a live 8s capture measured 17358/17360 events LOST
# to buffer overflow (WINEVENT_KEYWORD_THREAD/IMAGE/CPU_PRIORITY flooded the buffer).
# Restricting to PROCESS cuts volume to process start/stop only.
WINEVENT_KEYWORD_PROCESS = 0x10


def _on_etw_event(event_tufo, event_queue, on_heartbeat=None, on_drop=None):
    """Enqueues (pid, parent_pid, image_name, create_time, creator_pid).
    creator_pid is from the ETW event HEADER (EventHeader.ProcessId) - the process
    that generated the event, i.e. the actual creating process, not the payload's
    ProcessID (the new process). Same approach as Fibratus/Velociraptor."""
    try:
        _event_id, event = event_tufo
        # pywintrace uppercases manifest task names (etw/etw.py: task_name.strip().upper()),
        # so "ProcessStart" arrives as "PROCESSSTART". Match both name and numeric task ID.
        task_name = "".join(str(event.get("Task Name", "")).split()).upper()
        task_id = event.get("EventHeader", {}).get("EventDescriptor", {}).get("Task")
        if task_name != "PROCESSSTART" and task_id != TASK_PROCESS_START:
            return
        pid = event.get("ProcessID")
        parent_pid = event.get("ParentProcessID")
        image_name = event.get("ImageName")
        create_time = event.get("CreateTime")
        creator_pid = event.get("EventHeader", {}).get("ProcessId")
    except Exception as e:
        logging.error(f"[ETW] Error extracting fields from a Kernel-Process event: {e}")
        return

    # No ProcessID = unusable; don't count as heartbeat, but still queue for error logging.
    if on_heartbeat and pid is not None:
        on_heartbeat()

    try:
        event_queue.put_nowait((pid, parent_pid, image_name, create_time, creator_pid))
    except queue.Full:
        logging.warning("[ETW] Event queue full - dropping an event because scoring is falling behind.")
        if on_drop:
            on_drop()


def _scoring_worker(engine_instance, event_queue, correlator=None):
    """Drains tuples from the queue on a thread separate from the ETW callback.
    Accepts 4- or 5-tuples (creator_pid optional for backward compatibility)."""
    while True:
        pid, parent_pid, image_name, create_time, *rest = event_queue.get()
        creator_pid = rest[0] if rest else None
        try:
            if correlator is not None:
                if creator_pid is None:
                    correlator.submit_etw(pid, parent_pid, image_name, create_time)
                else:
                    correlator.submit_etw(pid, parent_pid, image_name, create_time, creator_pid=creator_pid)
            else:
                engine_instance.evaluate_etw_process_start(pid, parent_pid, image_name, create_time)
        except Exception as e:
            logging.error(f"[ETW] Scoring worker failed on an event: {e}")


def start_etw_monitor(engine_instance, on_heartbeat=None, correlator=None, on_drop=None):
    """correlator (process_correlator.ProcessCorrelator), if given, receives
    every decoded ProcessStart instead of the engine directly - None (the
    default) preserves the exact single-sensor behavior this module had
    before ProcessCorrelator existed."""
    try:
        logging.info(f"[*] Starting ETW capture on {KERNEL_PROCESS_PROVIDER_NAME}...")
        event_queue = queue.Queue(maxsize=EVENT_QUEUE_MAXSIZE)
        threading.Thread(target=_scoring_worker, args=(engine_instance, event_queue, correlator), daemon=True).start()

        def _callback(event_tufo):
            _on_etw_event(event_tufo, event_queue, on_heartbeat=on_heartbeat, on_drop=on_drop)

        # GUID() converts the string via CLSIDFromString; passing a bare string raises
        # "byref() argument 1 must be _ctypes._CData, not str" at start()/stop() time.
        provider = ProviderInfo(KERNEL_PROCESS_PROVIDER_NAME, GUID(KERNEL_PROCESS_PROVIDER_GUID),
                                 any_keywords=WINEVENT_KEYWORD_PROCESS)
        etw_session = ETW(providers=[provider], event_callback=_callback)
        etw_session.start()

        logging.info("[+] ETW kernel-process capture active. Awaiting real-time events...")
        return etw_session
    except Exception as e:
        logging.error(f"[!] Failed to start ETW capture (Ensure you are running as Administrator): {e}")
        return None


def stop_etw_monitor(session):
    """Stop an ETW session. Safe to call with None.

    pywintrace's consumer thread is not a daemon and blocks in ProcessTrace()
    until told to stop - without this call the process cannot exit. ETW.stop()
    disables the provider first; if that raises, the consumer is stopped directly
    to avoid the hang."""
    if session is None:
        return
    try:
        session.stop()
    except Exception as e:
        logging.error(f"[!] ETW session did not stop cleanly: {e}")
        try:
            session.consumer.stop()
        except Exception as consumer_error:
            logging.error(f"[!] ETW consumer thread could not be stopped either: {consumer_error}")
        return
    logging.info("[*] ETW kernel-process capture stopped.")
