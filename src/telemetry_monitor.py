import win32evtlog
import logging
import queue
import re
import threading

# Bounded to prevent an indefinitely backed-up queue when scoring falls behind.
EVENT_QUEUE_MAXSIZE = 2000

# Presence of a numeric <EventID> is the liveness signal (checked against 600 real events
# from four Windows channels). Tolerates Qualifiers attribute and namespace prefix.
_EVENT_ID_RE = re.compile(r"<(?:\w+:)?EventID[^>]*>\s*\d+\s*</(?:\w+:)?EventID>")


def on_sysmon_event(action, context, event_handle, on_heartbeat=None, on_drop=None):
    """EvtSubscribe callback; context is the shared queue.Queue.

    EvtRender must happen synchronously here - the OS invalidates event_handle
    on return. Scoring is handed to _scoring_worker so a slow scoring pass
    can't stall this callback and risk the OS dropping buffered Sysmon events.
    """
    if action != win32evtlog.EvtSubscribeActionDeliver:
        return
    try:
        xml_content = win32evtlog.EvtRender(event_handle, win32evtlog.EvtRenderEventXml)
    except Exception as e:
        logging.error(f"[TELEMETRY] Error rendering event: {e}")
        return

    # Heartbeat fires before the queue check: a full queue means the scoring
    # worker is behind, not that the sensor is dead. Only events with a numeric
    # EventID count as liveness - a stream of unparseable events must not keep
    # a backed-up sensor "live" while no usable telemetry is flowing.
    if on_heartbeat and isinstance(xml_content, str) and _EVENT_ID_RE.search(xml_content):
        on_heartbeat()

    try:
        context.put_nowait(xml_content)
    except queue.Full:
        logging.warning("[TELEMETRY] Event queue full - dropping an event because scoring is falling behind.")
        if on_drop:
            on_drop()


def _scoring_worker(engine_instance, event_queue):
    """Drains rendered Sysmon XML off the queue and runs it through the
    heuristic engine, on a thread separate from the EvtSubscribe callback
    above. Runs until the process exits (daemon thread)."""
    while True:
        xml_content = event_queue.get()
        try:
            engine_instance.evaluate_event(xml_content)
        except Exception as e:
            logging.error(f"[TELEMETRY] Scoring worker failed on an event: {e}")


def start_monitor(engine_instance, on_heartbeat=None, on_drop=None):
    try:
        logging.info("[*] Subscribing to Microsoft-Windows-Sysmon/Operational via EvtSubscribe...")
        event_queue = queue.Queue(maxsize=EVENT_QUEUE_MAXSIZE)
        threading.Thread(target=_scoring_worker, args=(engine_instance, event_queue), daemon=True).start()

        def _callback(action, context, event_handle):
            on_sysmon_event(action, context, event_handle, on_heartbeat=on_heartbeat, on_drop=on_drop)

        subscription_handle = win32evtlog.EvtSubscribe(
            "Microsoft-Windows-Sysmon/Operational",
            win32evtlog.EvtSubscribeToFutureEvents,
            None,
            _callback,
            event_queue,
            "*"
        )
        logging.info("[+] Sysmon push subscription active. Awaiting real-time events...")
        return subscription_handle
    except Exception as e:
        logging.error(f"[!] Failed to subscribe to Sysmon events (Ensure you are running as Administrator and Sysmon is installed): {e}")
        return None
