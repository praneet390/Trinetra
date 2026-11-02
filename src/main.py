import threading
import time
import logging
from static_scanner import StaticScanner
from telemetry_monitor import start_monitor
from etw_monitor import start_etw_monitor, stop_etw_monitor
from kernel_sensor import ensure_driver_running, start_kernel_monitor, stop_kernel_monitor, stop_driver_service
from heuristic_engine import HeuristicEngine
from module_inspector import ModuleInspector
from process_correlator import ProcessCorrelator
from rule_engine import RuleEngine
from sensor_health import SensorHealth, watchdog_loop, current_blind_state, sensor_label
from detection_config import load_config
from self_test import RecentPidSightings, self_test_loop
from process_tracker import ProcessTracker

MODULE_SWEEP_INTERVAL_SECONDS = 30

def main():
    # force=True is load-bearing, not stylistic: importing etw_monitor (via
    # `from etw import ...`) pulls in pywintrace's etw/common.py, which
    # calls logging.basicConfig(level=logging.ERROR) as an import-time side
    # effect - before this line ever runs. logging.basicConfig() is a no-op
    # once any handler exists, so without force=True this call (and the
    # equivalent one HeuristicEngine.__init__ makes) would silently lose,
    # leaving every INFO-level log (the entire static scan, rule loading,
    # sensor startup) invisible - confirmed live: exactly this happened
    # before this line was added.
    logging.basicConfig(level=logging.INFO, format='[*] %(message)s', force=True)

    print("=====================================================")
    print("          Windows Defensive Agent (EDR)              ")
    print("=====================================================")

    rules = RuleEngine()
    config = load_config()
    engine = HeuristicEngine(rule_engine=rules, config=config)

    binaries_path = "../data/binaries.json"
    logging.info(f"[*] Starting Static Ingress Scanner on {binaries_path}...")
    scanner = StaticScanner(engine, binaries_path, rule_engine=rules)
    scanner.scan()
    logging.info("[+] Static Scan Complete.")
    
    logging.info("[*] Starting Behavioral Telemetry Monitors...")
    correlator = ProcessCorrelator(engine, fuse_window=config['correlator']['fuse_window_seconds'],
                                   witness_window=config['correlator'].get('witness_window_seconds'))
    engine.correlator = correlator
    correlator.start()

    sysmon_health = SensorHealth("sysmon")
    etw_health = SensorHealth("etw")
    kernel_health = SensorHealth("kernel")
    sub_handle = start_monitor(engine, on_heartbeat=sysmon_health.touch, on_drop=sysmon_health.record_drop)
    etw_handle = start_etw_monitor(engine, on_heartbeat=etw_health.touch, correlator=correlator,
                                   on_drop=etw_health.record_drop)

    ensure_driver_running()
    kernel_handle = start_kernel_monitor(engine, correlator, on_heartbeat=kernel_health.touch,
                                         on_drop=kernel_health.record_drop)

    if config['correlator'].get('witness_check', True):
        witness_handles = {"etw": (etw_handle, etw_health), "kernel": (kernel_handle, kernel_health)}
        correlator.enable_witness_check(
            lambda name: sensor_label(*witness_handles[name]) in ("live", "stale")
        )

    def _blind_state():
        return current_blind_state(
            [(sub_handle, sysmon_health), (etw_handle, etw_health), (kernel_handle, kernel_health)],
            engine.total_events_seen,
        )

    threading.Thread(
        target=watchdog_loop,
        args=([sysmon_health, etw_health, kernel_health],),
        kwargs={"blind_state_fn": _blind_state},
        daemon=True,
    ).start()

    if not sub_handle:
        logging.warning("[-] Sysmon telemetry monitor failed to start. Continuing with reduced telemetry.")
    if not etw_handle:
        logging.warning("[-] ETW telemetry monitor failed to start. Continuing with reduced telemetry.")
    if not kernel_handle:
        logging.warning("[-] Kernel driver sensor failed to start. Continuing with reduced telemetry.")

    sightings = RecentPidSightings()
    tracker = ProcessTracker()

    def _observe_raw_event(event_id, data):
        sightings.observe(event_id, data)
        tracker.add(event_id, data)

    engine.on_event = _observe_raw_event
    engine.ancestry_provider = tracker.get_ancestry
    threading.Thread(
        target=self_test_loop,
        args=(sightings.seen,),
        kwargs={
            "interval": config['self_test']['interval_seconds'],
            "timeout": config['self_test']['timeout_seconds'],
        },
        daemon=True,
    ).start()

    inspector = ModuleInspector(engine)

    try:
        logging.info("[*] EDR Engine is active. Press Ctrl+C to terminate.")
        last_sweep = 0
        while True:
            time.sleep(1)
            last_sweep += 1
            if last_sweep >= MODULE_SWEEP_INTERVAL_SECONDS:
                last_sweep = 0
                logging.info("[*] Running module provenance sweep...")
                inspector.sweep()
    except KeyboardInterrupt:
        logging.info("\n[*] Shutting down Defensive Agent...")
    finally:
        # pywintrace's consumer thread is not a daemon; unless it is stopped the
        # process can't exit (see etw_monitor.stop_etw_monitor).
        stop_etw_monitor(etw_handle)
        stop_kernel_monitor(kernel_handle)
        stop_driver_service()

if __name__ == "__main__":
    main()
