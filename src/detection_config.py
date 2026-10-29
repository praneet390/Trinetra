"""
Config-driven tunables for HeuristicEngine: decay rate, mitigation
thresholds, and the ransomware burst window/count. Deliberately does NOT
cover the safety floor (protected process names/PIDs, LSASS/hollowing
access-mask bitmasks, Defender-tamper/PowerShell-abuse pattern lists) -
those stay hardcoded in heuristic_engine.py on purpose, so a bad or
malicious config file can never loosen the one thing that must never move.

A missing or malformed config file must never change behavior - it falls
back to exactly the hardcoded defaults that shipped before this file
existed.
"""

import logging
import os

import yaml

DEFAULT_CONFIG_PATH = os.path.join(os.path.dirname(__file__), '..', 'config', 'detection.yml')

DEFAULTS = {
    'decay_points_per_second': 1.0 / 3.0,  # ~20 points/minute
    'thresholds': {
        'warning': 50,
        'critical': 80,
    },
    'ransomware': {
        'file_event_window_seconds': 20,
        'file_event_threshold': 60,
    },
    'correlator': {
        # How long process_correlator.py waits for a same-pid ETW+Sysmon
        # pair to fuse before giving up and dispatching whatever arrived
        # alone - provisional default, not yet measured against real
        # Sysmon-vs-ETW delivery lag on a live system (see README).
        'fuse_window_seconds': 2.0,
        # Per-event witness-gap check (process_correlator.py): a process
        # creation reported by the kernel driver but not by ETW (or vice
        # versa) within this many seconds is logged as [SENSOR-BLINDSPOT].
        # Warning-only - it never scores or mitigates anything.
        'witness_check': True,
        'witness_window_seconds': 5.0,
        # Whether a mismatch between the ETW event header's creating pid
        # and the claimed parent SCORES as PPID spoofing. Off until the
        # creator-agreement counters (/api/summary -> witness) confirm the
        # header pid matches the kernel driver's real creator on your host.
        'etw_creator_scoring': False,
    },
    'self_test': {
        # How often self_test.py's benign process-visibility/alert-pipeline
        # check runs. Deliberately infrequent: it's a real OS process
        # spawn, not free, and sensor_health.py's per-sensor heartbeat
        # already catches the common "sensor thread died" case within 60s -
        # this check is for the rarer, worse case of "the thread is alive
        # but isn't actually seeing real events".
        'interval_seconds': 300,
        'timeout_seconds': 15,
    },
}


def _deep_merge(base, override):
    merged = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def load_config(path=DEFAULT_CONFIG_PATH):
    """Hardcoded DEFAULTS merged with (and overridden by) whatever the YAML
    at `path` provides. Absent file, empty file, or malformed YAML all fall
    back to DEFAULTS untouched - this must never be the reason detection
    behavior changes unexpectedly."""
    try:
        with open(path, 'r') as f:
            user_config = yaml.safe_load(f)
    except (FileNotFoundError, OSError):
        return dict(DEFAULTS)
    except yaml.YAMLError as e:
        logging.warning(f"[CONFIG] Failed to parse {path}, using defaults: {e}")
        return dict(DEFAULTS)

    if not isinstance(user_config, dict):
        return dict(DEFAULTS)

    return _deep_merge(DEFAULTS, user_config)
