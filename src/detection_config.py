"""
Config-driven tunables for HeuristicEngine. Does NOT cover the safety floor
(protected PIDs, LSASS access-mask bitmasks, Defender-tamper patterns) -
those are hardcoded so a malicious config file can never loosen them.
A missing or malformed config always falls back to hardcoded DEFAULTS.
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
        # Provisional - not yet measured against real Sysmon-vs-ETW delivery lag.
        'fuse_window_seconds': 2.0,
        # Kernel-driver/ETW creation gap logged as [SENSOR-BLINDSPOT]; never scores.
        'witness_check': True,
        'witness_window_seconds': 5.0,
        # Off until creator-agreement counters (/api/summary -> witness) confirm
        # the ETW header pid matches the kernel driver's real creator on this host.
        'etw_creator_scoring': False,
    },
    'self_test': {
        # Infrequent: real OS process spawn; sensor_health.py heartbeat already
        # catches "sensor thread died" within 60s. This catches "thread alive
        # but not seeing real events".
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
    """DEFAULTS merged with YAML overrides; absent/malformed file always falls back to DEFAULTS."""
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
