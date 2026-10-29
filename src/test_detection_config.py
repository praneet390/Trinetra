"""Self-check for detection_config.py. Run: python test_detection_config.py"""

import os
import tempfile

from detection_config import load_config, DEFAULTS


def test_missing_file_returns_hardcoded_defaults():
    missing_path = os.path.join(tempfile.gettempdir(), 'definitely_does_not_exist_xyz.yml')
    assert load_config(missing_path) == DEFAULTS


def test_malformed_yaml_falls_back_to_defaults():
    with tempfile.NamedTemporaryFile('w', suffix='.yml', delete=False) as f:
        f.write("not: valid: yaml: [")
        path = f.name
    try:
        assert load_config(path) == DEFAULTS
    finally:
        os.unlink(path)


def test_non_mapping_yaml_falls_back_to_defaults():
    with tempfile.NamedTemporaryFile('w', suffix='.yml', delete=False) as f:
        f.write("- just\n- a\n- list\n")
        path = f.name
    try:
        assert load_config(path) == DEFAULTS
    finally:
        os.unlink(path)


def test_partial_override_merges_with_defaults():
    with tempfile.NamedTemporaryFile('w', suffix='.yml', delete=False) as f:
        f.write("thresholds:\n  critical: 90\n")
        path = f.name
    try:
        config = load_config(path)
        assert config['thresholds']['critical'] == 90
        assert config['thresholds']['warning'] == DEFAULTS['thresholds']['warning'], "unset sibling key must keep its default"
        assert config['decay_points_per_second'] == DEFAULTS['decay_points_per_second']
    finally:
        os.unlink(path)


def test_full_override():
    with tempfile.NamedTemporaryFile('w', suffix='.yml', delete=False) as f:
        f.write("decay_points_per_second: 1.0\nransomware:\n  file_event_threshold: 10\n")
        path = f.name
    try:
        config = load_config(path)
        assert config['decay_points_per_second'] == 1.0
        assert config['ransomware']['file_event_threshold'] == 10
        assert config['ransomware']['file_event_window_seconds'] == DEFAULTS['ransomware']['file_event_window_seconds']
    finally:
        os.unlink(path)


def test_correlator_witness_defaults_are_safe():
    # Warning-only gap detection is on; the ETW-header creator only SCORES
    # (and so can auto-terminate) once an operator turns it on.
    correlator = DEFAULTS['correlator']
    assert correlator['witness_check'] is True
    assert correlator['witness_window_seconds'] == 5.0
    assert correlator['etw_creator_scoring'] is False


def test_shipped_config_file_matches_the_witness_defaults():
    config = load_config()
    assert config['correlator']['witness_check'] is True
    assert config['correlator']['witness_window_seconds'] == 5.0
    assert config['correlator']['etw_creator_scoring'] is False
    assert config['correlator']['fuse_window_seconds'] == DEFAULTS['correlator']['fuse_window_seconds']


def test_partial_correlator_override_keeps_the_other_witness_defaults():
    with tempfile.NamedTemporaryFile('w', suffix='.yml', delete=False) as f:
        f.write("correlator:\n  etw_creator_scoring: true\n")
        path = f.name
    try:
        correlator = load_config(path)['correlator']
        assert correlator['etw_creator_scoring'] is True
        assert correlator['witness_check'] is True and correlator['witness_window_seconds'] == 5.0
    finally:
        os.unlink(path)


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for t in tests:
        t()
        print(f"  ok  {t.__name__}")
    print(f"OK ({len(tests)} checks)")
