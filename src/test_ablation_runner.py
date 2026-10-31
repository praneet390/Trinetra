"""
Tests for ablation_runner.py.

Validates that:
  1. Each scenario produces a finding under the "all_three" config.
  2. Each scenario is correctly missed under the sensor configs that
     structurally cannot observe it.
  3. The kernel-exclusive scenarios (PPID spoof, LSASS, driver load)
     produce no finding under sysmon_only or etw_only.
  4. The Sysmon-exclusive scenarios (defender_tamper, office_lolbin)
     produce no finding under kernel_only or etw_only.
  5. The output formatters don't raise and produce non-empty strings.

These tests run without any Windows dependencies: the engine's dispatch
path for the relevant check IDs is exercised through pure Python; no
Sysmon service, ETW subscription, or kernel driver is needed.
"""

import pytest

from ablation_runner import (
    SCENARIOS,
    SENSOR_CONFIGS,
    run_ablation,
    _run_scenario,
    _BASE_PID,
    format_table,
    format_json,
    format_csv,
    format_latex,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _result(scenario_id, config_id, results):
    for r in results:
        if r['scenario_id'] == scenario_id and r['config_id'] == config_id:
            return r
    raise KeyError(f"No result for ({scenario_id!r}, {config_id!r})")


# ---------------------------------------------------------------------------
# All-three config: every scenario must produce a finding
# ---------------------------------------------------------------------------

@pytest.mark.parametrize('scenario', SCENARIOS, ids=[s['id'] for s in SCENARIOS])
def test_all_three_detects_every_scenario(scenario):
    active = frozenset({'sysmon', 'etw', 'kernel'})
    result = _run_scenario(scenario, active, _BASE_PID + 1)
    assert result['detected'], (
        f"Scenario '{scenario['id']}' was not detected with all three sensors active. "
        f"Score={result['score']}, expected_checks={result['expected_check_ids']}"
    )


# ---------------------------------------------------------------------------
# Kernel-exclusive scenarios: sysmon_only and etw_only must both miss
# ---------------------------------------------------------------------------

KERNEL_EXCLUSIVE = ['ppid_spoof', 'ppid_spoof_trusted', 'lsass_access', 'driver_load']


@pytest.mark.parametrize('scenario_id', KERNEL_EXCLUSIVE)
def test_kernel_exclusive_missed_by_sysmon_only(scenario_id):
    scenario = next(s for s in SCENARIOS if s['id'] == scenario_id)
    active = frozenset({'sysmon'})
    result = _run_scenario(scenario, active, _BASE_PID + 2)
    assert not result['detected'], (
        f"Kernel-exclusive scenario '{scenario_id}' was unexpectedly detected "
        f"on sysmon_only. Score={result['score']}"
    )


@pytest.mark.parametrize('scenario_id', KERNEL_EXCLUSIVE)
def test_kernel_exclusive_missed_by_etw_only(scenario_id):
    scenario = next(s for s in SCENARIOS if s['id'] == scenario_id)
    active = frozenset({'etw'})
    result = _run_scenario(scenario, active, _BASE_PID + 3)
    assert not result['detected'], (
        f"Kernel-exclusive scenario '{scenario_id}' was unexpectedly detected "
        f"on etw_only. Score={result['score']}"
    )


@pytest.mark.parametrize('scenario_id', KERNEL_EXCLUSIVE)
def test_kernel_exclusive_detected_by_kernel_only(scenario_id):
    scenario = next(s for s in SCENARIOS if s['id'] == scenario_id)
    active = frozenset({'kernel'})
    result = _run_scenario(scenario, active, _BASE_PID + 4)
    assert result['detected'], (
        f"Kernel-exclusive scenario '{scenario_id}' was missed even on kernel_only. "
        f"Score={result['score']}"
    )


# ---------------------------------------------------------------------------
# Sysmon-exclusive scenarios: kernel_only and etw_only must both miss
# ---------------------------------------------------------------------------

SYSMON_EXCLUSIVE = ['defender_tamper', 'office_lolbin']


@pytest.mark.parametrize('scenario_id', SYSMON_EXCLUSIVE)
def test_sysmon_exclusive_missed_by_kernel_only(scenario_id):
    scenario = next(s for s in SCENARIOS if s['id'] == scenario_id)
    active = frozenset({'kernel'})
    result = _run_scenario(scenario, active, _BASE_PID + 5)
    assert not result['detected'], (
        f"Sysmon-exclusive scenario '{scenario_id}' was unexpectedly detected "
        f"on kernel_only. Score={result['score']}"
    )


@pytest.mark.parametrize('scenario_id', SYSMON_EXCLUSIVE)
def test_sysmon_exclusive_missed_by_etw_only(scenario_id):
    scenario = next(s for s in SCENARIOS if s['id'] == scenario_id)
    active = frozenset({'etw'})
    result = _run_scenario(scenario, active, _BASE_PID + 6)
    assert not result['detected'], (
        f"Sysmon-exclusive scenario '{scenario_id}' was unexpectedly detected "
        f"on etw_only. Score={result['score']}"
    )


@pytest.mark.parametrize('scenario_id', SYSMON_EXCLUSIVE)
def test_sysmon_exclusive_detected_by_sysmon_only(scenario_id):
    scenario = next(s for s in SCENARIOS if s['id'] == scenario_id)
    active = frozenset({'sysmon'})
    result = _run_scenario(scenario, active, _BASE_PID + 7)
    assert result['detected'], (
        f"Sysmon-exclusive scenario '{scenario_id}' was missed on sysmon_only. "
        f"Score={result['score']}"
    )


# ---------------------------------------------------------------------------
# Full run integrity
# ---------------------------------------------------------------------------

def test_run_ablation_returns_complete_matrix():
    results = run_ablation()
    expected_count = len(SCENARIOS) * len(SENSOR_CONFIGS)
    assert len(results) == expected_count, (
        f"Expected {expected_count} result rows, got {len(results)}"
    )


def test_run_ablation_all_three_column_all_detected():
    results = run_ablation()
    all_three = [r for r in results if r['config_id'] == 'all_three']
    for r in all_three:
        assert r['detected'], (
            f"Scenario '{r['scenario_id']}' not detected with all three sensors"
        )


def test_run_ablation_scores_are_non_negative():
    results = run_ablation()
    for r in results:
        assert r['score'] >= 0, f"Negative score in result: {r}"


# ---------------------------------------------------------------------------
# Score sanity for specific scenarios
# ---------------------------------------------------------------------------

def test_ppid_spoof_score_is_80_kernel_only():
    scenario = next(s for s in SCENARIOS if s['id'] == 'ppid_spoof')
    active = frozenset({'kernel'})
    result = _run_scenario(scenario, active, _BASE_PID + 20)
    assert result['score'] == 80.0, (
        f"PPID spoof (untrusted creator) should score 80 on kernel-only, got {result['score']}"
    )


def test_defender_tamper_score_is_90_sysmon_only():
    scenario = next(s for s in SCENARIOS if s['id'] == 'defender_tamper')
    active = frozenset({'sysmon'})
    result = _run_scenario(scenario, active, _BASE_PID + 21)
    assert result['score'] == 90.0, (
        f"Defender tamper should score 90 on sysmon-only, got {result['score']}"
    )


def test_office_lolbin_score_is_60_sysmon_only():
    scenario = next(s for s in SCENARIOS if s['id'] == 'office_lolbin')
    active = frozenset({'sysmon'})
    result = _run_scenario(scenario, active, _BASE_PID + 22)
    assert result['score'] == 60.0, (
        f"Office LOLBin should score 60 on sysmon-only, got {result['score']}"
    )


def test_driver_load_score_is_20_kernel_only():
    scenario = next(s for s in SCENARIOS if s['id'] == 'driver_load')
    active = frozenset({'kernel'})
    result = _run_scenario(scenario, active, _BASE_PID + 23)
    assert result['score'] == 20.0, (
        f"Driver load should score 20 on kernel-only, got {result['score']}"
    )


# ---------------------------------------------------------------------------
# Formatters: smoke tests (non-empty, no exceptions)
# ---------------------------------------------------------------------------

@pytest.fixture(scope='module')
def full_results():
    return run_ablation()


def test_format_table_non_empty(full_results):
    out = format_table(full_results)
    assert 'DETECTED' in out or '✓' in out
    assert 'MISSED' in out or '✗' in out
    assert len(out) > 200


def test_format_json_valid(full_results):
    import json
    out = format_json(full_results)
    parsed = json.loads(out)
    assert isinstance(parsed, list)
    assert len(parsed) == len(SCENARIOS) * len(SENSOR_CONFIGS)


def test_format_csv_has_header(full_results):
    out = format_csv(full_results)
    assert out.startswith('scenario_id,')
    lines = out.strip().splitlines()
    assert len(lines) == len(SCENARIOS) * len(SENSOR_CONFIGS) + 1  # +1 header


def test_format_latex_contains_tabular(full_results):
    out = format_latex(full_results)
    assert r'\begin{tabular}' in out
    assert r'\checkmark' in out
    assert r'\times' in out
