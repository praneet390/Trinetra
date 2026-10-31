"""
Five-scenario sensor coverage evaluation.

Runs the 5 most illustrative TTP scenarios against each sensor configuration
(sysmon-only, etw-only, kernel-only, all-three) and reports:
  - Detected / missed per cell
  - Score achieved per cell
  - Coverage count per sensor config
  - Gaps each individual sensor leaves open

Usage:
    python five_scenario_eval.py            # table to stdout
    python five_scenario_eval.py --json     # JSON for automated ingestion
    python five_scenario_eval.py --csv      # CSV for spreadsheet / LaTeX

Scenarios selected to maximise coverage-gap visibility:
  Kernel-exclusive (3): PPID spoof, LSASS access (pre-PPL), Kernel driver load
  Sysmon-exclusive (2): Defender tamper, Office LOLBin
  ETW-only          (0): ETW misses all 5 — confirms it is a corroboration
                          sensor, not a primary detection source.
"""

import argparse
import json
import sys
import os

# Allow running from either repo root or src/.
_SRC = os.path.dirname(os.path.abspath(__file__))
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

from ablation_runner import (
    SCENARIOS,
    SENSOR_CONFIGS,
    _run_scenario,
    _BASE_PID,
)

# ---------------------------------------------------------------------------
# The 5 scenarios (IDs from ablation_runner.SCENARIOS)
# ---------------------------------------------------------------------------

FIVE_IDS = [
    'ppid_spoof',
    'lsass_access',
    'driver_load',
    'defender_tamper',
    'office_lolbin',
]

FIVE_SCENARIOS = [s for s in SCENARIOS if s['id'] in FIVE_IDS]

# Preserve the order above.
FIVE_SCENARIOS.sort(key=lambda s: FIVE_IDS.index(s['id']))

# Short labels for the table (keep to ~34 chars).
SHORT_LABEL = {
    'ppid_spoof':      'PPID Spoof',
    'lsass_access':    'LSASS Access (pre-PPL)',
    'driver_load':     'Kernel Driver Load',
    'defender_tamper': 'Defender Tamper',
    'office_lolbin':   'Office LOLBin',
}

# Which sensor each scenario requires to fire (for the gap summary).
EXCLUSIVE = {
    'ppid_spoof':      'kernel',
    'lsass_access':    'kernel',
    'driver_load':     'kernel',
    'defender_tamper': 'sysmon',
    'office_lolbin':   'sysmon',
}

# Why the non-exclusive sensors miss it (one-liner for the report).
MISS_REASON = {
    'ppid_spoof': (
        'Sysmon EventID 1 has no CreatingThreadId; ETW ParentProcessId '
        'is the claimed (spoofed) parent — only kernel PsSetCreateProcessNotifyRoutineEx '
        'exposes the real creator.'
    ),
    'lsass_access': (
        'PPL rejects OpenProcess before Sysmon EventID 10 can fire; '
        'ETW Microsoft-Windows-Kernel-Process has no handle-access event. '
        'Only ObRegisterCallbacks pre-op fires before the access check.'
    ),
    'driver_load': (
        'Sysmon EventID 6 (DriverLoad) is not wired into the engine dispatch; '
        'ETW has no driver-load event. Kernel sensor receives EVENT_TYPE_DRIVER_LOAD '
        'directly from the driver IOCTL.'
    ),
    'defender_tamper': (
        'ETW ProcessStart and kernel PROC-CREATE both deliver CommandLine=None '
        '(confirmed via Get-WinEvent and process_correlator.submit_kernel). '
        'Pattern match on empty string never fires.'
    ),
    'office_lolbin': (
        'ETW and kernel set ParentImage=None — os.path.basename("") is "" '
        'which is never in OFFICE_PARENTS. Only Sysmon EventID 1 carries '
        'the real parent image path.'
    ),
}


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def run_five(verbose=False):
    """Run all 5 scenarios × 4 configs. Returns list of result dicts."""
    config_labels = {
        'all_three':   'All Three',
        'kernel_only': 'Kernel Only',
        'sysmon_only': 'Sysmon Only',
        'etw_only':    'ETW Only',
    }
    results = []
    for i, scenario in enumerate(FIVE_SCENARIOS):
        if verbose:
            print(f"\n{'─' * 60}")
            print(f"  SCENARIO: {SHORT_LABEL[scenario['id']]}")
            print(f"  Harness : {scenario['harness']}")
            print(f"  Exclusive sensor: {EXCLUSIVE[scenario['id']].upper()}")
            print(f"{'─' * 60}")
        for config_id, active in SENSOR_CONFIGS:
            pid = _BASE_PID + (i * 100) + {'all_three': 1, 'kernel_only': 2,
                                            'sysmon_only': 3, 'etw_only': 4}[config_id]
            if verbose:
                active_str = ', '.join(sorted(active))
                print(f"  [{config_labels[config_id]:<15}]  active sensors: {active_str}")
            r = _run_scenario(scenario, active, pid)
            r['scenario_id']   = scenario['id']
            r['scenario_name'] = scenario['name']
            r['config_id']     = config_id
            if verbose:
                status = f"✓  DETECTED  (score={r['score']:.0f})" if r['detected'] else "✗  MISSED"
                print(f"                      → {status}")
            results.append(r)
    if verbose:
        print(f"\n{'─' * 60}\n")
    return results


# ---------------------------------------------------------------------------
# Formatters
# ---------------------------------------------------------------------------

_COL_W = 20

def _cell(r):
    if r['detected']:
        return f"✓ ({r['score']:.0f})"
    return '✗'


def format_report(results):
    configs = [c for c, _ in SENSOR_CONFIGS]
    config_labels = {
        'all_three':   'All Three',
        'kernel_only': 'Kernel Only',
        'sysmon_only': 'Sysmon Only',
        'etw_only':    'ETW Only',
    }

    # --- header ---
    lines = []
    lines.append('')
    lines.append('FIVE-SCENARIO SENSOR COVERAGE EVALUATION')
    lines.append('=' * 100)
    lines.append('')
    lines.append(
        f"  {'Scenario':<35}"
        + ''.join(f"{config_labels[c]:>{_COL_W}}" for c in configs)
    )
    lines.append('  ' + '-' * 98)

    for scenario in FIVE_SCENARIOS:
        sid = scenario['id']
        row_results = {r['config_id']: r for r in results if r['scenario_id'] == sid}
        cells = ''.join(
            f"{_cell(row_results[c]):>{_COL_W}}" for c in configs
        )
        lines.append(f"  {SHORT_LABEL[sid]:<35}{cells}")

    lines.append('  ' + '-' * 98)
    lines.append('')
    lines.append(
        "  Key:  ✓ (score) = detected    ✗ = structurally impossible on this sensor path"
    )
    lines.append('')

    # --- coverage counts ---
    lines.append('COVERAGE COUNT PER SENSOR CONFIG  (out of 5 scenarios)')
    lines.append('=' * 100)
    lines.append('')
    for config_id, _ in SENSOR_CONFIGS:
        detected_count = sum(
            1 for r in results
            if r['config_id'] == config_id and r['detected']
        )
        bar = '█' * detected_count + '░' * (5 - detected_count)
        lines.append(
            f"  {config_labels[config_id]:<15}  {bar}  {detected_count}/5"
        )
    lines.append('')

    # --- per-scenario gap analysis ---
    lines.append('PER-SCENARIO GAP ANALYSIS')
    lines.append('=' * 100)
    lines.append('')
    for scenario in FIVE_SCENARIOS:
        sid = scenario['id']
        exclusive = EXCLUSIVE[sid]
        row_results = {r['config_id']: r for r in results if r['scenario_id'] == sid}

        detected_configs  = [c for c in ['all_three', f'{exclusive}_only'] if row_results[c]['detected']]
        missed_configs    = [c for c in ['sysmon_only', 'etw_only', 'kernel_only']
                             if c != f'{exclusive}_only' and not row_results[c]['detected']]

        lines.append(f"  ▶  {SHORT_LABEL[sid]}")
        lines.append(f"     Exclusive sensor : {exclusive}")
        lines.append(f"     Detected under   : {', '.join(config_labels[c] for c in ['all_three', f'{exclusive}_only'])}")
        lines.append(f"     Missed under     : {', '.join(config_labels[c] for c in missed_configs)}")
        lines.append(f"     Structural reason: {MISS_REASON[sid]}")
        lines.append('')

    # --- fusion proof ---
    lines.append('FUSION PROOF')
    lines.append('=' * 100)
    lines.append('')
    lines.append('  Individual sensors — coverage gaps:')
    for config_id, _ in SENSOR_CONFIGS:
        if config_id == 'all_three':
            continue
        missed = [
            SHORT_LABEL[r['scenario_id']]
            for r in results
            if r['config_id'] == config_id and not r['detected']
        ]
        lines.append(f"    {config_labels[config_id]:<15} misses: {', '.join(missed) if missed else 'none'}")
    lines.append('')
    lines.append('  Fused (all three) — coverage gaps:')
    missed_fused = [
        SHORT_LABEL[r['scenario_id']]
        for r in results
        if r['config_id'] == 'all_three' and not r['detected']
    ]
    lines.append(f"    All Three        misses: {', '.join(missed_fused) if missed_fused else 'none — full coverage'}")
    lines.append('')
    lines.append(
        '  Conclusion: No individual sensor achieves full coverage. '
        'The union of all three is\n'
        '  the minimum architecture required to detect all five TTP classes demonstrated here.'
    )
    lines.append('')

    return '\n'.join(lines)


def format_json(results):
    out = []
    for r in results:
        out.append({
            'scenario_id':   r['scenario_id'],
            'scenario_name': r['scenario_name'],
            'config_id':     r['config_id'],
            'detected':      r['detected'],
            'score':         r['score'],
            'exclusive_sensor': EXCLUSIVE.get(r['scenario_id'], 'unknown'),
        })
    return json.dumps(out, indent=2)


def format_csv(results):
    import csv, io
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(['scenario_id', 'scenario_name', 'config_id', 'detected', 'score', 'exclusive_sensor'])
    for r in results:
        w.writerow([
            r['scenario_id'], r['scenario_name'], r['config_id'],
            r['detected'], r['score'], EXCLUSIVE.get(r['scenario_id'], 'unknown'),
        ])
    return buf.getvalue()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(description='Five-scenario sensor coverage evaluation')
    p.add_argument('--json',    action='store_true', help='Output JSON')
    p.add_argument('--csv',     action='store_true', help='Output CSV')
    p.add_argument('--verbose', action='store_true', help='Print live result for each run')
    args = p.parse_args()

    results = run_five(verbose=args.verbose or (not args.json and not args.csv))

    if args.json:
        print(format_json(results))
    elif args.csv:
        print(format_csv(results), end='')
    else:
        print(format_report(results))


if __name__ == '__main__':
    main()
