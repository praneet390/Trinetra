<div align="center">

<img src="assets/banner.svg" alt="Trinetra — Three-Sensor Windows EDR" width="100%"/>

*In Hindu mythology, Shiva's third eye perceives what the other two cannot — it sees through illusion, burns what is hidden. The name fits.*

![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11%20x64-0078D4)
![Python](https://img.shields.io/badge/python-3.11%2B-3776AB)
![Driver](https://img.shields.io/badge/kernel%20driver-WDM-5C2D91)
![Tested](https://img.shields.io/badge/tested-Windows%2011%20build%2026100-brightgreen)
![License](https://img.shields.io/badge/license-MIT-green)

</div>

---

**Trinetra is an open-source Windows EDR that monitors endpoint activity through three independent sensors — Sysmon, kernel ETW, and a custom kernel-mode driver — and fuses their output to detect threats that any single sensor misses.**

Every Windows monitoring approach has gaps it cannot close on its own. Sysmon can be made to record the wrong parent process. ETW's kernel telemetry carries no command-line data — by design, regardless of configuration. Neither can intercept credential-access attempts against protected system processes before they happen. Attackers who understand these constraints can craft techniques that walk through any single-sensor deployment undetected.

Trinetra's answer is correlation: run all three simultaneously, cross-check every event, and treat sensor disagreement as a detection in its own right. When ETW and Sysmon report the same process but claim different parents, a `[TELEMETRY_CONTRADICTION]` alert fires. When the kernel driver witnesses a process the ETW session never reported within a 5-second window, that's a `[SENSOR-BLINDSPOT]` — catching ETW session tampering per event, not on a 60-second heartbeat. The kernel driver also intercepts LSASS handle requests at the pre-operation stage, before the handle is granted and before Windows can block the observer — something Sysmon's EventID 10 structurally cannot do. The agent protects itself the same way: external handles to the Trinetra process are stripped of terminate and inject rights at the kernel, so `taskkill /F` fails before it lands. Every mitigation is preceded by a forensic snapshot of the full process ancestry chain — the evidence is captured before the process is gone. And the tool is honest about what it cannot see: a four-state health model qualifies every dashboard tile when a sensor degrades, so a quiet console genuinely means quiet, not blind.

In ablation testing on Windows 11 build 26100, no individual sensor detected more than 3 of 5 attack scenarios. **All three fused: 5/5.** The gaps are structural — not a configuration problem, not a tuning problem. Fusion is the only configuration that reaches full coverage.

---

## Architecture

```mermaid
flowchart LR
    K[sensor.sys<br/>WDM driver] -->|PROC-CREATE · LSASS-ACCESS<br/>DRIVER-LOAD| C
    E[ETW<br/>Kernel-Process] -->|ProcessStart| C
    S[Sysmon<br/>Event Log] -->|EventID 1/10/11/13| C
    C[ProcessCorrelator<br/>fuse · dedup · witness] --> H
    P[StaticScanner<br/>PE · IAT · entropy] --> H
    M[ModuleInspector<br/>30s sweep · dwell] --> H
    R[RuleEngine<br/>YAML · Sigma] --> H
    H{{HeuristicEngine<br/>score + decay}} -->|≥ 50| W[Forensic snapshot]
    H -->|≥ 80| X[Suspend + Terminate]
    H --> D[Dashboard :8787]
    HW[SensorHealth<br/>HEALTHY → CRITICALLY_BLIND] -.->|caveat banner| D
```

`ProcessCorrelator` is the fusion layer: every event is matched by PID within a 2-second window, claimed parent PIDs are cross-checked between all three sensors, and any discrepancy that survives deduplication surfaces as a named alert. Each sensor operates independently — one going dark degrades the configuration; it does not halt detection.

---

## What each sensor sees

| Field | Sysmon | ETW | Kernel driver |
|---|:-:|:-:|:-:|
| `CommandLine` | ✅ | ❌ | ❌ |
| `ParentImage` path | ✅ | ❌ | ❌ |
| Claimed parent PID | ✅ | ✅ | ✅ |
| **Real** creator PID | ❌ | ⚠️ | ✅ ground truth |
| LSASS handle requests | ❌ PPL blocks | ❌ | ✅ pre-operation |
| Kernel driver loads | ❌ | ❌ | ✅ real-time |
| Cross-sensor contradiction | — | — | ✅ |

> ⚠️  ETW's `EventHeader.ProcessId` carries the creating process — event delivery metadata, not a declared manifest field. A process that tunnels events through a surrogate can spoof this value. The kernel driver's `PsSetCreateProcessNotifyRoutineEx` callback is immune.

The ETW and Sysmon blind spots are structural — no configuration change closes them. The kernel driver closes both, while Sysmon provides the command-line visibility the kernel lacks. Fusion is the only complete picture.

---

## Sensor ablation study

Five attack scenarios run against each sensor configuration in isolation, then fused. Tested live on **Windows 11 build 26100** (`attack_run_20261031_223251`).

| Scenario | MITRE | All Three | Kernel only | Sysmon only | ETW only |
|---|---|:-:|:-:|:-:|:-:|
| PPID Spoof | T1134.004 | ✅ (80) | ✅ (80) | ❌ | ❌ |
| LSASS Access (pre-PPL) | T1003.001 | ✅ (70) | ✅ (70) | ❌ | ❌ |
| Kernel Driver Load | — | ✅ (20) | ✅ (20) | ❌ | ❌ |
| Defender Tamper | T1562.001 | ✅ (90) | ❌ | ✅ (90) | ❌ |
| Office LOLBin | T1204.002 | ✅ (60) | ❌ | ✅ (60) | ❌ |
| **Coverage** | | **5 / 5** | **3 / 5** | **2 / 5** | **0 / 5** |

Each ❌ is a structural guarantee:

- **Sysmon** cannot verify the real process creator (`PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` spoofs the claimed parent silently) and PPL rejects LSASS handle requests before EventID 10 can fire.
- **Kernel driver** carries no command line — `PsSetCreateProcessNotifyRoutineEx` simply does not provide it. Command-line-dependent detections structurally cannot fire.
- **ETW alone scores 0/5.** `ProcessStart` exposes five fields. `CommandLine` and `ParentImage` are absent from the provider manifest — not configurable, not fixable. 35 live events confirmed: both `null` on every one.

---

## Capabilities

**Kernel-verified PPID detection** — A process can claim any parent via `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`. Sysmon and ETW log the claim. The kernel driver reads the real creator PID from `PsSetCreateProcessNotifyRoutineEx`, which cannot be spoofed.

**Pre-operation LSASS interception** — PPL blocks Sysmon's EventID 10 before it fires against `lsass.exe`. `ObRegisterCallbacks` runs at the pre-operation stage — before the handle is granted, before PPL can close the observer out. Confirmed across three test runs.

**Cross-sensor contradiction detection** — When ETW and Sysmon report the same process but disagree on the parent PID, a `[TELEMETRY_CONTRADICTION]` alert fires. Never silently resolved.

**Per-event sensor blindspot detection** — If the kernel driver and ETW disagree on whether a process was created within a 5-second window, a `[SENSOR-BLINDSPOT]` alert fires. Detects ETW session tampering per event, not on a 60-second heartbeat.

**Driver-level self-protection** — `ObRegisterCallbacks` strips `PROCESS_TERMINATE`, `PROCESS_VM_WRITE`, and `PROCESS_CREATE_THREAD` from any external handle opened against the agent process. `taskkill /F` fails at the kernel.

**Scored, decaying threat model** — Per-process cumulative score with time-decay (~20 pts/min). Forensic snapshot at 50, suspend + terminate at 80. Trusted-path discounts apply — a PPID spoof from a known COM broker scores 20 instead of 80; an LSASS access from System32 scores 30 instead of 70. These resolved live false positives against Outlook and VS Code before shipping.

**Static PE analysis + live memory sweep** — Section entropy, RWX segments, import hash, IAT injection primitives, parsed from bytes, never executed. Parallel 30-second module sweep: anonymous RWX regions, staging-path DLLs, true dwell-time tracking.

**Sensor health state machine** — `HEALTHY / DEGRADED / PARTIALLY_BLIND / CRITICALLY_BLIND`. The dashboard qualifies its own "0 alerts" tiles when visibility is reduced — it never silently lies about what it can see.

---

## Detection reference

| Detection | Score | MITRE |
|---|:-:|---|
| Defender service / real-time protection disabled | 90 | T1562.001 |
| Kernel-verified PPID spoofing | 80 | T1134.004 |
| Ransomware-style file-write burst (60 renames / 20 s) | 80 | T1486 |
| LSASS memory access — dangerous access mask | 70 | T1003.001 |
| Office app spawned LOLBin | 60 | T1204.002 |
| `svchost.exe` hollowing-class access | 50 | T1055.012 |
| Obfuscated / download-execute PowerShell | 45 | T1059.001 |
| Run-key persistence write | 40 | T1547.001 |
| Execution from staging directory | 30 | T1036 |
| Kernel-mode driver loaded | 20 | — |
| Injected module / anonymous RWX region | 35–60 | T1055 |
| Static PE findings | 25–70 | various |

---

## Safety model

Trinetra can terminate processes. The floor exists because of two real incidents: a rule that auto-killed VS Code twice, and a false positive that suspended `csrss.exe` and froze the OS.

- **Hardcoded, not configurable** — the protected-process list, access-mask bitmasks, and tamper patterns are constants. A bad config file cannot loosen them.
- **Protected floor** — PIDs 0 and 4, the agent itself, and core OS processes (`csrss.exe`, `lsass.exe`, `winlogon.exe`, `services.exe`, `svchost.exe`, and others) can never be scored or mitigated.
- **Forensic snapshot before action** — process ancestry chain captured before any mitigation; unrecoverable from a dead process.

To observe without kill risk: comment out `self.mitigate(pid)` in `HeuristicEngine._check_threshold()`.

---

## Installation

> Windows 10/11 x64, Python 3.11+, run **elevated**. Use a disposable VM.

**1. Clone and install dependencies**
```powershell
git clone https://github.com/praneet390/Entity_2.0
cd Entity_2.0
python -m venv .venv
.venv\Scripts\pip install pefile psutil pywin32 pyyaml pywintrace
```

**2. Install Sysmon**
```powershell
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile Sysmon.zip
Expand-Archive Sysmon.zip -DestinationPath tools\sysmon -Force
cd tools\sysmon; .\Sysmon64.exe -accepteula -i ..\..\tools\sysmon\config.xml
```

**3. Install the kernel driver** *(optional — without it, the agent runs on Sysmon + ETW only)*

Run once as Administrator, reboot once:
```bat
install.bat
```

**4. Optional threat-intel enrichment** — MalwareBazaar metadata only; binaries are never downloaded.
```powershell
$env:MALWAREBAZAAR_AUTH_KEY = "..."   # free key from auth.abuse.ch; never commit it
python tools\threat_intel_sync.py --recent 100
```

---

## Usage

```powershell
# Live dashboard — http://127.0.0.1:8787
cd src
..\.venv\Scripts\python.exe web_server.py

# Headless agent
..\.venv\Scripts\python.exe main.py

# Failure-injection lab
python failure_lab.py

# Tests
python -m pytest
```

---

## Project layout

```
src/             agent, sensors, correlator, engine, dashboard server
  webapp/        dashboard frontend
driver/sensor/   sensor.c, sensor.sys, EntityDriverCert.cer
rules/           sigma.yml, static.yar, family_signatures.yar, custom/
config/          detection.yml
tools/           extract_features.py, threat_intel_sync.py, sysmon/config.xml
data/            binaries.json, known_imphashes.json
install.bat      one-shot driver cert + test-signing setup
```
