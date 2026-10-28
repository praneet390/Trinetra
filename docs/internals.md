# Internals & reference

> Long-form design notes, rationale and incident history. For the short version see the [README](../README.md).


A from-scratch EDR (Endpoint Detection & Response) agent for Windows. It fuses
**three independent process sensors** — Sysmon, raw ETW, and a custom
**kernel-mode driver** — with static PE analysis and an active process/module
sweep, and feeds everything into one scored heuristic engine that can
auto-mitigate (suspend + terminate) a process that crosses a threat threshold.

The central idea: every sensor has a *structural* blind spot (Sysmon and ETW
only ever see a process's **claimed** parent; ETW and the driver carry no
command line), so the sensors' **disagreement and complementary coverage are
themselves detection signals**. [`reports/evasion_matrix.md`](../reports/evasion_matrix.md)
documents, with live-tested results, which techniques each sensor catches
alone, which only the fusion catches — and the one case (a non-elevated
`OpenProcess` on LSASS) that no sensor in the pipeline can see.

Built and hardened through live-fire testing on a real Windows machine, not
just unit tests — several of the design decisions below exist specifically
because a naive version of that rule produced a real false positive (or
worse) when run against real system activity. Those are called out inline.

---

## Table of contents

- [How it works](#how-it-works)
- [Architecture](#architecture)
- [Kernel telemetry: ETW + Sysmon correlation](#kernel-telemetry-etw--sysmon-correlation)
- [Kernel driver sensor](#kernel-driver-sensor)
- [What each detector actually catches](#what-each-detector-actually-catches)
- [Threat intel sync (MalwareBazaar)](#threat-intel-sync-malwarebazaar)
- [Safety model](#safety-model-read-this-before-running-it)
- [Setup](#setup)
- [Running it](#running-it)
- [Web dashboard](#web-dashboard)
- [Custom detection rules](#custom-detection-rules)
- [Known-good hash allowlist](#known-good-hash-allowlist)
- [Configuration](#configuration)
- [Workflows](#workflows)
- [Project layout](#project-layout)
- [Known limitations / roadmap](#known-limitations--roadmap)
- [Credits / inspiration](#credits--inspiration)

---

## How it works

The agent runs several independent detection surfaces in parallel — three
behavioral sensors (Sysmon, ETW, kernel driver), a static scanner and an active
module sweep — all feeding one shared scoring engine:

1. **Static scan** (`src/static_scanner.py`) — reads pre-extracted PE
   features (`data/binaries.json`, produced offline by
   `tools/extract_features.py`) and scores structural red flags: RWX
   sections, high-entropy sections (packing), dangerous import combinations
   (process injection, keylogging, LSASS dumping), unsigned binaries
   impersonating a known vendor, and "metamorphic clone" detection (two
   files with identical structure but different hashes — the same malware
   family repacked).

2. **Behavioral telemetry — three independent sensors** fused into one
   stream (`src/telemetry_monitor.py`, `src/etw_monitor.py`,
   `src/kernel_sensor.py` + `driver/sensor/sensor.c`,
   `src/process_correlator.py` + `src/heuristic_engine.py`; the driver is
   described in [Kernel driver sensor](#kernel-driver-sensor)): Sysmon's
   `Microsoft-Windows-Sysmon/Operational` event log (`EvtSubscribe`,
   push-based, rich fields) and raw ETW on
   `Microsoft-Windows-Kernel-Process` (`pywintrace`, thinner fields but
   lower latency and independent of Sysmon being installed/configured at
   all) both feed the same scoring engine — see [Kernel telemetry: ETW +
   Sysmon correlation](#kernel-telemetry-etw--sysmon-correlation). Findings
   scored: credential-access attempts against LSASS, process-hollowing
   attempts against `svchost.exe`, Defender-tampering commands, obfuscated
   PowerShell, Office-macro-style dropper chains, Run-key persistence, and
   ransomware-style mass file writes.

3. **Active module sweep** (`src/module_inspector.py`) — every 30 seconds,
   walks the live process table (independent of Sysmon) looking for DLLs
   already mapped into high-value system processes from dropper-style
   staging directories (`Temp`, `Public`, Recycle Bin). This catches
   injection that happened *before* the agent started, or isn't covered by
   the Sysmon config.

4. **Custom rule pack** (`src/rule_engine.py`, optional, additive) — every
   YAML rule under `rules/custom/*.yml` is evaluated alongside the three
   surfaces above, on the exact same events/samples, scored through the
   exact same engine. See [Custom detection rules](#custom-detection-rules).

Every finding adds points to a per-process (or per-file-hash, for static
findings) score in `HeuristicEngine`. Scores **decay over time** (~20
points/minute by default — see [Configuration](#configuration)) so only
activity that compounds *quickly* — the actual shape of an attack chain —
can reach the action thresholds:

| Score | Action |
|---|---|
| ≥ 50 (configurable) | `[WARNING]` logged, simulated memory snapshot (no action taken) |
| ≥ 80 (configurable) | `[CRITICAL THREAT]` — `mitigate()` is called: the process is suspended, then terminated |

## Architecture

```
                    ┌─────────────────────┐
tools/extract_       │  data/binaries.json  │
features.py  ───────▶│  (PE features, once  │
(offline, run         │   per sample set)    │
 manually)            └──────────┬───────────┘
                                  │
                                  ▼
┌──────────────┐        ┌─────────────────┐
│ static_       │──────▶│                 │
│ scanner.py    │        │                 │
└──────────────┘        │                 │
                         │  Heuristic       │      score ≥ 80
┌──────────────┐        │  Engine          │──────────────────▶ mitigate()
│ Sysmon        │─EvtSubscribe→ telemetry_  │  (per-PID /       (suspend +
│ Operational   │        │  monitor.py ─┐   │   per-file-hash    terminate,
│ log           │        │              │   │   scoring,          PROTECTED
└──────────────┘        │              ▼   │   decay,           processes
                         │        Process   │   PID-reuse        refused)
┌──────────────┐        │        Correlator │   guard)
│ Kernel-Process│──ETW trace→ etw_monitor.py│───┘
│ (ETW provider)│        │        (fuses      │
└──────────────┘        │      provisional/   │
                         │      fused events)  │
┌──────────────┐        │                 │
│ module_       │─every─▶│                 │
│ inspector.py  │ 30s     └─────────────────┘
│ (live sweep)  │              ▲
└──────────────┘               │
                    ┌───────────┴───────────┐
                    │  SensorHealth watchdog  │  observes both sensors'
                    │  (sensor_health.py)     │  heartbeats, logs staleness
                    └─────────────────────────┘  (never auto-restarts)
```

`src/main.py` wires all three detection surfaces into one process and keeps
it alive so the Sysmon subscription callback and the periodic module sweep
both keep running.

`telemetry_monitor.py`'s `EvtSubscribe` callback only renders each event's
XML and hands it to a bounded queue (2000 events) before returning
immediately — a separate worker thread drains that queue into the
Heuristic Engine. Scoring (including a `mitigate()` call, which blocks on
`psutil` suspend/terminate) never happens on the OS callback thread, so a
slow scoring pass can't stall or drop buffered Sysmon events — the same
split osquery's `WindowsEventLogPublisher` uses, for the same reason.

## Kernel telemetry: ETW + Sysmon correlation

Behavioral detection runs on **two independent kernel sensors**, not one:

- **Sysmon** (`telemetry_monitor.py`) — the existing `EvtSubscribe` path.
  Rich fields (`CommandLine`, full parent image path), but depends on
  Sysmon being installed and its config covering the right event types.
- **Raw ETW** (`etw_monitor.py`) — consumes
  `Microsoft-Windows-Kernel-Process` directly via
  [`pywintrace`](https://github.com/fireeye/pywintrace) (Apache-licensed,
  pure `ctypes`, no C compiler needed). Needs no Sysmon install at all and
  delivers `ProcessStart` lower-latency than Sysmon's own enrichment
  pipeline — but the raw kernel event only ever carries `ProcessID`,
  `ParentProcessID`, `ImageName`, `CreateTime` (empirically confirmed via
  `Get-WinEvent -ListProvider Microsoft-Windows-Kernel-Process` against a
  real capture). **No `CommandLine`, no parent *image path* (only a parent
  PID)** — a real, permanent gap versus Sysmon, not a bug. Every
  command-line-dependent check (Defender-tampering, obfuscated PowerShell)
  structurally cannot fire on ETW-only data, by design — see
  `HeuristicEngine.evaluate_etw_process_start`'s docstring.

`process_correlator.py`'s `ProcessCorrelator` fuses the two for the same
real process, keyed on PID:

1. ETW's event usually arrives first → dispatched **immediately** as a
   *provisional* finding (`_source: "etw"`), so latency never waits on
   Sysmon.
2. Sysmon's richer event arrives shortly after → held, not dispatched yet.
3. A background GC pass (every 5s) closes out any pending record older
   than `fuse_window` (2.0s, tunable in `config/detection.yml`): if both
   sources arrived, dispatch once more as *fused* (`_source: "fused"`,
   carrying Sysmon's `CommandLine`/`ParentImage`); if only Sysmon arrived
   (ETW down or missed it), dispatch as `_source: "sysmon"` — matching
   pre-correlator behavior exactly.

A dedup guard (`HeuristicEngine._score_once`, keyed on `(pid, check_id)`)
stops a non-command-line check (e.g. the staging-directory rule) from
scoring the same real event twice across the provisional and fused
dispatch — command-line-dependent checks never need this, since they
already can't fire on the provisional dispatch's `CommandLine: None`.

**Either sensor can be down without breaking the other.** A
`SensorHealth`/`watchdog_loop` pair (`sensor_health.py`) tracks each
sensor's own heartbeat independently and logs `[WATCHDOG] <name> sensor
stale` on the *transition* into staleness — this is deliberately
**observe-only**, it never attempts to restart a dead sensor (safe
handle-lifecycle management for that needs live-fire testing this
environment can't safely do). The web dashboard's sensor badge and Process
Explorer's Source column (`etw`/`fused`/`sysmon`) surface this live — stop
Sysmon (`sc stop sysmon64`) while the dashboard is running and watch the
Sysmon badge go stale while ETW-sourced rows keep appearing.

`sensor_health.compute_blind_state()` reduces both sensors' labels to one
aggregate visibility state — `HEALTHY` / `DEGRADED` / `PARTIALLY_BLIND` /
`CRITICALLY_BLIND` — surfaced as the dashboard's "Visibility" badge and
exposed via `/api/summary`'s `blind_state` field. `DEGRADED` means one
sensor is down *or dropping events* but another still delivers. A sensor
is "lossy" for 60s after its bounded queue last overflowed: alive and
delivering, but its picture of the endpoint has holes (the dashboard
shows how many events were dropped, and `/api/summary` exposes
`sysmon_dropped_events` / `etw_dropped_events`). A sensor's heartbeat also
only counts an event it could actually use — a Sysmon event with a numeric
`EventID`, an ETW `ProcessStart` with a `ProcessID` — so a stream of
malformed events can't keep a silent sensor looking alive.
`PARTIALLY_BLIND`/`CRITICALLY_BLIND` mean *no* sensor is currently live,
split by whether any telemetry was ever seen this session — a sensor that
died mid-run (`PARTIALLY_BLIND`) is a more urgent signal than one that
never came up at all (`CRITICALLY_BLIND`, e.g. running non-elevated). The
watchdog thread also logs every transition of this aggregate state (not
just per-sensor staleness), at a level that escalates with severity, so a
headless `main.py` run without a dashboard watching it still fails loudly.

When both sensors observe the same PID, the correlator also cross-checks
one field both of them independently carry: parent PID. If ETW and Sysmon
disagree about who a process's parent was, that disagreement is logged as
its own `[TELEMETRY_CONTRADICTION]` line — never silently resolved by
whichever field the fused-event merge happens to keep — and shows up on
the dashboard under its own "Telemetry Contradiction" category rather than
folded into a normal-looking process-create alert. Deliberately scoped to
ancestry only for now: it's the one field both current kernel sensors
carry, extend `ProcessCorrelator._check_ancestry_contradiction` once a
file/network/memory sensor feeds the correlator.

One PID-reuse tradeoff, disclosed rather than hidden: because ETW's
`CreateTime` and Sysmon's `UtcTime` arrive in different, not reliably
comparable formats (confirmed by reading `pywintrace`'s source — every ETW
field is rendered through `TdhFormatProperty`, and a `FILETIME` field like
`CreateTime` comes back as a locale-formatted string, not a number), the
correlator keys purely on PID rather than `(pid, timestamp)`. This accepts
the same PID-reuse race window (bounded by `fuse_window`) that
`heuristic_engine.py`'s `_reset_score_if_pid_reused` already documents
elsewhere in this codebase as a known, accepted edge case.

## Kernel driver sensor

`driver/sensor/sensor.c` is a WDM kernel driver (device `\\.\malprojectsensor`)
that gives the agent a third sensor whose answers a user-mode caller cannot
influence. `src/kernel_sensor.py` starts the driver's service, opens its
device, and polls one IOCTL (`GET_EVENT`) that drains a bounded 256-entry
circular queue. Every event carries a sequence number, so a gap is counted as
dropped events and surfaces through the same `SensorHealth` / blind-state
machinery as Sysmon and ETW.

| Event | Source in the driver | What it gives the engine |
|---|---|---|
| Process create | `PsSetCreateProcessNotifyRoutineEx` | The **real creator PID** (`CreatingThreadId`), compared with the claimed parent PID. A mismatch is kernel-verified parent-PID spoofing (`PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`), which Sysmon and ETW cannot see past. Also serves as the sensor's heartbeat. |
| LSASS access | `ObRegisterCallbacks` on process handles | Handle requests to `lsass.exe` carrying the same dangerous-rights mask the Sysmon rule uses. **Observe-only.** |
| Driver load | `PsSetLoadImageNotifyRoutine` (kernel-mode images only) | A new kernel driver appearing mid-session. |

Thread-create and ordinary user-mode image-load notifications are registered
too but stay `DbgPrintEx`-only; forwarding them would flood user mode.

**Self-protection.** The agent calls `REGISTER_SELF`; the driver then strips
`PROCESS_TERMINATE`, suspend/resume, create-thread, VM-operation and VM-write
rights from any *other* process's handle to it, so `taskkill /F` and
remote-thread injection against the agent fail. The PID is always the
caller's own, never caller-supplied, and the slot is freed on process exit so
a reused PID does not inherit immunity. This is not driver self-protection:
an administrator can still `sc stop` the driver, and the protection goes with
it.

**Scoring** (`heuristic_engine.py`). A kernel-verified PPID spoof scores +80,
or +20 when the *real creator* resolves under System32/SysWOW64: Windows' own
packaged-app/COM brokers legitimately reparent children, and an unconditional
+80 killed a live Outlook three times in testing. LSASS access scores +70
(+30 for a System32 caller); a driver load scores +20.

**Honest limits** (documented in `sensor.c` and `reports/evasion_matrix.md`):

- Windows' PPL enforcement rejects a lower-privilege caller's `OpenProcess`
  on LSASS *before* any registered Ob callback runs, for any driver. So the
  LSASS sensor only sees callers at a comparable protection level. Closing
  that needs an ELAM-class signed driver, not a code change.
- Like ETW, the driver carries no command line and no parent image path.
- The driver is built for test-signing (see [Building the driver](#building-the-kernel-driver)),
  not production attestation signing. The `ObRegisterCallbacks` altitude is a
  placeholder that would need a properly assigned value in a shipping product.
- A missing or untrusted driver is a normal "sensor unavailable" condition:
  the agent logs it and continues on Sysmon and ETW.

The `driver/sensor/*_test.c` programs are the attack harnesses behind the
evasion matrix (PPID spoof via an untrusted and a trusted broker, LSASS
access, command-line and parent-image blind spots, self-protection, and the
comms channel). They use documented Win32 APIs only and take no destructive
action.

### Self-test: proving the pipeline, not just the process

`sensor_health.py`'s heartbeat/blind-state tracking proves a sensor's
*thread* is alive — it can't prove that thread is actually seeing real
events. `self_test.py` closes that gap: every `interval_seconds` (default
300, `config/detection.yml`'s `self_test:` section), it spawns one real,
inert child process (`cmd.exe /c exit 0` — parent is this agent's own
process, never an `OFFICE_PARENTS` process, so `heuristic_engine.py`'s
LOLBin rule structurally cannot fire on it) and polls for up to
`timeout_seconds` to confirm *that exact PID* was actually reported by
telemetry. In `web_server.py` it also round-trips a canary line through
the real logging → `AlertStore` pipeline to prove alert generation itself
is wired. Failures log `[SELF-TEST] FAILED: ...` at `CRITICAL` (fails
loudly, per the architectural principle below); results are logged only on
transition (pass↔fail), like the watchdog's staleness tracking, so a
healthy pipeline doesn't spam the alert feed every cycle.

Scoped honestly: this only tests what this agent actually has a
sensor for — process-create visibility and (dashboard-only) alert
generation. It makes no claim about file, memory, network, or
cloud-delivery visibility, because no sensor for those exists here yet.

### Negative-evidence protection: "no activity" vs. "couldn't observe"

A dashboard showing "0 Critical Threats" is easy to misread as "confirmed
clean" — but if the endpoint is currently blind, it just means nothing was
seen, not that nothing happened. `sensor_health.negative_evidence_caveat()`
turns `blind_state` into that exact distinction: `None` only when
`blind_state` is `HEALTHY` (the counts *are* reliable negative evidence),
otherwise a short explanation scaled to how blind the endpoint actually is
— a `DEGRADED` endpoint still has one live sensor, a `CRITICALLY_BLIND` one
has none at all, and the two get different wording, not one generic
warning reused everywhere. `web_server.py`'s `/api/summary` exposes both
`negative_evidence_reliable` (bool) and `visibility_caveat` (the text) —
the dashboard renders the latter as a banner directly above the alert-count
tiles it qualifies, hidden entirely when visibility is healthy.

### Failure-injection lab: proving the reaction, not just the happy path

`failure_lab.py` deliberately breaks the telemetry pipeline and checks the
EDR reacts correctly — detects the failure, records what was lost, changes
health state, falls back to the surviving sensor, reduces confidence,
alerts loudly on total loss, and recovers — while measuring how long each
step took.

```bash
cd src
python failure_lab.py                  # all scenarios
python failure_lab.py sysmon_silence   # selected scenarios
python failure_lab.py --list
python failure_lab.py --json report.json
```

| Scenario | Fault injected |
|---|---|
| `sysmon_silence` / `etw_silence` | One sensor goes quiet, the other keeps working |
| `total_silence` | Both sensors go quiet after telemetry had been flowing |
| `cold_start_blind` | No sensor ever comes up (e.g. not elevated) |
| `etw_only_total_loss` | Sysmon not deployed, the only sensor dies mid-run |
| `queue_flood` | Burst overflows a stalled consumer's bounded queue |
| `malformed_input` | Garbage fed to both sensor callbacks |
| `sensor_contradiction` | ETW and Sysmon disagree about a parent PID |

**What is real vs. synthetic.** The ETW/Sysmon callbacks, bounded queues,
scoring workers, `ProcessCorrelator`, `HeuristicEngine`, `SensorHealth`,
`watchdog_loop` and the blind-state logic are the production code, unmodified.
Only the OS event source is synthetic — events are fabricated and fed in
through the same callbacks the kernel/Event Log would call (with string
field values, matching what pywintrace really produces). **It is
software-only and safe**: no service is stopped, no ETW session is touched,
nothing needs elevation; synthetic PIDs start at 2,000,000,000 (outside the
real PID range), `mitigate()` is replaced with a recorder, and every
scenario asserts it was never called and nothing was scored. Because it
swaps the root logger's handlers to capture the EDR's own output, run it
standalone, never inside the live dashboard process.

**Measured detection latency** is ≈ the sensor `stale_after` threshold (the
lab uses 0.4s so it runs fast; production defaults to 60s) plus at most one
watchdog tick; recovery is near-instant because a heartbeat clears staleness
immediately. Each scenario reports its own numbers.

**What it found in this codebase** (all fixed, all now guarded by mutation
tests in `test_failure_lab.py`):

1. Total loss of visibility mid-run (`PARTIALLY_BLIND`) was logged at `ERROR`,
   which the dashboard displays as only a WARNING — while the never-started
   case was `CRITICAL`. Both no-sensor-live states now log at `CRITICAL`.
2. `HeuristicEngine.total_events_seen` never counts events arriving through
   the correlator's ETW path, so an ETW-only deployment (no Sysmon) that lost
   its sensor mid-run was reported as `CRITICALLY_BLIND` ("never worked")
   instead of `PARTIALLY_BLIND`. "Telemetry seen" now also counts any
   sensor's own heartbeat (`sensor_health.current_blind_state`).
3. Event drops from a full queue were only logged: 349 ETW events could be
   lost while `blind_state` stayed `HEALTHY`. Each drop is now recorded on
   the sensor, which turns `lossy` (→ `DEGRADED`, the caveat banner, and a
   `[WATCHDOG] ... dropping events` log naming the count) until the drops
   stop. The lab also checks the drop counter agrees with the log record.
4. The Sysmon heartbeat was content-agnostic: unparseable events kept a
   silent sensor "live". It now needs a numeric `EventID` (a cheap pattern
   check on the callback thread — checked against 600 real events from four
   Windows channels, including classic `<EventID Qualifiers='0'>` events).
   The ETW equivalent, a `ProcessStart` with no `ProcessID`, is closed too.
   Both were originally reported as "known gaps" by the lab itself.

**Known gaps.** A scenario can record a weakness it observed with
`lab.gap(...)`: it is reported as `KNOWN GAP` but does not fail the run, so
real weaknesses are documented rather than encoded as expected behavior.
None are open right now — the two it originally reported are fixed and
checked (see above).

**Scope.** It tests what this agent actually has: process-create
telemetry from two sensors, the correlator, health/blind-state, and the log
pipeline. It makes no claim about file, memory, network, or cloud-delivery
failures because no sensor for those exists here, and it does not stop real
services — that needs a disposable VM, which is what the next section does.

### Live evaluation in a VM (`vm_eval.py`)

The lab above uses synthetic events. `vm_eval.py` is the real thing: run it
inside a disposable VM next to a running `web_server.py`, and it launches
harmless emulations of attacker techniques, then reads the agent's own
`/api/alerts` and `/api/summary` to score what it noticed.

```powershell
python vm_eval.py --list                     # scenarios, no side effects
python vm_eval.py --vm                       # attacks + benign corpus (elevated shell)
python vm_eval.py --vm --sensor-kill         # also stop/restart the Sysmon service
python vm_eval.py --vm --json ..\reports\vm_eval.json
```

Per scenario it reports detected/missed, time to alert, peak score and
whether the agent auto-mitigated. Nothing is downloaded, disabled, injected
or encrypted: the Defender-tamper command is only printed, the download
cradle targets a refused loopback port, the LSASS test opens and closes a
handle without reading, the shadow-copy delete uses a nil GUID, and the
Run key, scheduled task, service and files are removed afterwards.

- **Rule-backed scenarios** (encoded PowerShell, download cradle, Office
  parent, staging-directory exec, Defender tamper, Run key, LSASS handle,
  ransomware-style burst) must be detected; a miss fails the run.
- **Gap scenarios** (scheduled task, service creation, shadow-copy delete,
  certutil) have no rule today. They are reported as `NO RULE` — a coverage
  map, not a failure — and flip to `DETECTED*` if a rule is added later.
- **Benign corpus**: ordinary commands, several containing text that older
  rules false-positived on (`grep -E`, `sed -e`, `Set-MpPreference`). Any
  alert or mitigation is a `FALSE POSITIVE` and fails the run.
- **`--sensor-kill`**: stops Sysmon while ETW keeps delivering, and checks
  the sensor goes stale, `blind_state` becomes `DEGRADED`, the caveat is
  raised, the watchdog logs it, and everything recovers to `HEALTHY` after
  the service restarts. The service is always restarted, even on failure.

It refuses to run without `--vm` and without elevation, and refuses to start
unless both sensors are live (an idle VM starts so few processes that a
healthy ETW sensor can look stale; the harness warms it up first).
`test_vm_eval.py` checks every launcher against the real engine rules
without starting any scenario process, so a rule change that silently breaks
a scenario fails the test suite.

Not covered, on purpose: process injection, parent-PID spoofing and log
clearing (no safe emulation that proves a distinct signal).

## What each detector actually catches

| Detector | File | MITRE-ish technique |
|---|---|---|
| RWX / high-entropy sections | `static_scanner.py` | Packing / injected code |
| Injection & keylogger IAT patterns | `static_scanner.py` | T1055 injection, T1056 keylogging |
| LSASS dump IAT pattern (`MiniDumpWriteDump`+`OpenProcess`) | `static_scanner.py` | T1003.001 |
| Vendor-impersonation (unsigned + claims Microsoft/Google/etc.) | `static_scanner.py` | T1036 masquerading |
| Metamorphic clone detection | `static_scanner.py` | Polymorphic malware family clustering |
| AMSI bypass pattern (`AmsiScanBuffer`+`VirtualProtect`) | `static_scanner.py` | T1562.001 |
| ETW patch/evasion pattern (`EtwEventWrite`+`VirtualProtect`) | `static_scanner.py` | T1562.006 |
| SeDebugPrivilege-style acquisition precursor | `static_scanner.py` | T1134 |
| Direct native (`Nt*`/`Zw*`) syscalls + injection APIs | `static_scanner.py` | T1055 (usermode-hook evasion) |
| Bulk file enumeration + crypto API | `static_scanner.py` | T1486 (static ransomware precursor) |
| Crypto-clipper / webhook / paste-site / IP-literal C2 strings | `static_scanner.py` | T1027, T1102, T1071 |
| Imphash match against known-family intel | `static_scanner.py` | Family clustering (see [Threat intel sync](#threat-intel-sync-malwarebazaar)) |
| Execution from staging dirs (`Temp`, `Public`) | `heuristic_engine.py` | T1036 / T1105 |
| Defender-tamper command lines (only on processes that execute them: PowerShell, `cmd`, `sc`, `net`/`net1`, `taskkill`, `reg`) | `heuristic_engine.py` | T1562.001 |
| Obfuscated/download-execute PowerShell (PowerShell hosts only: `powershell.exe`/`pwsh.exe`, or a renamed copy via Sysmon's `OriginalFileName`) | `heuristic_engine.py` | T1059.001, T1027 |
| Office app → LOLBin child process | `heuristic_engine.py` | T1204.002 |
| LSASS credential access (real bitmask check) | `heuristic_engine.py` | T1003.001 |
| Process hollowing via `svchost.exe` access | `heuristic_engine.py` | T1055.012 |
| Run-key persistence | `heuristic_engine.py` | T1547.001 |
| Ransomware-style file-write burst | `heuristic_engine.py` | T1486 |
| Injected module in a high-value process | `module_inspector.py` | T1055 |

Matching Sigma rules for the Sysmon-driven detections live in
[`rules/sigma.yml`](../rules/sigma.yml); YARA rules for the static/family
detections live in [`rules/static.yar`](../rules/static.yar) and
[`rules/family_signatures.yar`](../rules/family_signatures.yar).

## Detection forensics: ancestry, hands-on classification, live status, dwell time

Four evidence capabilities sit on top of the scoring engine, all additive —
none of them change what gets detected or mitigated, only what is recorded
and surfaced about the detections the engine already makes.

**Memory Ancestry Graph** (`src/process_tracker.py` +
`heuristic_engine._capture_forensic_snapshot`). The moment a PID first
crosses the warning or critical threshold (or someone requests its
mitigation), the engine captures a forensic snapshot: the full known
ancestor chain — PID, PPID, image, command line, user, spawn time, and the
time this agent first observed each node — with every parent→child edge
labeled `EXEC` (the syscall family that created the link), plus any recent
process-*access* edge the PID originated, labeled in the same syscall
vocabulary: `MMAP(RWX)` when the granted rights let the actor map/write
executable memory into the victim, `CREATETHREAD` for the remote-thread
primitive, or the raw `OpenProcess(mask)` otherwise. Birth edges and the
injection edge are presented as **one reconstructed attack chain**
(`kind: 'access'` marks the non-parental edge) — automatically, at
detection time, with no analyst effort. Snapshots are taken **once per
PID** (the first threshold crossing wins — escalation does not rewrite
evidence) and **survive mitigation and process death on purpose**: by the
time a human opens the alert, `mitigate()` may long since have terminated
the process, and a dead process's ancestry is unrecoverable from psutil.
Environment variables are captured best-effort, only for still-alive
ancestors, only when the panel is opened — a dead ancestor reports
`environment unrecoverable: process has exited` instead of a silent null.
Every chain reports whether it is complete or partial (`incomplete`), so a
truncated walk is never mistaken for a full one. The headless CLI
entrypoint wires the same tracker the dashboard does, so both entrypoints
produce identical evidence.

**HANDS-ON THREAT classification** (`src/hands_on.py`). A positively-
identified **Cobalt Strike stager** is a different class of detection from
generic shellcode/family hits: it means an operator's tooling is (or is
about to be) executing on this host. Those detections — an imphash match
against a Cobalt Strike intel family, or a custom YAML rule that
declares Cobalt Strike — carry the `[HANDS-ON THREAT]` marker, and the
dashboard's alert store pins them to the **top of the alert queue
regardless of timestamp** (page-size limits are applied *after* pinning,
so the one alert that must be seen is never the one dropped) and renders
them with an **orange HANDS-ON THREAT banner**. Classification is
identity-evidence only, by exact family-alias match — structural patterns
(download-execute IAT trios, RWX sections, entropy) never earn the tag,
so when the banner shows, it means Cobalt Strike. Scoring is identical
either way; the classification changes how the finding is surfaced, not
how it is weighed.

**Live Agent Feedback** (`/api/processes/<pid>/live`). One click answers
"is the attacker still inside right now": alive/dead, name, status,
threads, memory, open files, active network connections, and mapped-module
count — a single psutil snapshot taken inside the request. Individual
reads an OS denies (elevated/protected processes) come back listed under
`denied` rather than failing the whole answer, because "alive but locked
down" is itself an answer.

**Attacker Dwell Time Calculator** (`src/module_inspector.py`). The active
sweep is the agent's only direct witness of *when a suspicious thing first
appeared*, so it keeps two bounded first-seen ledgers:

- *Module residency* — every suspicious-path module; flagged findings
  report how long the module has been resident (`- resident for
  18d 3h 4m`), provenance stated (`dwell_source:
  agent_first_observation`).
- *Anonymous memory regions* — every **executable anonymous** (no file
  backing) region in every process swept. That is where shellcode lives:
  no file, no module, no on-disk artifact. First-seen is recorded BEFORE
  any flagging decision and for RX-at-rest regions too (the
  alloc-RW → write → reprotect-RX stealth shape means a region can become
  shellcode long after it first appeared), so the age reported when a
  detection fires is measurement, not reconstruction. Only the
  shellcode-shaped combination — anonymous AND writable AND executable
  (RWX) — is scored (`anonymous_rwx_region`), with the region's age in
  the finding (`- resident for 18d 4h 12m`); RX-only regions are tracked
  but never flagged, because legitimate JIT runtimes (V8, .NET, the JVM)
  keep anonymous executable code pages at rest. The dwell figure is
  mathematically derived from the agent's own observation record
  (`now - first_seen`) — the form of forensic proof that holds up when
  its provenance, not a log-timestamp guess, is what gets examined.

All stores are bounded (snapshots, access edges, both dwell ledgers —
same LRU discipline as every other buffer here), and the dashboard exposes
live status and the ancestry chain as per-row **Live / Chain** buttons in
the Endpoint Processes table, rendered textContent-only (detection
payloads carry attacker-controlled strings).

## Threat intel sync (MalwareBazaar)

[`tools/threat_intel_sync.py`](../tools/threat_intel_sync.py) pulls **metadata
only** — hashes, imphash, family/tag, file type, first-seen date — from
[MalwareBazaar](https://bazaar.abuse.ch)'s API and writes it into
`data/known_imphashes.json`, which `static_scanner.py` checks every sample's
imphash against.

**This project never downloads actual malware binaries from MalwareBazaar,
by design.** MalwareBazaar's API has a `get_file` query that returns raw
sample content — that endpoint is not implemented anywhere in this repo.
Only `get_recent`, `get_siginfo`, and `get_taginfo` are used, which return
JSON classification data about samples abuse.ch has already analyzed, not
sample content. If you want raw samples for your own analysis, get them
yourself in an isolated VM — see [`samples/README.md`](../samples/README.md).

**Why imphash instead of raw hashes:** imphash is a hash of a PE's ordered
import table. Two samples that share an imphash almost always share the
same compiler-emitted binary lineage (same builder/family) even after the
file bytes themselves are repacked or the hash otherwise changes — so this
catches variants this project has never seen a literal sample of, which a
SHA-256 blocklist alone never could.

### Setup

1. Get a free `Auth-Key` at [auth.abuse.ch](https://auth.abuse.ch/)
   (personal account, enable API access under MalwareBazaar). This project
   can't do this step for you — it's account creation on a third-party
   service.
2. Set it as an environment variable. **Never hardcode it, never commit
   it** — `.gitignore` already excludes `.env` and `*.key` as a backstop:
   ```powershell
   $env:MALWAREBAZAAR_AUTH_KEY = "your-key-here"
   ```

### Usage

```powershell
cd tools
# Pull the 100 most recent samples abuse.ch has classified
..\.venv\Scripts\python.exe threat_intel_sync.py --recent 100

# Pull samples for specific families (repeatable flag)
..\.venv\Scripts\python.exe threat_intel_sync.py --family Quasar --family AsyncRAT

# Pull samples by tag
..\.venv\Scripts\python.exe threat_intel_sync.py --tag NSIS
```

Each run merges into the existing `data/known_imphashes.json` rather than
overwriting it, so you can build up coverage incrementally across multiple
family/tag queries over time.

## Safety model (read this before running it)

This agent can **suspend and kill real processes** on your machine. Two
incidents during development directly shaped the current safety design —
documented here so anyone running this understands exactly what guardrails
exist and why:

- **A rate-only ransomware detector killed a running IDE twice**, because a
  bare "N files created in T seconds" counter can't distinguish mass
  encryption from an IDE indexing a workspace, `git status`, or a build. Fix:
  the ransomware rule now excludes known dev-tool/sync-client process names
  and is scoped to only the folder types Windows' own **Controlled Folder
  Access** protects by default (Desktop/Documents/Pictures/Music/Videos/
  Downloads) — not the whole filesystem.

- **A scoring bug caused a full system freeze.** `mitigate()` had no
  awareness that some PIDs are core OS processes (`csrss.exe` in particular —
  suspending it halts the entire Win32 subsystem session-wide, which is
  exactly why Task Manager and Process Explorer both hard-refuse to touch
  it). A repeating, individually-low-severity false positive against a
  trusted-path system process was able to climb past the mitigation
  threshold given enough time, since "trusted path" only ever *reduced*
  score — it was never true immunity.

  The fix is a **hard, unconditional, two-layer floor**, not a smarter
  heuristic:
  1. `HeuristicEngine._add_score()` refuses to accumulate *any* score for a
     fixed set of protected process names (`csrss.exe`, `wininit.exe`,
     `winlogon.exe`, `services.exe`, `smss.exe`, `lsass.exe`, `svchost.exe`,
     `dwm.exe`, `explorer.exe`, `System`/`System Idle Process`/`Registry`/
     `MemCompression`), PID 0, PID 4, and the agent's own PID.
  2. `mitigate()` independently refuses to call `suspend()`/`terminate()`
     against that same set — deliberately redundant with #1, so the
     refusal holds even if some future code path calls `mitigate()`
     directly, bypassing scoring entirely.

  **This protected list is a floor, not a substitute for caution.** It
  covers the processes whose termination is catastrophic; it does not make
  every other kill "safe." Review `[CRITICAL THREAT]` log lines before
  trusting auto-mitigation in any environment that matters to you.

- **Two false-positive noise sources were found and removed rather than
  patched over**: Windows Defender's own platform DLLs and, more broadly,
  the entire `ProgramData` directory (Visual Studio installer components,
  Windows Terminal's MSIX packaged-COM proxy, OEM vendor helper DLLs all
  legitimately live there) were dropped from the module-injection staging
  path list rather than chasing an endless per-vendor allowlist.

**Everything above is unit-tested**, but if you want detection without any
auto-kill risk while you build trust in a new environment, the simplest
change is to comment out the `self.mitigate(pid)` call in
`HeuristicEngine._check_threshold()` and just log at that severity instead.

## Setup

Requires Windows, Python 3.11+, and (for real-time behavioral detection)
[Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
running as Administrator.

```bash
cd mal_project
python -m venv .venv
.venv\Scripts\pip install pefile psutil pywin32 pyyaml pywintrace
```

### Installing Sysmon

The static scanner works standalone, but real-time behavioral detection
needs Sysmon installed and running. Download it fresh (do **not** commit
Sysmon binaries to this repo — they're excluded via `.gitignore`):

```powershell
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile Sysmon.zip
Expand-Archive Sysmon.zip -DestinationPath tools\sysmon -Force
```

Then, **from an elevated (Administrator) PowerShell**, install it with the
config in this repo — scoped deliberately narrow to only the event types
this agent actually consumes (`ProcessCreate`, `ProcessAccess` on
lsass/svchost, `FileCreate`, `RegistryEvent` on Run keys, `ImageLoad` into
high-value processes), rather than a generic noisy community config:

```powershell
cd tools\sysmon
.\Sysmon64.exe -accepteula -i config.xml
```

Verify it's running:

```powershell
Get-Service Sysmon64
```

### Building the kernel driver

Optional: without it the agent runs on Sysmon and ETW and reports the kernel
sensor as unavailable. Needs Visual Studio with the Windows Driver Kit (the
project targets `WindowsKernelModeDriver10.0`, SDK 10.0.26100.0). **Do this in
a disposable test VM** — it enables test-signing and loads an unattested
kernel driver.

1. Build `driver/sensor/sensor.vcxproj` for `x64` (Debug). The link step passes
   `/integritycheck`; `PsSetCreateProcessNotifyRoutineEx` fails with
   `STATUS_ACCESS_DENIED` without it. Output: `driver/sensor/x64/Debug/sensor.sys`,
   the path `src/kernel_sensor.py` looks for.
2. Sign `sensor.sys` with a self-made test certificate (the project sets
   `SignMode=Off`; signing is a separate step), and trust that certificate in
   the VM.
3. Enable test-signing (`bcdedit /set testsigning on`) and reboot.

`kernel_sensor.ensure_driver_running()` creates the `sensor` kernel-driver
service on first run and starts it; the agent stops it on clean exit. Build
output, `*.sys`, `*.pfx` and `*.cer` are git-ignored (`driver/.gitignore`).

The test harnesses in `driver/sensor/*_test.c` build with
`cl.exe /nologo /W4 /EHsc <name>.c /link /OUT:<name>.exe` from a VS developer
prompt (`ppid_spoof_trusted_broker_test.c` is a DLL run through `rundll32.exe`;
see [`reports/evasion_matrix.md`](../reports/evasion_matrix.md)).

## Running it

The behavioral monitor needs Administrator to subscribe to the Sysmon
event log, so run from an **elevated** PowerShell:

```powershell
cd mal_project\src
..\.venv\Scripts\python.exe main.py
```

You should see:

```
[*] Starting Static Ingress Scanner on ../data/binaries.json...
[+] Static Scan Complete.
[*] Starting Behavioral Telemetry Monitors...
[+] Sysmon push subscription active. Awaiting real-time events...
[+] ETW kernel-process capture active. Awaiting real-time events...
[+] Kernel driver sensor active. Awaiting real-time events...
[*] EDR Engine is active. Press Ctrl+C to terminate.
```

Any sensor can fail to start independently without stopping the others -
`[-] Sysmon telemetry monitor failed to start.`, `[-] ETW telemetry
monitor failed to start.` and/or `[-] Kernel driver sensor failed to start.` —
the static scan and module sweep still run fine on their own, and whichever
behavioral sensors did start keep working.

Press `Ctrl+C` to stop.

## Web dashboard

`src/web_server.py` serves a Falcon/Singularity-style dashboard (stat
tiles, detections-over-time and by-technique charts, an endpoint process
table with a Terminate action, static-scan verdicts, a live Telemetry
Events heartbeat, and a Process Explorer tab) on top of the exact same
`HeuristicEngine`/`StaticScanner`/Sysmon/`ModuleInspector` wiring as
`main.py` — no detection logic changes, just a JSON API + static files.
Stdlib-only (`http.server`), nothing new to install; the frontend is
vanilla HTML/CSS/JS with charts drawn by Chart.js from a CDN.

**Telemetry Events tile.** Most process/file/registry activity on a normal
machine matches none of the suspicious patterns in `heuristic_engine.py`
and produces no alert, by design — indistinguishable from "the Sysmon
subscription is dead" from the dashboard alone. This tile counts every
Sysmon event `evaluate_event()` receives, scored or not, with a live/stale
indicator dot, so you can watch it tick up in real time as proof the
pipeline is actually running.

**Process Explorer tab.** A Falcon/Singularity-style raw activity view:
every process launch Sysmon reports, flagged or not, kept in its own
bounded buffer entirely separate from the Detections feed — mixing every
benign launch into the same feed used for actual findings would drown the
signal that feed exists to surface. Its **Lineage** column (Velociraptor's
process-tracker pattern) resolves each process's ancestry by PID, e.g.
`explorer.exe -> cmd.exe -> rundll32.exe`, from `src/process_tracker.py`.

**Rules tab.** Shows every rule loaded from `rules/custom/*.yml` (see
[Custom detection rules](#custom-detection-rules) below) — name, technique,
score, enabled/disabled, and a live hit counter.

```powershell
cd mal_project\src
..\.venv\Scripts\python.exe web_server.py
```

Then open `http://127.0.0.1:8787`. Bound to loopback only, on purpose —
the process-terminate endpoint should never be reachable off the box.

**Runs elevated automatically.** On launch, if the process isn't already
Administrator, it re-invokes itself via Windows' own UAC consent prompt —
approve it once and the same behavioral telemetry that used to need a
manually-opened elevated PowerShell just starts, with the dashboard
reopening in a new elevated window. Click "No" (or run with
`$env:EDR_NO_ELEVATE=1` first) and it falls back to the same degraded
static-only mode `main.py` uses when Sysmon isn't available — nothing
breaks, you just lose real-time behavioral detections.

## Custom detection rules

`src/rule_engine.py` loads every YAML file in `rules/custom/*.yml` and
evaluates it alongside (never instead of) the hardcoded rules in
`heuristic_engine.py`/`static_scanner.py` — additive by design, modeled on
Velociraptor's artifact format and Sigma's structural-match style. Every
hit is routed through the engine's own `_add_score()`/`add_static_score()`,
so the protected-process floor, decay, and PID-reuse guard apply to a
custom rule exactly as they do to every hardcoded one — see
`test_rule_engine.py`'s `test_custom_rule_cannot_score_a_protected_pid` for
a test that proves this against the real engine, not a mock.

`match` is a constrained tree of `{field, op, value}` conditions under
`all`/`any` — **never** an eval'd expression, so a rule *file* can never
execute code:

```yaml
id: custom_lolbin_from_appdata_roaming
name: LOLBin executed from AppData Roaming
applies_to: process_create   # process_create | process_access | file_create | registry_event | static_pe
technique: T1218
score: 35
match:
  all:
    - field: image
      op: contains
      value: "\\appdata\\roaming\\"
    - field: image
      op: contains
      value: [rundll32.exe, regsvr32.exe, mshta.exe]
message: "LOLBin '{image}' launched from AppData\\Roaming"
enabled: true
```

Ships with one working example
([`rules/custom/example_lolbin_appdata.yml`](../rules/custom/example_lolbin_appdata.yml)).
Operators: `equals`, `contains` (value may be a single substring or a list
of candidate substrings — "does the field contain ANY of these"), `in`,
`not_in`, `regex`, `gt`, `lt`. Fields are normalized, lowercased Sysmon
field names per `applies_to` (`image`, `parent_image`, `command_line`,
`target_image`, `granted_access`, `target_filename`, `target_object`); for
`static_pe`, see `StaticScanner`'s feature dict (`filename`, `hash`,
`imports_flat`, `max_entropy`, `has_rwx_section`, `string_indicators`,
`imphash`, `company_name`, `product_name`, `has_signature`). A malformed
rule file is skipped with a logged warning, never fatal — drop a new file
in and it's picked up on the next process start, no code changes required.
Loaded rules and their live hit counts are visible in the dashboard's
Rules tab.

## Known-good hash allowlist

`data/known_good_hashes.json` (absent by default, same as
`data/known_imphashes.json` — deleting it changes nothing) is a flat
SHA-256 allowlist checked in `HeuristicEngine.add_static_score()`, the one
choke point every static finding already routes through:

```json
{
  "<sha256>": {
    "reason": "verified vendor installer, manually reviewed 2026-08-29",
    "source": "manual",
    "added": "2026-08-29"
  }
}
```

Because the check lives in `add_static_score()` itself, listing a hash
here suppresses *every* static finding for it uniformly — hardcoded rules,
imphash-family matches, and `rules/custom/*.yml` hits alike — with zero
special-casing anywhere else. It's an unconditional override sitting in
front of detection, not another rule competing for weight inside it,
mirrored on ClamAV's `.fp`/`.sfp` false-positive-suppression database.
This is a hand-maintained, human-vetted list by design (the same trust
model as this project's other operator-editable inputs — custom rules,
`config/detection.yml`) — nothing populates it automatically.

**Scope**: this covers *static file* scanning only. A known-good binary's
*live process* can still accumulate behavioral score from
`heuristic_engine.py`'s Sysmon-driven rules — extending the allowlist to
behavioral events would need Sysmon configured to emit file hashes on
`ProcessCreate` (not in `tools/sysmon/config.xml` today) and is a
meaningfully larger change than this one.

## Configuration

`config/detection.yml` holds the numeric tunables `src/detection_config.py`
loads at startup — decay rate, the warning/critical thresholds, the
ransomware burst window/count, the correlator's fuse window, and the
self-test interval/timeout. **Not** configurable here, on purpose: the
protected-process floor, LSASS/hollowing access-mask bitmasks, and
Defender-tamper/PowerShell-abuse pattern lists all stay hardcoded in
`heuristic_engine.py`, so a bad or malicious edit to this file can never
loosen the one thing that must never move (see
[Safety model](#safety-model-read-this-before-running-it)). A missing or
malformed config file falls back to exactly the hardcoded defaults this
engine always used — deleting the file changes nothing.

```yaml
decay_points_per_second: 0.3333
thresholds:
  warning: 50
  critical: 80
ransomware:
  file_event_window_seconds: 20
  file_event_threshold: 60
correlator:
  fuse_window_seconds: 2.0
self_test:
  interval_seconds: 300
  timeout_seconds: 15
```

## Workflows

### Extracting features from a new sample

Static analysis is entirely offline and never executes a sample — it parses
PE bytes directly (`pefile`).

```bash
cd mal_project/samples
# drop your .exe file(s) here
cd ../tools
# add the filename(s) to target_files in extract_features.py
../.venv/Scripts/python.exe extract_features.py
```

This regenerates `data/binaries.json`, which `static_scanner.py` reads on
the next `main.py` run.

### Running just the static scan (no admin needed)

```python
import sys; sys.path.insert(0, "src")
from heuristic_engine import HeuristicEngine
from static_scanner import StaticScanner

engine = HeuristicEngine()
StaticScanner(engine, "data/binaries.json").scan()
print(engine.static_scores)
```

### Testing a behavioral rule without waiting for a real trigger

`heuristic_engine.py`'s `evaluate_event()` takes raw Sysmon event XML, so
any rule can be exercised with synthetic XML instead of needing a live
attack technique:

```python
import sys; sys.path.insert(0, "src")
from heuristic_engine import HeuristicEngine

NS = "http://schemas.microsoft.com/win/2004/08/events/event"
def event(event_id, **fields):
    data = "".join(f'<Data Name="{k}">{v}</Data>' for k, v in fields.items())
    return f'<Event xmlns="{NS}"><System><EventID>{event_id}</EventID></System><EventData>{data}</EventData></Event>'

engine = HeuristicEngine()
engine.evaluate_event(event(1,
    ProcessId=1234,
    Image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    CommandLine="powershell -WindowStyle Hidden -EncodedCommand aQBlAHgA...",
))
```

### Adding a new detection rule

For a straightforward pattern match, drop a YAML file in `rules/custom/`
(see [Custom detection rules](#custom-detection-rules)) — no code changes,
no restart-required build step, picked up on the next process start.

For anything the constrained `{field, op, value}` match language can't
express (bitmask checks, rate-based detectors, cross-event correlation):

1. Add the scoring logic to the relevant `_handle_*` method in
   `heuristic_engine.py` (or a new one, dispatched from `evaluate_event()`).
2. If it needs a Sysmon event type not already logged, add an
   include/exclude rule to `tools/sysmon/config.xml` and reinstall
   (`Sysmon64.exe -c config.xml` updates the running config without a full
   reinstall).
3. Document it as a Sigma rule in `rules/sigma.yml` for portability to other
   tooling.
4. Test it with synthetic XML (see above) before trusting it against real
   traffic — every rule in this repo that skipped that step caused a real
   false positive during development.

## Project layout

```
mal_project/
├── src/                    Agent runtime
│   ├── main.py             Entry point - wires static scan + telemetry + module sweep
│   ├── heuristic_engine.py Central scoring engine, all detection logic, mitigate()
│   ├── static_scanner.py   Reads data/binaries.json, scores static PE findings
│   ├── telemetry_monitor.py  Sysmon EvtSubscribe wiring
│   ├── etw_monitor.py       Raw ETW Kernel-Process sensor (pywintrace) - independent of Sysmon
│   ├── kernel_sensor.py     Kernel driver sensor client - starts the service, polls the driver's IOCTL queue, routes events
│   ├── hands_on.py          HANDS-ON THREAT (Cobalt Strike) classification shared by scanner and dashboard
│   ├── process_correlator.py Fuses matching ETW + Sysmon process-create events (provisional/fused) and routes kernel events
│   ├── sensor_health.py     Per-sensor heartbeat tracking + observe-only staleness watchdog + aggregate blind-state
│   ├── self_test.py         Periodic benign self-test - proves the telemetry/alert pipeline actually delivers, not just that a thread is alive
│   ├── failure_lab.py       Software-only failure-injection lab - breaks the telemetry pipeline on purpose and verifies detection/fallback/recovery
│   ├── vm_eval.py           Live VM evaluation: harmless technique emulations + benign corpus scored against the running agent's API
│   ├── module_inspector.py Active live-process module sweep
│   ├── rule_engine.py       Additive YAML rule pack (../rules/custom/*.yml) - see Custom detection rules
│   ├── detection_config.py  Config-driven tunables (config/detection.yml) - decay/thresholds/ransomware window
│   ├── process_tracker.py   Parent/child lineage + full ancestry graph (PID/PPID/cmdline/user/spawn time, EXEC edges) for Process Explorer & forensic snapshots
│   ├── web_server.py        Dashboard entry point - same wiring as main.py + JSON API, self-elevates
│   ├── dashboard_data.py    Pure data-shaping (severity/category, chart/table rows) for web_server.py
│   ├── conftest.py          Pytest bootstrap: stand-ins for Windows-only imports so the suite runs off-Windows too
│   ├── webapp/              Dashboard frontend (HTML/CSS/JS, Chart.js via CDN)
│   └── test_*.py            Self-checks (synthetic-XML rule tests, static-scan fixtures, mocked sweeps) - `python test_x.py`
├── driver/
│   ├── sensor/              Kernel driver (sensor.c, sensor.vcxproj) + attack/test harnesses (*_test.c)
│   └── hello/               Minimal driver used to validate the toolchain and signing setup
├── tools/
│   ├── extract_features.py Offline PE feature extractor (pefile-based, never executes samples)
│   ├── threat_intel_sync.py MalwareBazaar metadata sync (imphash/family intel, never downloads samples)
│   └── sysmon/              Sysmon config.xml (binaries gitignored - see Setup)
├── config/
│   └── detection.yml         Numeric tunables for detection_config.py (safety floor stays hardcoded)
├── rules/
│   ├── static.yar            Structural YARA rules (RWX, entropy, LSASS-dump IAT, impersonation)
│   ├── family_signatures.yar YARA rules for specific known samples analyzed in reports/
│   ├── sigma.yml              Sigma rules mirroring every Sysmon-driven heuristic
│   └── custom/                Additive YAML detection rules, evaluated by src/rule_engine.py
├── data/
│   ├── binaries.json         Extracted PE features (output of extract_features.py)
│   ├── known_imphashes.json  Family/imphash intel (output of threat_intel_sync.py; absent until you run it)
│   └── known_good_hashes.json  Hand-maintained SHA-256 allowlist (absent by default; see Known-good hash allowlist)
├── samples/                 Raw samples go here locally - not committed (see samples/README.md)
├── reports/                 Malware analysis write-ups + evasion_matrix.md (live-tested sensor-fusion results)
└── scripts/
    └── monitor.ps1           Earlier PowerShell-only version of the telemetry monitor (superseded)
```

## Known limitations / roadmap

- **ETW's raw `ProcessStart` event carries no `CommandLine` and no parent
  *image path*** (only a parent PID) — a permanent kernel-provider
  limitation, not a bug. Command-line-dependent checks simply can't fire on
  an ETW-only (unfused) dispatch; see [Kernel telemetry: ETW + Sysmon
  correlation](#kernel-telemetry-etw--sysmon-correlation).
- **The sensor watchdog is observe-only** — it logs when Sysmon or ETW goes
  stale but never attempts to restart either one. Auto-restart needs
  careful `EvtSubscribe`/ETW-trace handle-lifecycle management and real
  live-fire testing against genuine sensor death, which this development
  environment can't safely exercise.
- **`fuse_window` (default 2.0s, `config/detection.yml`) is provisional,
  not measured** — it hasn't been tuned against real Sysmon-vs-ETW
  delivery lag on a live system yet. If fused dispatches are rare in
  practice, or provisional-only dispatches are common even with both
  sensors healthy, this is the first knob to check.
- **The ETW/Sysmon correlator keys on PID alone**, not PID+timestamp — see
  the tradeoff explained in [Kernel telemetry: ETW + Sysmon
  correlation](#kernel-telemetry-etw--sysmon-correlation). A PID reused by
  an unrelated process within one `fuse_window` of the original process
  exiting could be wrongly fused; the far more common case (reuse well
  after the window elapses) is unaffected.
- **EventID 7 (ImageLoad) has a Sigma rule but no engine handler.**
  `rules/sigma.yml`'s "DLL Loaded Into High-Value Process From Staging
  Directory" rule documents the technique and the Sysmon config emits those
  events, but `heuristic_engine.py`'s `evaluate_event()` doesn't dispatch
  EventID 7 yet. Coverage for that specific pattern currently exists only
  via `module_inspector.py`'s separate active sweep.
- **No trusted-publisher (Authenticode) verification at runtime** — the
  static scanner's impersonation check compares version-info claims against
  signature *presence*, not signature *validity*. A properly-signed
  malicious binary with a stolen/valid cert would not be caught by this
  check.
- **Scoring is per-PID / per-file-hash, not per-ProcessGuid.** A PID-reuse
  guard (comparing OS process start time) mitigates the most common failure
  mode, but Sysmon's `ProcessGuid` field would be a more robust key long-term.
- **The PowerShell-abuse rule only inspects PowerShell hosts** (`powershell.exe`, `pwsh.exe`, or any image whose Sysmon `OriginalFileName` says so). It used to match every process, which made the bare `-e ` pattern flag any lowercased `grep -E`/`sed -e`/`node -e` and any wrapper merely *quoting* those words. The trade-off: a renamed copy of PowerShell is only caught if Sysmon supplies `OriginalFileName` (Sysmon 10+), and a `cmd.exe /c "powershell -enc ..."` wrapper is not itself flagged — the `powershell.exe` child it spawns is.
- **The Defender-tamper rule only inspects processes that execute such commands** (PowerShell, `cmd.exe`, `sc.exe`, `net.exe`/`net1.exe`, `taskkill.exe`, `reg.exe`, matched by image name or Sysmon `OriginalFileName`). It used to inspect every process, and because one hit scores +90 (above the 80 mitigation threshold on its own) any tool whose command line merely *contained* a pattern - `grep`, `git commit -m`, `python -c`, an editor, a `bash -c` wrapper - was suspended and terminated. Launchers that only pass a command along (`wmic`, `schtasks`, `mshta`, ...) are not inspected themselves; the interpreter/utility process they spawn is. Matching also ignores double quotes and extra whitespace, so `"C:\WINDOWS\system32\sc.exe" stop windefend` (how PowerShell launches it) matches like `sc stop windefend`. A renamed copy of a *utility* (`sc.exe` -> `x.exe`) is only caught if the pattern doesn't embed its name; renamed interpreters and `reg.exe` are.
- **Benign commands on those hosts can still trigger the Defender-tamper rule and be mitigated**: it matches text, not intent. Confirmed still flagged: a read-only `Get-MpPreference | Select DisableRealtimeMonitoring`, *re-enabling* protection (`-DisableRealtimeMonitoring $false`), `Remove-MpPreference` (which tightens Defender), and a PowerShell/`cmd` command line that merely quotes a pattern (`Select-String 'set-mppreference' ...`, `echo sc stop windefend`). Fixing these needs a policy decision (an exclusion an attacker could game, or making interpreter-only matches non-lethal), so it is left as-is rather than guessed at.
- **`mitigate()`'s "simulated memory snapshot" at score ≥ 50 does nothing
  yet** — it's a log line, not an actual forensic capture.
- **The kernel driver is test-signed**, not attestation- or ELAM-signed, and
  uses a placeholder `ObRegisterCallbacks` altitude. It cannot protect itself
  from `sc stop`, and its LSASS handle sensor cannot see callers PPL rejects
  (see [Kernel driver sensor](#kernel-driver-sensor)).
- **Detection gaps by design of the sensors**: no sensor sees a non-elevated
  `OpenProcess` on LSASS; ETW and the driver carry no command line or parent
  image. `reports/evasion_matrix.md` lists the cells that were not run live
  (e.g. fusion with Sysmon stopped).
- Four `vm_eval.py` techniques (scheduled-task and service persistence,
  shadow-copy deletion, certutil abuse) have no rule yet.

## Credits / inspiration

Detection design in this project draws on ideas from two much larger,
mature open-source projects (no code copied — these informed *what* to
detect, not *how* the Python is written):

- **[Fibratus](https://github.com/rabbitstack/fibratus)** — a Go-based
  Windows security sensor with a mature ETW-driven, MITRE-ATT&CK-mapped
  rule catalog. The LSASS credential-access detection, the process-hollowing
  access-mask logic, and the ransomware/Office-LOLBin/Defender-tamper
  Sigma rules in this project are modeled on patterns from Fibratus's
  `rules/` directory.
- **[System Informer](https://github.com/winsiderss/systeminformer)**
  (formerly Process Hacker) — a deep Windows process/handle/module
  inspection tool. `module_inspector.py`'s active live-process module sweep
  is inspired by its process/module enumeration view: where Sysmon
  telemetry is passive and event-driven, this periodically inspects what's
  already mapped into running processes.
