# Comparison with other open-source Windows endpoint tools

Checked on **2026-10-28**. Every cell below was read from the project's own
source tree (shallow clone at the commit shown) unless marked otherwise. "Not
found" means a targeted search of that tree turned up nothing; it is not proof
of absence. Nothing here was run on a live system.

| Project | Commit reviewed | Last commit |
|---|---|---|
| [Fibratus](https://github.com/rabbitstack/fibratus) | `1fd558da6900` | 2026-10-27 |
| [OpenEDR](https://github.com/ComodoSecurity/openedr) | `30b36f203afb` | 2026-05-23 |
| [Velociraptor](https://github.com/Velocidex/velociraptor) | `ab374970f21c` | 2026-10-28 |
| [Wazuh](https://github.com/wazuh/wazuh) | `a61761ef0be2` | 2026-10-27 |
| [osquery](https://github.com/osquery/osquery) | `8d9442011e17` | 2026-10-27 |
| [ClamAV](https://github.com/Cisco-Talos/clamav) | `dd3aa1907cf6` | 2026-10-22 |

## 1. Basics

| | License | Windows telemetry source | Own Windows kernel driver |
|---|---|---|---|
| **This project** | MIT | Sysmon + ETW (`Kernel-Process`) + own driver, fused | Yes |
| **Fibratus** | Apache-2.0 | ETW (NT Kernel Logger; eBPF on Linux) | Not found |
| **OpenEDR** | Comodo Available Source License (CASL): source-available, not OSI | Own driver, injected API-hook DLL, mini-filter, network filter | Yes (`edrdrv`) |
| **Velociraptor** | AGPL-3.0 | VQL artifacts, incl. ETW (`Windows.ETW.*`) | Not found |
| **Wazuh** | GPL-2.0 (engine: AGPL-3.0) | Agent log/FIM collection, Windows event channels | Not found |
| **osquery** | Apache-2.0 or GPL-2.0 | OS APIs, ETW tables (`process_etw_events`) | Not found |
| **ClamAV** | GPL-2.0 | File scanning; on-access is Linux-only | Not found |

## 2. Capabilities

| | Automated process kill / response | Real vs. claimed parent | Agent self-protection | Sensor-health / blind-state reporting |
|---|---|---|---|---|
| **This project** | Yes: suspend + terminate on score ≥ 80 | Yes: driver (`CreatingThreadId`) | Yes: `ObRegisterCallbacks` strips terminate / inject rights | Yes: 4 aggregate states, drop counters, caveat banner |
| **Fibratus** | Yes: rule actions `kill` and `isolate` | Yes: `real_ppid` from the ETW event header; no shipped rule uses it | Not found | Not found (ETW lost-event counters are defined but not surfaced) |
| **OpenEDR** | Not found in product code (policy engine raises events / verdicts) | Yes: driver records `ProcessCreatorPid` when it differs from the parent | Yes: `objmon.cpp`, "Processes access filter (self protection)" | Not found |
| **Velociraptor** | Partial: network-quarantine artifact (IPsec policy) | Partial: the ETW artifact shows the header PID as the parent next to the payload fields; no comparison or rule | Not found | Not found |
| **Wazuh** | Active-response framework; shipped Windows scripts are `block-ip` and `disable-account` | Not found | Not found | Agent-level only: manager marks agents `disconnected` |
| **osquery** | Not found | Not found | Not found | Not found |
| **ClamAV** | Not applicable (scanner) | Not applicable | Not found | Not found |

### Closed-source, documentation only (not source-reviewed)

| | What is documented |
|---|---|
| **Elastic Defend** | Its [Parent Process PID Spoofing](https://www.elastic.co/guide/en/security/8.19/prebuilt-rule-8-19-34-parent-process-pid-spoofing.html) rule compares the reported parent with a recorded real parent PID. |
| **Sysmon** | Event 1 exposes `ParentProcessId` / `ParentImage` and no creator field (per third-party schema references; Microsoft's pages were not reachable from the review environment). Events 4 and 16 report service-state and configuration changes. |

## 3. Evidence for the non-obvious cells

- **Fibratus real parent.** `pkg/event/param_decoder_windows.go:295`:
  `e.AppendParam(params.ProcessRealParentID, params.PID, r.Header.ProcessID)`.
  `pkg/event/event_windows.go:276` defines `IsSurrogateProcess()` as
  `ParentID != RealParentID`. `docs/telemetry/events/process.md:12`: "Real parent
  process identifier useful for detecting process spoofing." No file under
  `rules/` references it. `pkg/rules/engine.go:312-322` executes `kill` and
  `isolate` actions.
- **OpenEDR real parent.** `edrav2/iprj/edrdrv/src/procmon.cpp:1232-1233` writes
  `EvFld::ProcessCreatorPid` from `CreatingThreadId.UniqueProcess` when it
  differs from `ParentProcessId`, inside a `PsSetCreateProcessNotifyRoutineEx`
  callback.
- **OpenEDR self-protection.** `edrav2/iprj/edrdrv/src/objmon.cpp` is headed
  "Processes access filter (self protection)" and removes `PROCESS_TERMINATE |
  PROCESS_CREATE_THREAD | …` from handle access masks via `ObRegisterCallbacks`.
- **OpenEDR license.** `LICENSE.md`: "COMODO AVAILABLE SOURCE LICENSE (CASL)
  AGREEMENT"; section 1.4 permits MSSPs/SOCs to build paid services on it.
- **Velociraptor ETW.** `artifacts/definitions/Windows/ETW/KernelProcess.yaml`
  subscribes to the same provider this project uses
  (`{22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716}`) and resolves the **parent** from
  `System.ProcessID`, i.e. the event header. Its quarantine artifact
  (`Windows.Remediation.Quarantine`) configures an IPsec network policy, not
  process termination.
- **Wazuh response.** `src/active-response/src/` ships `block-ip-*` and
  `disable-account`; the agent state `disconnected` is in
  `src/client-agent/src/state.c`.
- **ClamAV.** `docs/man/clamonacc.8.in`: "On-Access is only available on Linux
  systems."

## 4. What this means for the project's claims

**Not unique.** Reading the real creator from the kernel (Fibratus, OpenEDR,
Elastic), stripping handle rights to protect the agent (OpenEDR), and automated
kill actions (Fibratus) all exist elsewhere. OpenEDR is the closest relative: a
kernel driver with process, object, registry, file-system and network
monitoring. It is source-available rather than open source.

**Not found in any of the sources examined:**

1. A correlator fusing **independent** behavioral sensors (Sysmon, ETW and an
   own driver), with the disagreement between them logged as a finding, and
   per-event detection of a blinded sensor by checking that two unfiltered
   witnesses (kernel driver, ETW) both report each process creation.
2. Sensor health reduced to an aggregate visibility state that qualifies the
   alert counts themselves.
3. A published, live-tested matrix of which technique each sensor does and does
   not catch, including negative results, and a failure-injection lab that tests
   the agent's reaction to a dying sensor.
4. An OSI-licensed (MIT) project with a kernel driver, agent and dashboard
   together. OpenEDR has the first two under a source-available license.

These are statements about what I found, not claims that nothing else exists.

## 5. Correction to this project's own matrix

`reports/evasion_matrix.md` and the README previously recorded **ETW as unable
to see the real process creator**. Fibratus and Velociraptor both take the
creating process from the ETW **event header** (`Header.ProcessID` /
`System.ProcessID`), and Velociraptor does so on the same
`Microsoft-Windows-Kernel-Process` provider. `src/etw_monitor.py` already reads
`event["EventHeader"]` but never reads the header's `ProcessId`. So the "N" for
ETW in the PPID-spoof rows reflects what this implementation extracts, **not a
limit of ETW**.

**Status (implemented, not yet verified live).** `etw_monitor.py` now reads
`EventHeader.ProcessId` (key confirmed against pywintrace 0.2.0's source), the
correlator compares it with the kernel driver's real creator and exposes
agree/disagree counts on `/api/summary`, and the engine can score a mismatch
with the claimed parent, **off by default** (`correlator.etw_creator_scoring`)
until the counters confirm the header means "creator" on the exact provider
this agent consumes. Fibratus and Velociraptor's use of the header is the
evidence it does; it is not a substitute for running it.

## Method and limits

- Source reviewed through shallow clones, with targeted `grep` for kernel-API
  use (`ObRegisterCallbacks`, `PsSetCreateProcessNotifyRoutine*`, `DriverEntry`),
  response actions, spoofing / real-parent handling, self-protection and
  health / heartbeat concepts.
- Vendor sites (`fibratus.io`, Microsoft Learn, Elastic docs) were not reachable
  from the review environment except via search snippets, so documentation-level
  claims are limited to what is cited above.
- A project's feature set is larger than the columns here. This compares only
  the dimensions this project cares about, and says nothing about rule breadth,
  scale or maturity, where the established tools are far ahead.
