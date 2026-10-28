# Evasion matrix: sensor disagreement as a detection primitive

**Status: live-tested.** Every row below was run against the actual
running agent (`web_server.py`, admin-elevated, kernel driver service
`sensor` + `Sysmon64` + ETW all confirmed `Running` at test time) on
2026-10-25, with results read back from the live dashboard's
`/api/alerts` feed and, for row 3, cross-checked directly against the
raw `Microsoft-Windows-Sysmon/Operational` event log. One of the five
rows (row 3) came back **different from what the code-tracing pass
originally predicted** - corrected below, with the old prediction kept
visible so the correction is checkable, not just asserted.

## Thesis

This project runs three independently-sourced process/telemetry sensors
(Sysmon, ETW's `Microsoft-Windows-Kernel-Process` provider, and a custom
kernel driver) into one correlator (`src/process_correlator.py`). Each
sensor has a *structural*, code-documented blind spot - not a tuning gap,
a hole no amount of better rules closes for that sensor alone. The
question this matrix answers: **are there techniques that beat every
sensor individually, but still get caught because the sensors disagree
or because a second sensor covers the first one's specific gap?** And,
just as important, **where does that stop being true** - where does
missing one sensor (usually Sysmon) create a hole no amount of fusion
logic can fill?

## Methodology

Each row has a purpose-built harness in `driver/sensor/*_test.c`,
following the same pattern as the two that already existed
(`ppid_spoof_test.c`, `lsass_access_test.c`): documented Win32 API use
only, no real destructive action, PIDs printed so results can be
cross-checked against the agent's own log/dashboard output, full cleanup
after. All five harnesses below were built with the project's actual
MSVC toolchain and run against the live agent; alert ids were baselined
immediately before each run and the dashboard re-polled a few seconds
after, so each row's result is attributable to that specific run (PID
cross-checked against the harness's own printed output in every case).

"Fusion"/"full pipeline" below means "all three sensors live, as
`process_correlator.py` actually wires them" - which for process-create
events is real cross-sensor merging (`_gc_once`), but for LSASS access
is two independently-scored paths that are never correlated with each
other (`heuristic_engine.py`'s own comment: "an INDEPENDENT,
corroborating sensor, not a dedup"). Rows 4/5's "Sysmon stopped" cell
was **not** run live this pass - stopping a security-relevant Windows
service is a system-settings change outside what was done unilaterally
here; the exact commands to run it yourself are at the bottom of this
report.

## Results

| # | Technique | Harness | Sysmon alone | ETW alone | Kernel alone | Full pipeline | Status |
|---|---|---|---|---|---|---|---|
| 1 | PPID spoof via an arbitrary (untrusted) broker | `ppid_spoof_test.c` | **N** | **N** | **Y** - +80, confirmed (`id 41`) | **Y** | **confirmed live** |
| 2 | PPID spoof where the real creator is a trusted System32 broker (rundll32-hosted) | `ppid_spoof_trusted_broker_test.c` | **N** | **N** | **Y**, discounted - +20, confirmed (`id 68`) | **Y**, discounted | **confirmed live** |
| 3 | LSASS `OpenProcess(PROCESS_VM_READ)` from an unprivileged, non-PPL caller | `lsass_access_test.c` | **N** - *revised, see below* | N/A (sensor doesn't cover handle access) | **N** - PPL blocks the Ob callback | **N** - no sensor catches this | **confirmed live - corrected** |
| 4 | Defender-tamper command line (`set-mppreference -disablerealtimemonitoring`) | `cmdline_blind_spot_test.c` | **Y** - +90, confirmed (`id 97`) | **N** - structural, no `CommandLine` field | **N** - structural, no `CommandLine` field | **Y** while Sysmon is up; untested with Sysmon stopped | **confirmed live (Sysmon-up cell)** |
| 5 | Office-parent → LOLBin-child chain, parent identified only by resolved image path | `parentimage_blind_spot_test.c` | **Y** - +60, confirmed (`id 130`) | **N** - structural, no `ParentImage` field | **N** - structural, no `ParentImage` field | **Y** while Sysmon is up; untested with Sysmon stopped | **confirmed live (Sysmon-up cell)** |
| 6 | Kernel-mode driver load (`DRIVER-LOAD` event) | none built | N/A | N/A | Y (code-traced only) | Y, kernel-exclusive | analytical only, not run |
| 7 | Dual-sensor ancestry contradiction via PID-reuse timing | none built | — | — | — | — | not attempted, see incidental finding below |

> **Erratum (2026-10-28).** Rows 1-2 record ETW as unable to see past a spoofed
> parent. That reflects what `src/etw_monitor.py` extracts (the payload
> `ProcessID` / `ParentProcessID`), **not a limit of ETW**: the event header's
> process ID is the creating process, and Fibratus (`real_ppid`) and Velociraptor
> (`Windows.ETW.KernelProcess`, same provider) both use it. The live results above
> are accurate for the code as tested; the "structural" wording applies to rows 4-5
> only (no `CommandLine` / `ParentImage` field exists in the ETW payload). See
> [`docs/comparison.md`](../docs/comparison.md#5-correction-to-this-projects-own-matrix).
>
> **Follow-up.** The agent now reads the ETW header's creating PID and
> cross-checks it against the driver (scoring on it is off by default). Rows 1-2
> have **not** been re-run with it, so their ETW cells above still describe the
> earlier code.

## Row-by-row

**Row 1 - confirmed, clean.** `ppid_spoof_test.exe` run: claimed parent
0x120c (4620), real creator 0x2630 (9776). Dashboard alert `id 41`:
*"Kernel-verified PPID spoofing: process claims parent PID 4620 but was
actually created by PID 9776"*, +80. Exact match to the harness's own
printed expectation. Sysmon and ETW never produced a corresponding
finding for this pid, confirming neither sensor can see past the
spoofed claim on its own - only the kernel sensor's unspoofable
`CreatingThreadId` resolution catches it.

**Row 2 - confirmed, clean.** Built as a DLL (`/LD`) and run via
`rundll32.exe ppid_spoof_trusted_broker_test.dll,RunTest` specifically
so the real `CreateProcess` caller the kernel observes is genuinely
`rundll32.exe` (a System32-resident, Microsoft-signed process) rather
than an arbitrary test .exe - the discount in `heuristic_engine.py`
keys off the *real creator's* resolved path, not the claimed parent's.
Dashboard alert `id 68`: *"Trusted-broker PPID spoofing: process claims
parent PID 10780 but was actually created by PID 10212"*, **+20**, not
+80 - the discount fired exactly as designed. This is the code path the
Outlook false-positive fix (`dc5f6e4`) tuned; see below for why that
trade is a reasonable one, not a hidden gap.

**Row 3 - corrected by live testing, the most important result in this
pass.** The original code-tracing wrote this as "Sysmon catches it via
EID 10 because its driver is Microsoft-signed/ELAM-class and PPL only
blocks lower-signed drivers." That assumption was **wrong**, and live
testing caught it:

- `lsass_access_test.exe` ran `OpenProcess(PROCESS_VM_READ, FALSE,
  <lsass pid>)` from this unprivileged, non-elevated-to-PPL process,
  exactly as the harness documents. It failed with `ERROR_ACCESS_DENIED`
  as expected.
- The kernel driver produced no `kernel_lsass_access`/`lsass_access`
  alert - expected, per `sensor.c`'s own honesty note.
- Sysmon **also** produced nothing. Its `ProcessAccess` rule is
  correctly configured for this (`tools/sysmon/config.xml` scopes
  `TargetImage` to `\lsass.exe` and `\svchost.exe`), and the pipeline
  demonstrably works - it logged real `svchost.exe` hollowing-access
  hits (`id 80`/`81`) in the same test window. A direct query of the raw
  `Microsoft-Windows-Sysmon/Operational` log for EventID 10 in the three
  minutes around the test returned **zero events of any kind, any
  target** - not a pipeline/parsing failure on this project's side,
  Sysmon's own kernel hook never fired at all.

Conclusion: PPL's enforcement blocks an `ObRegisterCallbacks`
pre-operation callback from ever firing for an insufficiently-privileged
caller's access attempt against a PPL target, **regardless of which
driver registered the callback or its signing level** - this is a
property of the Windows object-manager boundary itself, not something
Sysmon's signature lets it see around. For this specific technique
(an ordinary, non-elevated process calling `OpenProcess` directly
against the real LSASS), **no sensor in this pipeline sees it, and no
fusion logic can recover what none of them captured.** This is a
stronger, more honest finding than the one originally written, and it
directly contradicts this project's own "kernel ground truth" framing
in one specific, now-proven case.

**Rows 4/5 - confirmed for the "Sysmon up" cell, both clean.**
`cmdline_blind_spot_test.exe`: alert `id 97`, *"Attempted Defender
tampering: cmd.exe /c echo test-only harmless string containing
set-mppreference -disablerealtimemonitoring..."*, **+90**, PID matched
exactly. `parentimage_blind_spot_test.exe`: alert `id 130`, *"Office app
'outlook.exe' spawned LOLBin 'cmd.exe' - likely macro dropper"*, **+60**,
on the real cmd.exe child of the renamed test copy. The "ETW alone"/
"kernel alone" cells are not just inferred from silence - they follow
deterministically from `CommandLine`/`ParentImage` being hard-set to
`None` on those two dispatch paths (`_normalize_command_line(None or
'')` is always `''`, matched against patterns that are never the empty
string; `os.path.basename(None or '')` is always `''`, never in
`OFFICE_PARENTS`), which this pass additionally confirmed by reading the
exact code those two dispatches run through. The "Sysmon stopped" cell -
the actual "fusion does not help" case - was not run; see reproduction
steps below.

## Incidental findings from live testing

Running the matrix surfaced two things worth reporting on their own,
neither of which is a sensor blind spot - one is a scoring-correctness
bug, the other is expected background noise that's worth naming so it
isn't mistaken for something else later.

**A real double-scoring bug, found via row 5.** Watching the alert feed
for the office_lolbin test showed the renamed test process (PID 10528,
running from a `%TEMP%` path, so it also tripped the unrelated
`staging_dir` check) get scored **+30 twice** for the same real event,
then correctly deduped on a third dispatch (`[DEDUP] Skipping duplicate
'staging_dir' for PID 10528 - already scored by an earlier dispatch of
this same event`). Tracing why: `process_correlator.submit_kernel`
(`src/process_correlator.py:88-97`) never sets `_dedup_key` on the dict
it dispatches, unlike `submit_etw` and the fused-dispatch path in
`_gc_once`, both of which set it to the pid. `HeuristicEngine._score_once`
(`src/heuristic_engine.py:573-608`) treats a missing `dedup_key` as "a
plain single-sensor dispatch, pass through unconditionally" - the exact
behavior the function's own docstring says is for a system with *no*
correlator in front of it. But the kernel sensor's dispatch always goes
through the correlator and always represents the same real process-create
event that ETW and/or Sysmon also report - so every check in
`_handle_process_create` that uses `_score_once` (`staging_dir`,
`defender_tamper`, `powershell_abuse`, `office_lolbin` - not
`kernel_ppid_spoof`, which is gated to only ever run on the kernel
dispatch itself) double-scores whenever a real process trips one of
those rules **and** is observed by the kernel driver alongside ETW or
Sysmon, which is the normal case for every process on the system
whenever the kernel driver is running. This inflates scores and brings
processes closer to the mitigation threshold than the rules intend,
system-wide, not just in this test.

**First fix applied, then the live re-test surfaced a second, deeper
bug in the same area.** `submit_kernel` was given `'_dedup_key': pid`
(`src/process_correlator.py`), putting the kernel path into the same
per-pid dedup bucket ETW/Sysmon use. Full suite passed. The agent was
restarted to pick it up, and `parentimage_blind_spot_test.exe` was
re-run live to confirm - and the *exact same* double `+30` still
happened (`staging_dir` scored twice, then correctly deduped on a
third dispatch, same pattern as before). That ruled out "the fix
didn't apply" and pointed at something the fix didn't cover: a dict-key
type mismatch underneath it.

Tracing it: `HeuristicEngine.evaluate_event()`'s real Sysmon XML parsing
(`src/heuristic_engine.py`) reads `'ProcessId'` straight from an
ElementTree `Data` element's `.text` - **always a `str`**, never cast.
`kernel_sensor.py`'s `struct.unpack`-decoded pid is **always a genuine
`int`**. A quick isolated repro confirmed it directly: feeding
`submit_etw` a pid of `1234` (int) and `submit_sysmon` a `ProcessId` of
`'1234'` (str) for "the same" real process produced **two separate
dispatches** instead of one fused one - `int 1234` and `str '1234'` are
different dict keys, so `_pending.setdefault()` (the actual ETW+Sysmon
fusion mechanism, not just the newer `_dedup_key` dedup) silently never
merges them either. In production this mostly goes unnoticed for
ETW-vs-Sysmon specifically because pywintrace's own `etw.py` has an
unrelated bug of its own (`type(data) == int` as a precondition for
calling the `int()` converter - a no-op check, since `TdhFormatProperty`
returns a formatted `str`, so the conversion never actually fires) that
leaves ETW's pid as a `str` too, matching Sysmon's `str` by accident.
The kernel sensor's genuinely-`int` pid never matched either of them,
in either direction, fix or no fix - which is exactly why the first fix
alone didn't change the observed behavior.

**Fixed properly**: added `_normalize_pid()` (`src/process_correlator.py`),
casting every `_pending` key and every `_dedup_key` to `int` at all
three submission points (`submit_etw`, `submit_kernel`, `submit_sysmon`)
regardless of what type each sensor happened to hand over. Verified
directly: `submit_etw(1234, ...)` + `submit_sysmon({'ProcessId': '1234', ...})`
now produces one `'fused'` dispatch, not two, with a shared int
`_dedup_key`. Four regression tests total in
`src/test_process_correlator.py`
(`test_submit_kernel_sets_dedup_key_to_pid`,
`test_kernel_and_etw_dispatches_for_the_same_pid_share_a_dedup_key`,
`test_etw_int_pid_and_sysmon_str_pid_still_fuse`,
`test_kernel_int_pid_and_sysmon_str_pid_share_a_dedup_key`); full suite
passes at 402/402.

**Live re-verified.** Agent restarted again, `parentimage_blind_spot_test.exe`
re-run a third time against the fully-fixed code. Result: `staging_dir`
scored **once** (+30, Total Score: 30) and the other two sensors'
dispatches for the same real pid were both correctly logged as
`[DEDUP] Skipping duplicate 'staging_dir' - already scored by an
earlier dispatch of this same event` - exactly the fixed behavior,
confirmed on the real dashboard, not just at the unit level. `office_lolbin`
fired cleanly at +60 on the real child process, unaffected. As a visible
side effect of no longer double-scoring: the test's own renamed process
stayed at a clean score of 30 and was left alone, instead of (as it was
on the pre-fix live run) crossing the mitigation threshold on inflated
score and getting auto-killed.

**Background noise, correctly attributed, not a threat.** A burst of
~12 alerts with a ~29KB `powershell.exe -EncodedCommand ...` payload
appeared during testing, overlapping row 1's run closely enough that
one of them landed on the same PID (3576) our spoofed-child process had
just vacated, pushing that PID's combined score (+80 ppid-spoof, +45
unrelated powershell-abuse) over the mitigation threshold and getting
it auto-killed. Traced to `src/vm_eval.py:131-133`'s `launch_ps_encoded`
scenario (`Write-Output 'edr-eval-<token>'`, base64-encoded) - this
project's own live-evaluation harness, apparently running concurrently
in a loop during this test session. Benign, but it is a real, organic
demonstration of the exact PID-reuse race `process_correlator.py`'s own
docstring already documents as an accepted risk - kept here as evidence
of that risk actually manifesting, not folded into row 1's result.
Separately, this session's own PowerShell tool calls were observed
tripping `powershell_abuse` themselves (`-executionpolicy bypass` is a
literal trigger pattern) - an expected, already-documented tradeoff
(`POWERSHELL_ABUSE_PATTERNS`'s own comment acknowledges "-e " etc. are
prone to exactly this kind of collateral match), not a new finding.

## The Outlook false positive, reframed

The kernel PPID-spoof check auto-killed a live, legitimate Outlook
process before the trusted-broker discount existed (fixed in `dc5f6e4`).
That is exactly the failure mode row 2 reproduces: an 80-point,
single-sensor-confident detector fired on real OS infrastructure doing
ordinary reparenting, because at the time nothing distinguished it from
an attacker doing the identical API call. The fix was not "ignore
System32 parents" (that would reopen row 2 as an actual blind spot) - it
was "keep detecting and logging it, discount the severity instead of
auto-mitigating on it alone, and let it compound with other signals
before anything gets killed." Row 2's live result (+20, logged,
not auto-mitigated) confirms the fix behaves as intended.

## Reproducing this matrix

All harnesses live in `driver/sensor/` and build the same way the two
pre-existing ones do:

```
cl.exe /nologo /W4 /EHsc <name>.c /link /OUT:<name>.exe
```

except `ppid_spoof_trusted_broker_test.c`, which is a DLL invoked
through `rundll32.exe`:

```
cl.exe /nologo /W4 /EHsc /LD ppid_spoof_trusted_broker_test.c /link /OUT:ppid_spoof_trusted_broker_test.dll
rundll32.exe ppid_spoof_trusted_broker_test.dll,RunTest
```

Rows 4 and 5's untested "full pipeline, Sysmon stopped" cell needs one
manual step this report deliberately didn't take:

```
sc stop sysmon64
<run cmdline_blind_spot_test.exe or parentimage_blind_spot_test.exe>
sc start sysmon64
```

Results in this report were read from `http://127.0.0.1:8787/api/alerts`
(the running agent's own dashboard API), baselined by alert `id` right
before each run.

## What's deliberately not here

Per the brief this report came from: no broad run against a general
malware corpus. That re-validates the existing lolbin/defender-tamper/
powershell-abuse heuristic ruleset (good QA, already covered by
`vm_eval.py`) rather than testing anything specific to sensor fusion,
which is the actual subject of this document. Row 6 (kernel-exclusive
`DRIVER-LOAD` coverage) and row 7 (a crafted PID-reuse race inside the
correlator's `fuse_window`) remain analytical/not-attempted, same as the
original pass - row 7 arguably got indirect, unplanned support from the
incidental vm_eval.py collision above, but that was observed, not
engineered, so it's kept separate rather than claimed as row 7's result.
