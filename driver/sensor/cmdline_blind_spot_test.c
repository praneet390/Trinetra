/*
 * CommandLine blind-spot test harness - proves that a command-line-
 * dependent rule (heuristic_engine.py's defender_tamper check, same
 * shape as powershell_abuse) structurally cannot fire on the ETW or
 * kernel driver sensor paths, only on Sysmon.
 *
 * Why: etw_monitor.py's own docstring documents that the raw
 * Microsoft-Windows-Kernel-Process ProcessStart event (confirmed via
 * Get-WinEvent -ListProvider) carries no CommandLine field at all -
 * CommandLine is set to None for every ETW-sourced event
 * (evaluate_etw_process_start). process_correlator.submit_kernel does
 * the identical thing for the kernel sensor's PROC-CREATE event
 * ("Like ETW, the kernel event carries no CommandLine..."), because
 * sensor.c's own process-create notification has nowhere to read a
 * command line from either. Only telemetry_monitor.py's Sysmon path
 * ever populates CommandLine, so defender_tamper/powershell_abuse are
 * two rules that can ONLY ever fire on a Sysmon-sourced or
 * Sysmon-fused dispatch - never on ETW alone, never on the kernel
 * driver alone, and the correlator's fusion logic (process_correlator.
 * _gc_once) does not synthesize a missing field from one sensor using
 * another's data for anything except the ancestry-contradiction check.
 *
 * What it does:
 *   1. Launches cmd.exe with a command line containing two of
 *      DEFENDER_TAMPER_PATTERNS's exact trigger substrings
 *      ('set-mppreference', 'disablerealtimemonitoring'), but spelled
 *      inside a harmless `echo` - this is a TELEMETRY-VISIBILITY test,
 *      not a real tamper attempt. Nothing is actually disabled; `echo`
 *      only prints text. DEFENDER_TAMPER_PATTERNS is a pure substring
 *      match over the command line (see _normalize_command_line), so
 *      this exercises the exact same code path a real attempt would,
 *      with zero actual risk.
 *   2. Prints its own PID so the operator can check which sensor(s)
 *      the resulting process-create event arrived through.
 *
 * How to actually use this for the evasion matrix (this harness alone
 * can't toggle which sensors are live - that's an operator step):
 *   Run A: with Sysmon, ETW, and the kernel driver all running.
 *          Expect a defender_tamper finding (score 90).
 *   Run B: `sc stop sysmon64` (or whatever the local Sysmon service
 *          name is) first, then run again with only ETW + kernel up.
 *          Expect NO defender_tamper finding at all - this is the
 *          honest "fusion did not help" cell: ETW and the kernel
 *          sensor both independently lack the one field this rule
 *          needs, so there is no cross-sensor fusion left to fall
 *          back on once Sysmon is gone.
 *   Remember to `sc start sysmon64` again afterward.
 *
 * Build (from a VS Developer environment, x64):
 *   cl.exe /nologo /W4 /EHsc cmdline_blind_spot_test.c /link /OUT:cmdline_blind_spot_test.exe
 */
#include <windows.h>
#include <stdio.h>

static void fail(const char *what) {
    fprintf(stderr, "[cmdline_blind_spot_test] FAILED: %s (GetLastError=%lu)\n", what, GetLastError());
    exit(1);
}

int main(void) {
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    // Harmless echo only - never actually calls Set-MpPreference or touches
    // Defender. The substrings alone are what DEFENDER_TAMPER_PATTERNS
    // matches on, regardless of what command actually contains them.
    char cmd[] = "cmd.exe /c echo TEST-ONLY harmless string containing "
                 "set-mppreference -disablerealtimemonitoring for pattern-visibility testing "
                 "& timeout /t 3 >nul";

    printf("[cmdline_blind_spot_test] this harness's own pid=%lu\n", GetCurrentProcessId());
    printf("[cmdline_blind_spot_test] launching cmd.exe with a command line containing "
           "DEFENDER_TAMPER_PATTERNS trigger substrings (harmless echo, nothing is actually disabled)\n");

    if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE,
                         CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        fail("CreateProcessA");
    }
    printf("[cmdline_blind_spot_test] child launched, pid=%lu (parent pid=%lu)\n",
           pi.dwProcessId, GetCurrentProcessId());
    printf("[cmdline_blind_spot_test] expected result WITH Sysmon running: defender_tamper finding, score 90\n");
    printf("[cmdline_blind_spot_test] expected result WITH SYSMON STOPPED (ETW+kernel only): no finding at all\n");

    WaitForSingleObject(pi.hProcess, 6000);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    printf("[cmdline_blind_spot_test] done\n");
    return 0;
}
