/*
 * CommandLine blind-spot test harness - proves that command-line-dependent
 * rules (defender_tamper, powershell_abuse) structurally cannot fire on
 * the ETW or kernel driver sensor paths, only on Sysmon.
 *
 * ETW's ProcessStart event carries no CommandLine field (confirmed via
 * Get-WinEvent); process_correlator.submit_kernel sets it to None too.
 * Only telemetry_monitor.py's Sysmon path ever populates CommandLine.
 * Run with Sysmon active to see the finding; stop Sysmon first to
 * confirm it disappears entirely with ETW + kernel only.
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
