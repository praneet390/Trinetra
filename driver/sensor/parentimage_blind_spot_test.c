/*
 * ParentImage blind-spot test harness - proves that heuristic_engine.
 * py's office_lolbin check (Office app spawning a LOLBin - the classic
 * macro-dropper chain) is structurally unreachable on the ETW or kernel
 * driver sensor paths, for the same root-cause reason as
 * cmdline_blind_spot_test.c but hitting a different field:
 *
 *     parent_image = (data.get('ParentImage') or '').lower()
 *     ...
 *     parent_name = os.path.basename(parent_image)
 *     if parent_name in OFFICE_PARENTS and child_name in LOLBIN_CHILDREN: ...
 *
 * ETW's raw ProcessStart event carries a parent PID but, confirmed via
 * Get-WinEvent, no parent IMAGE PATH - evaluate_etw_process_start sets
 * ParentImage=None. The kernel driver's PROC-CREATE event has nowhere
 * to get a parent image path from either - process_correlator.
 * submit_kernel sets ParentImage=None too. basename(None/'') is always
 * '', which is never in OFFICE_PARENTS, so office_lolbin can never fire
 * on an ETW-only or kernel-only dispatch - regardless of what the real
 * parent process actually is. This is a different structural gap than
 * the CommandLine one (a different field, feeding a different rule
 * family keyed on image basenames rather than command-line substrings),
 * included separately to show the "Sysmon-only field" problem is
 * general, not a one-rule quirk.
 *
 * This harness does NOT launch a real Office application (not
 * guaranteed to be installed, and unnecessary - office_lolbin matches
 * purely on the parent's resolved image basename, nothing else, no
 * signature/hash check). Instead it makes a throwaway COPY of the
 * harmless, already-present cmd.exe, renames that copy to "outlook.exe"
 * inside a scratch temp folder (never touches any system directory),
 * and launches a REAL child from that renamed copy - no PPID spoofing
 * trick is used or needed here, since this is testing a resolved-
 * image-path field, not process ancestry. The copy is deleted when the
 * test finishes.
 *
 * What it does:
 *   1. Copies C:\Windows\System32\cmd.exe to
 *      %TEMP%\entity2_evasion_matrix\outlook.exe.
 *   2. Launches that copy with "/c cmd.exe /c echo ... & timeout ..." -
 *      since the copy IS cmd.exe, it correctly interprets /c and spawns
 *      a REAL, non-spoofed LOLBin child (cmd.exe) of its own.
 *   3. Prints every PID/path involved.
 *   4. Terminates both processes and deletes the temp copy.
 *
 * How to use this for the evasion matrix: run it with Sysmon, ETW, and
 * the kernel driver all live simultaneously (no sensor needs to be
 * stopped for this one - the gap is structural per-sensor, not
 * configuration-dependent). Expect an office_lolbin finding (score 60)
 * attributed to the Sysmon-sourced or fused dispatch, and confirm via
 * logs that no ETW-only or kernel-only dispatch for the same pid ever
 * produced one.
 *
 * Build (from a VS Developer environment, x64):
 *   cl.exe /nologo /W4 /EHsc parentimage_blind_spot_test.c /link /OUT:parentimage_blind_spot_test.exe
 */
#include <windows.h>
#include <stdio.h>
#include <shlwapi.h>

#pragma comment(lib, "shlwapi.lib")

static void fail(const char *what) {
    fprintf(stderr, "[parentimage_blind_spot_test] FAILED: %s (GetLastError=%lu)\n", what, GetLastError());
    exit(1);
}

int main(void) {
    char tempDir[MAX_PATH] = { 0 };
    char scratchDir[MAX_PATH] = { 0 };
    char fakeOfficePath[MAX_PATH] = { 0 };
    char systemCmdPath[MAX_PATH] = { 0 };

    if (GetTempPathA(MAX_PATH, tempDir) == 0) fail("GetTempPathA");
    snprintf(scratchDir, MAX_PATH, "%sentity2_evasion_matrix", tempDir);
    CreateDirectoryA(scratchDir, NULL); // ok if it already exists

    if (!GetSystemDirectoryA(systemCmdPath, MAX_PATH)) fail("GetSystemDirectoryA");
    strncat_s(systemCmdPath, MAX_PATH, "\\cmd.exe", MAX_PATH - strlen(systemCmdPath) - 1);

    snprintf(fakeOfficePath, MAX_PATH, "%s\\outlook.exe", scratchDir);

    printf("[parentimage_blind_spot_test] copying %s -> %s (harmless renamed copy, deleted at end)\n",
           systemCmdPath, fakeOfficePath);
    if (!CopyFileA(systemCmdPath, fakeOfficePath, FALSE)) {
        fail("CopyFileA");
    }

    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    char cmdLine[2 * MAX_PATH];
    snprintf(cmdLine, sizeof(cmdLine),
             "\"%s\" /c \"cmd.exe /c echo child-of-fake-office-parent & timeout /t 3 >nul\"",
             fakeOfficePath);

    printf("[parentimage_blind_spot_test] this harness's own pid=%lu\n", GetCurrentProcessId());
    printf("[parentimage_blind_spot_test] launching renamed copy as the REAL (non-spoofed) parent: %s\n",
           fakeOfficePath);

    if (!CreateProcessA(NULL, cmdLine, NULL, NULL, FALSE,
                         CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        fail("CreateProcessA");
    }
    printf("[parentimage_blind_spot_test] fake-office process launched, pid=%lu\n", pi.dwProcessId);
    printf("[parentimage_blind_spot_test] it will in turn spawn a REAL cmd.exe child (a LOLBIN_CHILDREN name) - "
           "watch for that child's own pid in the sensor logs\n");
    printf("[parentimage_blind_spot_test] expected result on Sysmon/fused dispatch: office_lolbin finding, "
           "parent_name='outlook.exe', score 60\n");
    printf("[parentimage_blind_spot_test] expected result on ETW-only or kernel-only dispatch for the SAME "
           "child pid: no finding - ParentImage is None on both, so parent_name is always '', never 'outlook.exe'\n");

    WaitForSingleObject(pi.hProcess, 6000);
    TerminateProcess(pi.hProcess, 0);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    if (!DeleteFileA(fakeOfficePath)) {
        fprintf(stderr, "[parentimage_blind_spot_test] WARNING: could not delete temp copy %s (GetLastError=%lu) - "
                        "delete it manually\n", fakeOfficePath, GetLastError());
    }

    printf("[parentimage_blind_spot_test] done, temp copy cleaned up\n");
    return 0;
}
