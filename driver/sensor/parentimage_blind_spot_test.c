/*
 * ParentImage blind-spot test harness - proves heuristic_engine.py's
 * office_lolbin check is structurally unreachable on ETW or kernel sensor
 * paths. ETW's ProcessStart carries no parent image path (confirmed via
 * Get-WinEvent); process_correlator.submit_kernel sets ParentImage=None
 * too. basename(None/'') is never in OFFICE_PARENTS, so office_lolbin
 * cannot fire on ETW-only or kernel-only dispatch regardless of actual
 * parent process. Run with all three sensors live to see the finding on
 * the Sysmon/fused dispatch only.
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
