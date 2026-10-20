/*
 * PPID-spoofing test harness for driver/sensor/sensor.c.
 *
 * Nothing else in this project exercises this technique - vm_eval.py's
 * scenario list deliberately excluded it (there was no way to prove
 * detection without a kernel sensor; see the Phase 2 task notes). This is
 * that proof.
 *
 * What it does:
 *   1. Launches a throwaway, harmless "fake parent" process (cmd.exe,
 *      sitting idle on a long timeout) and keeps its own, fully-privileged
 *      handle to it - we created it ourselves, so no extra access rights
 *      need to be requested.
 *   2. Uses STARTUPINFOEX + InitializeProcThreadAttributeList +
 *      UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_PARENT_PROCESS) -
 *      a documented Windows API, not an exploit - to launch a REAL child
 *      process while telling the OS its parent is the fake-parent process
 *      from step 1, not this test harness itself (the actual caller).
 *   3. Prints every PID involved so the operator can cross-check against
 *      what the driver reports in WinDbg:
 *        - this harness's own PID            = the REAL creator
 *        - the fake parent's PID             = the CLAIMED parent
 *        - the spoofed child's PID           = the new process sensor.c
 *          should report a PPID-SPOOF line for
 *   4. Cleans up both child processes afterward - nothing is left running.
 *
 * Build (from a VS Developer environment, x64):
 *   cl.exe /nologo /W4 /EHsc ppid_spoof_test.c /link /OUT:ppid_spoof_test.exe
 */
#include <windows.h>
#include <stdio.h>

static void fail(const char *what) {
    fprintf(stderr, "[ppid_spoof_test] FAILED: %s (GetLastError=%lu)\n", what, GetLastError());
    exit(1);
}

int main(void) {
    // --- Step 1: launch the throwaway "fake parent" ------------------------
    STARTUPINFOA fakeParentSi = { sizeof(fakeParentSi) };
    PROCESS_INFORMATION fakeParentPi = { 0 };
    char fakeParentCmd[] = "cmd.exe /c timeout /t 30 >nul";

    if (!CreateProcessA(NULL, fakeParentCmd, NULL, NULL, FALSE,
                         CREATE_NO_WINDOW, NULL, NULL, &fakeParentSi, &fakeParentPi)) {
        fail("CreateProcessA(fake parent)");
    }
    printf("[ppid_spoof_test] fake parent launched, pid=%lu\n", fakeParentPi.dwProcessId);

    // --- Step 2: build the attribute list naming it as the claimed parent --
    SIZE_T attrListSize = 0;
    InitializeProcThreadAttributeList(NULL, 1, 0, &attrListSize);
    LPPROC_THREAD_ATTRIBUTE_LIST attrList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(
        GetProcessHeap(), 0, attrListSize);
    if (!attrList) fail("HeapAlloc(attribute list)");

    if (!InitializeProcThreadAttributeList(attrList, 1, 0, &attrListSize)) {
        fail("InitializeProcThreadAttributeList");
    }
    if (!UpdateProcThreadAttribute(attrList, 0,
                                    PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                                    &fakeParentPi.hProcess, sizeof(HANDLE), NULL, NULL)) {
        fail("UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_PARENT_PROCESS)");
    }

    STARTUPINFOEXA childSi = { 0 };
    childSi.StartupInfo.cb = sizeof(childSi);
    childSi.lpAttributeList = attrList;
    PROCESS_INFORMATION childPi = { 0 };
    char childCmd[] = "cmd.exe /c echo spoofed-child-running & timeout /t 5 >nul";

    printf("[ppid_spoof_test] this harness's own pid=%lu (the REAL creator sensor.c should report)\n",
           GetCurrentProcessId());
    printf("[ppid_spoof_test] launching spoofed child, claiming parent pid=%lu (the fake parent - this is the mismatch)\n",
           fakeParentPi.dwProcessId);

    if (!CreateProcessA(NULL, childCmd, NULL, NULL, FALSE,
                         EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW,
                         NULL, NULL, &childSi.StartupInfo, &childPi)) {
        fail("CreateProcessA(spoofed child)");
    }
    printf("[ppid_spoof_test] spoofed child launched, pid=%lu\n", childPi.dwProcessId);
    printf("[ppid_spoof_test] expected WinDbg line: PPID-SPOOF pid=0x%lx claimed_parent=0x%lx real_creator=0x%lx\n",
           childPi.dwProcessId, fakeParentPi.dwProcessId, GetCurrentProcessId());

    // Give the sensor driver a moment to have fired before we tear down.
    Sleep(2000);

    // --- Step 4: clean up - nothing left running afterward ------------------
    TerminateProcess(childPi.hProcess, 0);
    TerminateProcess(fakeParentPi.hProcess, 0);
    CloseHandle(childPi.hProcess);
    CloseHandle(childPi.hThread);
    CloseHandle(fakeParentPi.hProcess);
    CloseHandle(fakeParentPi.hThread);
    DeleteProcThreadAttributeList(attrList);
    HeapFree(GetProcessHeap(), 0, attrList);

    printf("[ppid_spoof_test] done, both processes cleaned up\n");
    return 0;
}
