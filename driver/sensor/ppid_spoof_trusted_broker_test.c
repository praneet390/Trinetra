/*
 * Trusted-broker PPID-spoofing test harness for driver/sensor/sensor.c +
 * heuristic_engine.py's kernel_ppid_spoof check.
 *
 * ppid_spoof_test.c already proves the kernel sensor catches a spoofed
 * PPID when the REAL creator is an untrusted, arbitrary process (scored
 * 80). heuristic_engine._handle_process_create has a second branch for
 * this same check that this harness exists to exercise instead:
 *
 *     is_trusted_creator = _is_trusted_system_path(creator_image)
 *     score = 20 if is_trusted_creator else 80
 *
 * Read literally: the discount applies when the REAL CREATOR (the
 * process that actually called CreateProcess - resolved from the
 * driver's CreatingThreadId, i.e. field3/real_creator_pid, NOT the
 * claimed/spoofed parent) resolves to a path under System32/SysWOW64.
 * That is NOT the same thing as "the claimed parent looks trusted" -
 * it is "whoever actually made the CreateProcess call looks trusted."
 * This is also the exact code path the dc5f6e4 Outlook fix exists to
 * tune (a live, legitimate System32 broker doing normal COM/packaged-
 * app reparenting must not auto-kill a real mail client).
 *
 * A normal user-mode EXE launched from a regular path can't make the
 * "real creator" field read as System32 just by choosing where its own
 * .exe file sits - the driver resolves the ACTUAL calling process's own
 * image path, not anything this harness claims about itself. So this
 * harness is built as a DLL and must be loaded into an already-signed,
 * already-System32-resident host process via rundll32.exe - the
 * textbook LOLBin pattern (COMMAND_LINE_HOSTS already enumerates
 * rundll32.exe as a LOLBIN_CHILD elsewhere in this project) - so that
 * when THIS CODE calls CreateProcessA, the real creator the kernel
 * observes is genuinely rundll32.exe running from
 * C:\Windows\System32\rundll32.exe. Nothing is injected into another
 * already-running process; rundll32 loading an attacker/test-authored
 * DLL via its own documented command-line usage is rundll32 operating
 * exactly as designed.
 *
 * What it does, once loaded:
 *   1. Launches a throwaway "claimed parent" (idle cmd.exe) exactly like
 *      ppid_spoof_test.c.
 *   2. Spawns a real child claiming that throwaway as its parent via
 *      PROC_THREAD_ATTRIBUTE_PARENT_PROCESS - but the REAL creator this
 *      time is rundll32.exe (this DLL's own host process), not an
 *      arbitrary unsigned test binary.
 *   3. Prints every PID via an allocated console (rundll32 attaches no
 *      console by default) so the operator can cross-check the kernel
 *      sensor's PROC-CREATE line and heuristic_engine's resulting score
 *      (expected: 20, "Trusted-broker PPID spoofing", not 80).
 *   4. Cleans up both spawned processes afterward.
 *
 * Build (from a VS Developer environment, x64):
 *   cl.exe /nologo /W4 /EHsc /LD ppid_spoof_trusted_broker_test.c /link /OUT:ppid_spoof_trusted_broker_test.dll
 *
 * Run:
 *   rundll32.exe ppid_spoof_trusted_broker_test.dll,RunTest
 */
#include <windows.h>
#include <stdio.h>

static void fail(const char *what) {
    fprintf(stderr, "[ppid_spoof_trusted_broker_test] FAILED: %s (GetLastError=%lu)\n", what, GetLastError());
}

__declspec(dllexport) void CALLBACK RunTest(HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow) {
    UNREFERENCED_PARAMETER(hwnd);
    UNREFERENCED_PARAMETER(hinst);
    UNREFERENCED_PARAMETER(lpszCmdLine);
    UNREFERENCED_PARAMETER(nCmdShow);

    AllocConsole();
    FILE *conOut = NULL;
    freopen_s(&conOut, "CONOUT$", "w", stdout);
    freopen_s(&conOut, "CONOUT$", "w", stderr);

    char selfPath[MAX_PATH] = { 0 };
    GetModuleFileNameA(NULL, selfPath, MAX_PATH); // the HOST process (rundll32.exe), not this DLL
    printf("[ppid_spoof_trusted_broker_test] host process (the REAL creator sensor.c will report) = %s, pid=%lu\n",
           selfPath, GetCurrentProcessId());

    // --- Step 1: throwaway claimed-parent process --------------------------
    STARTUPINFOA fakeParentSi = { sizeof(fakeParentSi) };
    PROCESS_INFORMATION fakeParentPi = { 0 };
    char fakeParentCmd[] = "cmd.exe /c timeout /t 30 >nul";

    if (!CreateProcessA(NULL, fakeParentCmd, NULL, NULL, FALSE,
                         CREATE_NO_WINDOW, NULL, NULL, &fakeParentSi, &fakeParentPi)) {
        fail("CreateProcessA(claimed parent)");
        FreeConsole();
        return;
    }
    printf("[ppid_spoof_trusted_broker_test] claimed parent launched, pid=%lu\n", fakeParentPi.dwProcessId);

    // --- Step 2: spoofed child, real creator = this host process -----------
    SIZE_T attrListSize = 0;
    InitializeProcThreadAttributeList(NULL, 1, 0, &attrListSize);
    LPPROC_THREAD_ATTRIBUTE_LIST attrList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(
        GetProcessHeap(), 0, attrListSize);
    if (!attrList) {
        fail("HeapAlloc(attribute list)");
        goto cleanup_fake_parent;
    }
    if (!InitializeProcThreadAttributeList(attrList, 1, 0, &attrListSize)) {
        fail("InitializeProcThreadAttributeList");
        goto cleanup_attr;
    }
    if (!UpdateProcThreadAttribute(attrList, 0,
                                    PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                                    &fakeParentPi.hProcess, sizeof(HANDLE), NULL, NULL)) {
        fail("UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_PARENT_PROCESS)");
        goto cleanup_attr;
    }

    STARTUPINFOEXA childSi = { 0 };
    childSi.StartupInfo.cb = sizeof(childSi);
    childSi.lpAttributeList = attrList;
    PROCESS_INFORMATION childPi = { 0 };
    char childCmd[] = "cmd.exe /c echo spoofed-child-of-trusted-broker & timeout /t 5 >nul";

    printf("[ppid_spoof_trusted_broker_test] launching spoofed child, claiming parent pid=%lu "
           "(real creator will be the host process above - %s)\n",
           fakeParentPi.dwProcessId, selfPath);

    if (!CreateProcessA(NULL, childCmd, NULL, NULL, FALSE,
                         EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW,
                         NULL, NULL, &childSi.StartupInfo, &childPi)) {
        fail("CreateProcessA(spoofed child)");
        goto cleanup_attr;
    }
    printf("[ppid_spoof_trusted_broker_test] spoofed child launched, pid=%lu\n", childPi.dwProcessId);
    printf("[ppid_spoof_trusted_broker_test] expected WinDbg line: PPID-SPOOF pid=0x%lx claimed_parent=0x%lx real_creator=0x%lx\n",
           childPi.dwProcessId, fakeParentPi.dwProcessId, GetCurrentProcessId());
    printf("[ppid_spoof_trusted_broker_test] expected heuristic_engine score: 20 (Trusted-broker PPID spoofing), "
           "NOT 80 - because the real creator (%s) resolves under System32\n", selfPath);

    Sleep(2000);

    TerminateProcess(childPi.hProcess, 0);
    CloseHandle(childPi.hProcess);
    CloseHandle(childPi.hThread);

cleanup_attr:
    DeleteProcThreadAttributeList(attrList);
    HeapFree(GetProcessHeap(), 0, attrList);

cleanup_fake_parent:
    TerminateProcess(fakeParentPi.hProcess, 0);
    CloseHandle(fakeParentPi.hProcess);
    CloseHandle(fakeParentPi.hThread);

    printf("[ppid_spoof_trusted_broker_test] done, both processes cleaned up\n");
    FreeConsole();
}
