/*
 * Trusted-broker PPID-spoofing test harness for driver/sensor/sensor.c +
 * heuristic_engine.py's kernel_ppid_spoof check.
 *
 * ppid_spoof_test.c exercises the score=80 path. This harness exercises
 * the score=20 path: when the REAL CREATOR (resolved from CreatingThreadId,
 * not the claimed/spoofed parent) resolves to a System32/SysWOW64 path.
 * This is the code path the dc5f6e4 Outlook fix tunes (a legitimate
 * System32 broker doing COM/packaged-app reparenting must not score 80).
 *
 * Built as a DLL loaded via rundll32.exe so the kernel observes the real
 * creator as C:\Windows\System32\rundll32.exe - a normal user-mode EXE
 * cannot make its own image path appear as System32 just by file location.
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
