/*
 * LSASS handle-access test harness for driver/sensor/sensor.c's
 * ObRegisterCallbacks sensor.
 *
 * OpenProcess will fail with ERROR_ACCESS_DENIED (PPL on modern Windows
 * blocks it). The point is to prove the KERNEL SENSOR observes the
 * ATTEMPT: ObRegisterCallbacks' pre-operation callback fires before the
 * OS access check, including PPL enforcement.
 *
 * Build (from a VS Developer environment, x64):
 *   cl.exe /nologo /W4 /EHsc lsass_access_test.c /link /OUT:lsass_access_test.exe
 */
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

static DWORD FindLsassPid(void) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        return 0;
    }

    PROCESSENTRY32 pe = { sizeof(pe) };
    DWORD pid = 0;

    if (Process32First(snap, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, "lsass.exe") == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(snap, &pe));
    }

    CloseHandle(snap);
    return pid;
}

int main(void) {
    DWORD lsassPid = FindLsassPid();
    if (lsassPid == 0) {
        fprintf(stderr, "[lsass_access_test] FAILED: could not find lsass.exe in process snapshot\n");
        return 1;
    }

    printf("[lsass_access_test] found lsass.exe, pid=%lu (0x%lx)\n", lsassPid, lsassPid);
    printf("[lsass_access_test] this harness's own pid=%lu (0x%lx) - the requestor sensor.c should report\n",
           GetCurrentProcessId(), GetCurrentProcessId());
    printf("[lsass_access_test] calling OpenProcess(PROCESS_VM_READ, FALSE, %lu) ...\n", lsassPid);

    HANDLE h = OpenProcess(PROCESS_VM_READ, FALSE, lsassPid);
    if (h != NULL) {
        // Unexpected on a normal, non-elevated setup, but handle it
        // cleanly either way rather than assuming failure.
        printf("[lsass_access_test] OpenProcess SUCCEEDED (unexpected on a normal setup) - closing handle\n");
        CloseHandle(h);
    } else {
        printf("[lsass_access_test] OpenProcess failed as expected, GetLastError=%lu "
               "(ERROR_ACCESS_DENIED=5 is the normal/expected result here)\n", GetLastError());
    }

    printf("[lsass_access_test] expected WinDbg line: LSASS-ACCESS requestor_pid=0x%lx target_pid=0x%lx "
           "(desired_access should include 0x10 = PROCESS_VM_READ)\n",
           GetCurrentProcessId(), lsassPid);

    return 0;
}
