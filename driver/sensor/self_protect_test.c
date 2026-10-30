/*
 * Self-protection + comms-channel combined test harness.
 *
 * Proves the exact scenario the feature exists for: "anyone with admin on
 * Windows should not be able to switch off the EDR tool with taskkill or
 * anything like it." Registers itself, sits in a window for taskkill to
 * run against (expected: access denied), then unregisters and reopens
 * the window (expected: taskkill succeeds - protection is registration-
 * state-tied, not a blanket unconditional block).
 *
 * Build (from a VS Developer environment, x64):
 *   cl.exe /nologo /W4 /EHsc self_protect_test.c /link /OUT:self_protect_test.exe
 */
#include <windows.h>
#include <stdio.h>
#include <process.h>

#define IOCTL_MALPROJECT_GET_EVENT \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MALPROJECT_REGISTER_SELF \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MALPROJECT_UNREGISTER_SELF \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define SENSOR_EVENT_IMAGE_NAME_MAX_CHARS 260

typedef enum _SENSOR_EVENT_TYPE {
    SensorEventProcessCreate = 1,
    SensorEventLsassAccess   = 2,
    SensorEventDriverLoad    = 3,
} SENSOR_EVENT_TYPE;

#pragma pack(push, 8)
typedef struct _SENSOR_EVENT {
    UINT64 SequenceNumber;
    UINT32 EventType;
    UINT32 PpidSpoofDetected;
    UINT64 Pid;
    UINT64 ClaimedParentOrRequestorPid;
    UINT64 RealCreatorPid;
    UINT64 DesiredAccessOrImageBase;
    UINT32 ImageNameTruncated;
    UINT32 Reserved;
    WCHAR  ImageName[SENSOR_EVENT_IMAGE_NAME_MAX_CHARS];
} SENSOR_EVENT;
#pragma pack(pop)

static HANDLE g_Device = NULL;
static volatile LONG g_StopPolling = 0;

static const char *EventTypeName(UINT32 t) {
    switch (t) {
        case SensorEventProcessCreate: return "ProcessCreate";
        case SensorEventLsassAccess:   return "LsassAccess";
        case SensorEventDriverLoad:    return "DriverLoad";
        default:                       return "Unknown";
    }
}

static unsigned __stdcall PollThread(void *arg) {
    (void)arg;
    while (!g_StopPolling) {
        SENSOR_EVENT ev;
        ZeroMemory(&ev, sizeof(ev));
        DWORD bytesReturned = 0;
        BOOL ok = DeviceIoControl(g_Device, IOCTL_MALPROJECT_GET_EVENT, NULL, 0,
                                   &ev, sizeof(ev), &bytesReturned, NULL);
        if (ok && bytesReturned == sizeof(ev)) {
            printf("  [poll] seq=%llu type=%s pid=%llu image=%ls\n",
                   (unsigned long long)ev.SequenceNumber, EventTypeName(ev.EventType),
                   (unsigned long long)ev.Pid, ev.ImageName);
        } else {
            Sleep(50);
        }
    }
    return 0;
}

static void PrintCountdown(const char *label, int seconds) {
    printf("[self_protect_test] %s - waiting %d seconds ...\n", label, seconds);
    for (int i = seconds; i > 0; i--) {
        printf("[self_protect_test]   still running, %d sec left (pid=%lu)\n", i, GetCurrentProcessId());
        Sleep(1000);
    }
}

int main(void) {
    g_Device = CreateFileW(L"\\\\.\\malprojectsensor", GENERIC_READ | GENERIC_WRITE,
                            0, NULL, OPEN_EXISTING, 0, NULL);
    if (g_Device == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "[self_protect_test] FAILED: CreateFileW, GetLastError=%lu\n", GetLastError());
        return 1;
    }

    DWORD bytesReturned = 0;
    if (!DeviceIoControl(g_Device, IOCTL_MALPROJECT_REGISTER_SELF, NULL, 0, NULL, 0, &bytesReturned, NULL)) {
        fprintf(stderr, "[self_protect_test] FAILED: REGISTER_SELF, GetLastError=%lu\n", GetLastError());
        CloseHandle(g_Device);
        return 1;
    }
    printf("[self_protect_test] registered self as protected, pid=%lu\n", GetCurrentProcessId());

    uintptr_t pollThread = _beginthreadex(NULL, 0, PollThread, NULL, 0, NULL);

    printf("[self_protect_test] ============================================\n");
    printf("[self_protect_test] NOW RUN:  taskkill /F /PID %lu\n", GetCurrentProcessId());
    printf("[self_protect_test] EXPECTED: taskkill fails (access denied), this process survives\n");
    printf("[self_protect_test] ============================================\n");
    PrintCountdown("protected window", 20);

    if (!DeviceIoControl(g_Device, IOCTL_MALPROJECT_UNREGISTER_SELF, NULL, 0, NULL, 0, &bytesReturned, NULL)) {
        fprintf(stderr, "[self_protect_test] FAILED: UNREGISTER_SELF, GetLastError=%lu\n", GetLastError());
    } else {
        printf("[self_protect_test] unregistered - protection removed\n");
    }

    printf("[self_protect_test] ============================================\n");
    printf("[self_protect_test] NOW RUN AGAIN:  taskkill /F /PID %lu\n", GetCurrentProcessId());
    printf("[self_protect_test] EXPECTED: taskkill SUCCEEDS this time\n");
    printf("[self_protect_test] ============================================\n");
    PrintCountdown("unprotected window", 20);

    InterlockedExchange(&g_StopPolling, 1);
    WaitForSingleObject((HANDLE)pollThread, 2000);
    CloseHandle((HANDLE)pollThread);
    CloseHandle(g_Device);
    printf("[self_protect_test] test window complete, exiting normally\n");
    return 0;
}
