/*
 * Comms-channel end-to-end test for driver/sensor/sensor.c's IOCTL interface.
 *
 * The struct/IOCTL definitions below are a deliberate, exact copy of the
 * ones in sensor.c - there is no shared header yet (the real Python
 * consumer will need its own ctypes mirror anyway), so this is read
 * carefully against sensor.c's definitions, not assumed to match.
 *
 * Build (from a VS Developer environment, x64):
 *   cl.exe /nologo /W4 /EHsc comms_channel_test.c /link /OUT:comms_channel_test.exe
 */
#include <windows.h>
#include <stdio.h>

#define IOCTL_MALPROJECT_GET_EVENT \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

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

static const char *EventTypeName(UINT32 t) {
    switch (t) {
        case SensorEventProcessCreate: return "ProcessCreate";
        case SensorEventLsassAccess:   return "LsassAccess";
        case SensorEventDriverLoad:    return "DriverLoad";
        default:                       return "Unknown";
    }
}

int main(void) {
    printf("[comms_channel_test] sizeof(SENSOR_EVENT) = %zu bytes (must match sensor.c's layout)\n", sizeof(SENSOR_EVENT));

    HANDLE h = CreateFileW(L"\\\\.\\malprojectsensor", GENERIC_READ | GENERIC_WRITE,
                            0, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "[comms_channel_test] FAILED: CreateFileW, GetLastError=%lu\n", GetLastError());
        return 1;
    }
    printf("[comms_channel_test] device opened successfully\n");

    int totalEvents = 0;
    UINT64 lastSeq = 0;
    BOOLEAN haveLastSeq = FALSE;

    printf("[comms_channel_test] polling for 8 seconds - go do something (launch a process, etc.)\n");
    DWORD startTick = GetTickCount();
    while (GetTickCount() - startTick < 8000) {
        SENSOR_EVENT ev;
        ZeroMemory(&ev, sizeof(ev));
        DWORD bytesReturned = 0;

        BOOL ok = DeviceIoControl(h, IOCTL_MALPROJECT_GET_EVENT, NULL, 0,
                                   &ev, sizeof(ev), &bytesReturned, NULL);
        if (!ok) {
            fprintf(stderr, "[comms_channel_test] DeviceIoControl FAILED, GetLastError=%lu\n", GetLastError());
            break;
        }

        if (bytesReturned == sizeof(ev)) {
            totalEvents++;
            if (haveLastSeq && ev.SequenceNumber != lastSeq + 1) {
                printf("[comms_channel_test]   *** SEQUENCE GAP: expected %llu, got %llu (dropped %llu) ***\n",
                       (unsigned long long)(lastSeq + 1), (unsigned long long)ev.SequenceNumber,
                       (unsigned long long)(ev.SequenceNumber - lastSeq - 1));
            }
            lastSeq = ev.SequenceNumber;
            haveLastSeq = TRUE;

            printf("[comms_channel_test] #%d seq=%llu type=%s pid=%llu field2=%llu field3=%llu field4=0x%llx ppid_spoof=%u trunc=%u image=%ls\n",
                   totalEvents, (unsigned long long)ev.SequenceNumber, EventTypeName(ev.EventType),
                   (unsigned long long)ev.Pid, (unsigned long long)ev.ClaimedParentOrRequestorPid,
                   (unsigned long long)ev.RealCreatorPid, (unsigned long long)ev.DesiredAccessOrImageBase,
                   ev.PpidSpoofDetected, ev.ImageNameTruncated, ev.ImageName);
        } else {
            // No event right now - brief sleep before retrying, same
            // polling cadence the real Python consumer will use.
            Sleep(50);
        }
    }

    printf("[comms_channel_test] done - %d event(s) received\n", totalEvents);
    CloseHandle(h);
    return 0;
}
