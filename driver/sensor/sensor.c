/*
 * Phase 2 sensor driver: real-parent-PID validation on process creation.
 *
 * Sysmon's ParentProcessId (Event ID 1) is read from
 * EPROCESS->InheritedFromUniqueProcessId, which a caller can legitimately
 * set to any running process via the PROC_THREAD_ATTRIBUTE_PARENT_PROCESS
 * attribute of UpdateProcThreadAttribute - a documented Windows API, not an
 * exploit. That makes Sysmon's parent field a CLAIM, not a fact.
 *
 * PsSetCreateProcessNotifyRoutineEx's PS_CREATE_NOTIFY_INFO carries a second,
 * independent field: CreatingThreadId.UniqueProcess, the process that
 * actually called NtCreateUserProcess. That value is populated by the
 * kernel at creation time and is not something the attribute can influence.
 * Comparing the two exposes any process whose claimed parent differs from
 * its real creator.
 *
 * IMPORTANT HONESTY NOTE (why this is a signal, not yet an alert): a mismatch
 * here is not proof of malice. Windows' own shell/AppX activation path
 * legitimately re-parents UWP app launches to explorer.exe this same way, so
 * some mismatches on a normal desktop are expected background noise. This
 * driver only proves the detection mechanism and streams every observation
 * to the debugger; deciding which mismatches are suspicious belongs to the
 * user-mode agent (a later phase), the same way this project already treats
 * every other heuristic as evidence to be weighed, not an automatic verdict.
 *
 * DbgPrintEx at DPFLTR_ERROR_LEVEL is used deliberately, same as hello.c:
 * error-level messages always reach an attached kernel debugger regardless
 * of the Kd_*_Mask filter settings.
 */
#include <ntddk.h>

DRIVER_UNLOAD SensorUnload;
DRIVER_INITIALIZE DriverEntry;

VOID
SensorProcessNotify(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
    );

VOID
SensorUnload(
    _In_ PDRIVER_OBJECT DriverObject
    )
{
    NTSTATUS status;

    UNREFERENCED_PARAMETER(DriverObject);

    status = PsSetCreateProcessNotifyRoutineEx(SensorProcessNotify, TRUE);
    if (!NT_SUCCESS(status)) {
        // A callback left dangling after unload is worse than refusing to
        // unload: the driver image goes away but the kernel still holds a
        // pointer into it, which is a guaranteed future bugcheck the moment
        // a process is created. Make this loud - there is nothing else this
        // driver can do about it once DriverUnload has been called, since
        // the I/O manager does not let DriverUnload fail.
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[mal_project] sensor: FAILED to remove process-notify callback, status=0x%08X - "
            "this unload is NOT safe, expect a bugcheck on the next process create\n", status);
    } else {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[mal_project] sensor: unloading cleanly, callback removed\n");
    }
}

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
{
    NTSTATUS status;

    UNREFERENCED_PARAMETER(RegistryPath);

    status = PsSetCreateProcessNotifyRoutineEx(SensorProcessNotify, FALSE);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[mal_project] sensor: PsSetCreateProcessNotifyRoutineEx failed, status=0x%08X\n", status);
        return status;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
        "[mal_project] sensor: DriverEntry reached, process-create callback registered, built %s %s\n",
        __DATE__, __TIME__);

    DriverObject->DriverUnload = SensorUnload;

    return STATUS_SUCCESS;
}

VOID
SensorProcessNotify(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
    )
{
    HANDLE realCreatorPid;
    PCUNICODE_STRING imageName;

    UNREFERENCED_PARAMETER(Process);

    if (CreateInfo == NULL) {
        // Process exit notification, not a create - nothing to validate.
        return;
    }

    realCreatorPid = CreateInfo->CreatingThreadId.UniqueProcess;
    imageName = CreateInfo->ImageFileName;

    if (imageName != NULL) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[mal_project] PROC-CREATE: pid=%p claimed_parent=%p real_creator=%p image=%wZ\n",
            ProcessId, CreateInfo->ParentProcessId, realCreatorPid, imageName);
    } else {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[mal_project] PROC-CREATE: pid=%p claimed_parent=%p real_creator=%p image=(none)\n",
            ProcessId, CreateInfo->ParentProcessId, realCreatorPid);
    }

    if (CreateInfo->ParentProcessId != realCreatorPid) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[mal_project] PPID-SPOOF: pid=%p claimed_parent=%p real_creator=%p\n",
            ProcessId, CreateInfo->ParentProcessId, realCreatorPid);
    }
}
