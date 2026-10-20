/*
 * Phase 2 sensor driver.
 *
 * Three independent kernel-ground-truth sensors, each registered and torn
 * down separately so a failure in one never takes the others down (see
 * DriverEntry/SensorUnload):
 *
 * 1. PROCESS CREATE - real-vs-claimed parent PID (the original Phase 2
 *    capability; see the detailed note above SensorProcessNotify). This is
 *    the one capability this driver cannot safely run without, so its
 *    registration failing still fails the whole load - the other two are
 *    best-effort additions on top of a working core.
 *
 * 2. THREAD CREATE/EXIT - PsSetCreateThreadNotifyRoutine. HONESTY NOTE: on
 *    its own this only proves "a thread appeared in process X" - the
 *    callback carries no field naming WHO created it, unlike process-
 *    create's CreatingThreadId. Attributing a cross-process thread
 *    creation (the actual CreateRemoteThread injection primitive) needs
 *    this correlated with a handle-access signal (ObRegisterCallbacks
 *    watching for PROCESS_CREATE_THREAD rights granted cross-process) -
 *    not yet built. This is a building block, not a complete detector;
 *    it is not sold as one in its log line.
 *
 * 3. IMAGE LOAD - PsSetLoadImageNotifyRoutine. Complements
 *    module_inspector.py's active sweep (which polls every 30s) with
 *    real-time load events. A kernel-mode image load (a new DRIVER
 *    appearing) is rare and high-signal, so it gets its own distinct,
 *    always-logged tag. User-mode DLL loads are logged unconditionally for
 *    now, same "stream everything, let the next layer decide what matters"
 *    posture as PROC-CREATE - staging-path scoping to match
 *    module_inspector.py's STAGING_DIRS and cut the noise down is a known,
 *    deliberate near-term follow-up, not done here.
 *
 * DbgPrintEx at DPFLTR_ERROR_LEVEL throughout, same as hello.c and the
 * original sensor.c: error-level output always reaches an attached kernel
 * debugger regardless of the Kd_*_Mask filter settings.
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
SensorThreadNotify(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId,
    _In_ BOOLEAN Create
    );

VOID
SensorImageLoadNotify(
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_ HANDLE ProcessId,
    _In_ PIMAGE_INFO ImageInfo
    );

// Tracks which best-effort sensors actually registered, so SensorUnload
// only attempts to remove what DriverEntry actually added - calling a
// Ps*Remove* routine for a callback that was never registered is itself
// an error, not a no-op.
static BOOLEAN g_ThreadNotifyRegistered = FALSE;
static BOOLEAN g_ImageLoadNotifyRegistered = FALSE;

VOID
SensorUnload(
    _In_ PDRIVER_OBJECT DriverObject
    )
{
    NTSTATUS status;
    BOOLEAN allClean = TRUE;

    UNREFERENCED_PARAMETER(DriverObject);

    // Process-create: always registered if we got this far (DriverEntry
    // fails the load otherwise), so always remove it.
    status = PsSetCreateProcessNotifyRoutineEx(SensorProcessNotify, TRUE);
    if (!NT_SUCCESS(status)) {
        allClean = FALSE;
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[mal_project] sensor: FAILED to remove process-notify callback, status=0x%08X - "
            "this unload is NOT safe, expect a bugcheck on the next process create\n", status);
    }

    if (g_ThreadNotifyRegistered) {
        status = PsRemoveCreateThreadNotifyRoutine(SensorThreadNotify);
        if (!NT_SUCCESS(status)) {
            allClean = FALSE;
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                "[mal_project] sensor: FAILED to remove thread-notify callback, status=0x%08X - "
                "this unload is NOT safe, expect a bugcheck on the next thread create\n", status);
        }
    }

    if (g_ImageLoadNotifyRegistered) {
        status = PsRemoveLoadImageNotifyRoutine(SensorImageLoadNotify);
        if (!NT_SUCCESS(status)) {
            allClean = FALSE;
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                "[mal_project] sensor: FAILED to remove image-load callback, status=0x%08X - "
                "this unload is NOT safe, expect a bugcheck on the next image load\n", status);
        }
    }

    if (allClean) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[mal_project] sensor: unloading cleanly, all registered callbacks removed\n");
    }
}

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
{
    NTSTATUS status;
    NTSTATUS bestEffortStatus;

    UNREFERENCED_PARAMETER(RegistryPath);

    // Core capability - required. If this fails, there is nothing useful
    // left for this driver to do, so fail the load outright rather than
    // come up in a partially-working state silently.
    status = PsSetCreateProcessNotifyRoutineEx(SensorProcessNotify, FALSE);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[mal_project] sensor: PsSetCreateProcessNotifyRoutineEx failed, status=0x%08X\n", status);
        return status;
    }

    // Best-effort additions below: log failure loudly but keep going -
    // graceful degradation, not an all-or-nothing load. A real-world
    // altitude/resource conflict on one sensor must not take the proven
    // process-create capability down with it.
    bestEffortStatus = PsSetCreateThreadNotifyRoutine(SensorThreadNotify);
    if (NT_SUCCESS(bestEffortStatus)) {
        g_ThreadNotifyRegistered = TRUE;
    } else {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[mal_project] sensor: PsSetCreateThreadNotifyRoutine failed, status=0x%08X - "
            "continuing without thread-create visibility\n", bestEffortStatus);
    }

    bestEffortStatus = PsSetLoadImageNotifyRoutine(SensorImageLoadNotify);
    if (NT_SUCCESS(bestEffortStatus)) {
        g_ImageLoadNotifyRegistered = TRUE;
    } else {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[mal_project] sensor: PsSetLoadImageNotifyRoutine failed, status=0x%08X - "
            "continuing without image-load visibility\n", bestEffortStatus);
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
        "[mal_project] sensor: DriverEntry reached, process-create callback registered "
        "(thread-notify=%d, image-load=%d), built %s %s\n",
        g_ThreadNotifyRegistered, g_ImageLoadNotifyRegistered, __DATE__, __TIME__);

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

VOID
SensorThreadNotify(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId,
    _In_ BOOLEAN Create
    )
{
    // See the HONESTY NOTE at the top of this file: this proves a thread
    // appeared/exited in ProcessId, not who created it. The tag is named
    // accordingly rather than implying an injection verdict it cannot make.
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
        "[mal_project] THREAD-%s: pid=%p tid=%p\n",
        Create ? "CREATE" : "EXIT", ProcessId, ThreadId);
}

VOID
SensorImageLoadNotify(
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_ HANDLE ProcessId,
    _In_ PIMAGE_INFO ImageInfo
    )
{
    BOOLEAN isKernelImage = (ImageInfo != NULL) && (ImageInfo->SystemModeImage != 0);
    PVOID imageBase = (ImageInfo != NULL) ? ImageInfo->ImageBase : NULL;

    if (isKernelImage) {
        // A new kernel-mode image (driver) loading is rare and high-signal -
        // always worth knowing about, unconditionally, unlike the
        // necessarily-noisier user-mode DLL case below.
        if (FullImageName != NULL) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                "[mal_project] DRIVER-LOAD: pid=%p base=%p image=%wZ\n",
                ProcessId, imageBase, FullImageName);
        } else {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                "[mal_project] DRIVER-LOAD: pid=%p base=%p image=(none)\n",
                ProcessId, imageBase);
        }
        return;
    }

    if (FullImageName != NULL) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[mal_project] IMAGE-LOAD: pid=%p base=%p image=%wZ\n",
            ProcessId, imageBase, FullImageName);
    } else {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[mal_project] IMAGE-LOAD: pid=%p base=%p image=(none)\n",
            ProcessId, imageBase);
    }
}
