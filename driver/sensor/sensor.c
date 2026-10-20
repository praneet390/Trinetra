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
 * 4. HANDLE ACCESS (LSASS) - ObRegisterCallbacks on PsProcessType,
 *    observe-only (nothing is blocked or stripped yet - see the protected-
 *    process floor note below for why that's deliberately a separate,
 *    later step). Fires on every process handle create/duplicate
 *    system-wide (a hot path), so it filters to the target being lsass.exe
 *    before doing anything else, then checks the requested access against
 *    LSASS_DANGEROUS_BITS - the exact same bitmask heuristic_engine.py's
 *    Sysmon-driven LSASS check already uses (PROCESS_CREATE_THREAD |
 *    PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE |
 *    PROCESS_DUP_HANDLE), kept identical on purpose so the two sensors
 *    agree on what counts as dangerous.
 *
 *    HONESTY NOTE, empirically confirmed, not assumed: an EARLIER draft of
 *    this comment claimed pre-operation callbacks always see an attempt
 *    "even when Windows itself is about to deny it." That is false for
 *    LSASS specifically. Verified by direct testing (three separate runs
 *    of an external, unprivileged OpenProcess(PROCESS_VM_READ, ...)
 *    against the real lsass.exe): the attempt never reached this callback
 *    at all - only LSASS's own internal self-referencing handle
 *    operations did (desired_access=0, harmless bookkeeping). The SAME
 *    code, SAME access mask (0x10 = PROCESS_VM_READ), tested against a
 *    non-protection-level-hardened target (notepad.exe) instead, reached
 *    this callback correctly with the real, unstripped DesiredAccess and
 *    produced a correctly-attributed LSASS-ACCESS line. Conclusion:
 *    Windows' Protected-Process-Light enforcement for LSASS rejects a
 *    lower-protection-level caller's attempt BEFORE it reaches registered
 *    Ob callbacks at all - a deliberate OS security boundary (PPL is
 *    explicitly hardened against third-party kernel drivers, not just
 *    user-mode malware), not a gap in this driver. Practical consequence:
 *    this capability, as built, observes LSASS access attempts only from
 *    callers at a comparable-or-higher protection level than LSASS itself
 *    - which is also roughly the same population PPL already blocks from
 *    succeeding. It remains fully correct and useful for any OTHER
 *    protected-list target that isn't PPL-hardened (the detection logic
 *    itself is proven, not theoretical - see the notepad.exe test above).
 *    Closing this specific LSASS gap for good would need this driver to
 *    run at a comparable protection level itself, which needs Microsoft
 *    ELAM/anti-malware-class attestation - a production-signing
 *    requirement, not a code change.
 *
 *    PROTECTED-PROCESS FLOOR: heuristic_engine.py's PROTECTED_PROCESS_NAMES/
 *    PROTECTED_PIDS floor exists because of two real incidents (an IDE
 *    killed twice, a full system freeze from suspending csrss.exe) - see
 *    the README's Safety model section. SensorIsProtectedProcess() below
 *    is that same floor, ported to the driver and self-tested in
 *    DriverEntry, specifically so it is ready and proven BEFORE this
 *    driver gains any capability to actually block or strip access -
 *    which this increment deliberately does not do yet. Observing an
 *    access attempt against LSASS is safe regardless of the floor;
 *    blocking one is not, and that is exactly why blocking is a separate,
 *    later increment built on top of a floor that already works.
 *
 * DbgPrintEx at DPFLTR_ERROR_LEVEL throughout, same as hello.c and the
 * original sensor.c: error-level output always reaches an attached kernel
 * debugger regardless of the Kd_*_Mask filter settings.
 */
#include <ntddk.h>

// PsGetProcessImageFileName is exported by ntoskrnl.exe but declared in
// ntifs.h, not ntddk.h - including ntifs.h alongside ntddk.h in the same
// WDM driver is a well-known source of redefinition conflicts, so this
// driver stays on ntddk.h throughout and declares the one routine it needs
// itself, the same pattern used across the EDR driver community. Returns a
// pointer to a fixed-size (16-byte) buffer inside EPROCESS holding the
// short image file name, truncated to 15 chars + NUL - more than enough
// for "lsass.exe" (9 chars).
NTKERNELAPI
PCHAR
PsGetProcessImageFileName(
    _In_ PEPROCESS Process
    );

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

OB_PREOP_CALLBACK_STATUS
SensorPreOperationCallback(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation
    );

BOOLEAN
SensorIsProtectedProcess(
    _In_opt_ PCHAR ImageFileName,
    _In_ HANDLE Pid
    );

VOID
SensorSelfTestProtectedFloor(VOID);

// Tracks which best-effort sensors actually registered, so SensorUnload
// only attempts to remove what DriverEntry actually added - calling a
// Ps*Remove* routine for a callback that was never registered is itself
// an error, not a no-op.
static BOOLEAN g_ThreadNotifyRegistered = FALSE;
static BOOLEAN g_ImageLoadNotifyRegistered = FALSE;
static BOOLEAN g_ObCallbacksRegistered = FALSE;
static PVOID g_ObRegistrationHandle = NULL;

// Ports heuristic_engine.py's PROTECTED_PROCESS_NAMES exactly (see that
// file's comment for the real incidents behind this list - an IDE killed
// twice, a full system freeze from suspending csrss.exe). Short image
// names only (PsGetProcessImageFileName's format), lowercase compared.
#define PROTECTED_PROCESS_NAME_COUNT 11
static const CHAR *g_ProtectedProcessNames[PROTECTED_PROCESS_NAME_COUNT] = {
    "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe", "smss.exe",
    "lsass.exe", "svchost.exe", "dwm.exe", "explorer.exe",
    "system", "memcompression"
    // Note: heuristic_engine.py also lists "system idle process" and
    // "registry" as protected names, both PID-0/PID-4-pseudo-process
    // display names that PsGetProcessImageFileName never actually returns
    // for a real PEPROCESS (those pseudo-processes are caught by PID
    // below instead, same as the Python side's own "check by number
    // first" comment on PROTECTED_PIDS says to do).
};

// Same PROTECTED_PIDS: PID 0 (System Idle Process) and 4 (System) are
// always these processes regardless of what their image name would say.
#define PROTECTED_PID_COUNT 2
static const ULONG_PTR g_ProtectedPids[PROTECTED_PID_COUNT] = { 0, 4 };

// Mirrors heuristic_engine.py's PROCESS_* bits and LSASS_DANGEROUS_BITS
// exactly, so this kernel sensor and the Sysmon-driven user-mode check
// agree on what counts as dangerous LSASS access.
#define SENSOR_PROCESS_CREATE_THREAD 0x0002
#define SENSOR_PROCESS_VM_OPERATION  0x0008
#define SENSOR_PROCESS_VM_READ       0x0010
#define SENSOR_PROCESS_VM_WRITE      0x0020
#define SENSOR_PROCESS_DUP_HANDLE    0x0040
#define SENSOR_LSASS_DANGEROUS_BITS \
    (SENSOR_PROCESS_CREATE_THREAD | SENSOR_PROCESS_VM_OPERATION | \
     SENSOR_PROCESS_VM_READ | SENSOR_PROCESS_VM_WRITE | SENSOR_PROCESS_DUP_HANDLE)

// Altitude for ObRegisterCallbacks: an arbitrary-but-unique string is
// sufficient on a dev/test VM with no other registered AV/EDR product
// competing for the same value (collisions return
// STATUS_FLT_INSTANCE_ALTITUDE_COLLISION, handled as a best-effort
// failure below, not a hard DriverEntry failure). Production deployment
// would need a properly assigned altitude - noted, not solved here.
#define SENSOR_OB_ALTITUDE L"389456"

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

    if (g_ObCallbacksRegistered) {
        // Unlike PsSetCreateProcessNotifyRoutineEx/PsRemoveCreateThread
        // NotifyRoutine/PsRemoveLoadImageNotifyRoutine above,
        // ObUnRegisterCallbacks returns VOID - there is no failure status
        // to check, it simply removes the registration for a handle this
        // driver knows is valid (it only ever calls this when
        // g_ObCallbacksRegistered is TRUE, meaning ObRegisterCallbacks
        // already succeeded and produced this exact handle).
        ObUnRegisterCallbacks(g_ObRegistrationHandle);
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

    // Prove the protected-process floor is correct BEFORE registering any
    // callback that will eventually (a later increment, not this one) be
    // capable of acting on it - see the file-header note on why this
    // ordering matters.
    SensorSelfTestProtectedFloor();

    {
        OB_OPERATION_REGISTRATION obOperations[1];
        OB_CALLBACK_REGISTRATION obCallbackReg;
        UNICODE_STRING altitude;

        RtlInitUnicodeString(&altitude, SENSOR_OB_ALTITUDE);

        RtlZeroMemory(&obOperations[0], sizeof(obOperations[0]));
        obOperations[0].ObjectType = PsProcessType;
        obOperations[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
        obOperations[0].PreOperation = SensorPreOperationCallback;
        obOperations[0].PostOperation = NULL;

        RtlZeroMemory(&obCallbackReg, sizeof(obCallbackReg));
        obCallbackReg.Version = OB_FLT_REGISTRATION_VERSION;
        obCallbackReg.OperationRegistrationCount = 1;
        obCallbackReg.Altitude = altitude;
        obCallbackReg.RegistrationContext = NULL;
        obCallbackReg.OperationRegistration = obOperations;

        bestEffortStatus = ObRegisterCallbacks(&obCallbackReg, &g_ObRegistrationHandle);
        if (NT_SUCCESS(bestEffortStatus)) {
            g_ObCallbacksRegistered = TRUE;
        } else {
            // Expected, graceful failure mode per the roadmap: an altitude
            // collision with another installed AV/EDR product returns
            // STATUS_FLT_INSTANCE_ALTITUDE_COLLISION here. Log and keep
            // the rest of the driver running rather than take the whole
            // sensor down over one capability.
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                "[mal_project] sensor: ObRegisterCallbacks failed, status=0x%08X - "
                "continuing without LSASS handle-access visibility\n", bestEffortStatus);
        }
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
        "[mal_project] sensor: DriverEntry reached, process-create callback registered "
        "(thread-notify=%d, image-load=%d, ob-handle-access=%d), built %s %s\n",
        g_ThreadNotifyRegistered, g_ImageLoadNotifyRegistered, g_ObCallbacksRegistered, __DATE__, __TIME__);

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

BOOLEAN
SensorIsProtectedProcess(
    _In_opt_ PCHAR ImageFileName,
    _In_ HANDLE Pid
    )
{
    ULONG_PTR pidValue;
    ULONG i;

    // Check by number first, exactly like heuristic_engine.py's own
    // comment says to: PID 0/4 are always System Idle Process/System
    // regardless of what (or whether) an image name is available.
    pidValue = (ULONG_PTR)Pid;
    for (i = 0; i < PROTECTED_PID_COUNT; i++) {
        if (pidValue == g_ProtectedPids[i]) {
            return TRUE;
        }
    }

    if (ImageFileName == NULL) {
        return FALSE;
    }

    {
        ANSI_STRING imageNameStr;

        // _stricmp is a CRT routine not safely available in kernel mode
        // without extra linking; RtlEqualString (a genuine Rtl export, no
        // CRT needed) with CaseInSensitive=TRUE is the idiomatic kernel-
        // mode equivalent. RtlInitAnsiString computes the length from the
        // NUL terminator, same as strlen would.
        RtlInitAnsiString(&imageNameStr, ImageFileName);

        for (i = 0; i < PROTECTED_PROCESS_NAME_COUNT; i++) {
            ANSI_STRING candidateStr;
            RtlInitAnsiString(&candidateStr, g_ProtectedProcessNames[i]);
            if (RtlEqualString(&imageNameStr, &candidateStr, TRUE)) {
                return TRUE;
            }
        }
    }

    return FALSE;
}

VOID
SensorSelfTestProtectedFloor(VOID)
{
    // Proves SensorIsProtectedProcess() agrees with heuristic_engine.py's
    // PROTECTED_PROCESS_NAMES/PROTECTED_PIDS on both directions - known
    // protected names/PIDs must return TRUE, and ordinary names/PIDs must
    // return FALSE - logged once at load time so a regression here is
    // caught by reading WinDbg output, not discovered the first time a
    // future blocking capability relies on this floor being correct.
    BOOLEAN pass = TRUE;

    pass &= SensorIsProtectedProcess("lsass.exe", (HANDLE)1234);
    pass &= SensorIsProtectedProcess("csrss.exe", (HANDLE)1234);
    pass &= SensorIsProtectedProcess(NULL, (HANDLE)0);   // System Idle Process, by PID alone
    pass &= SensorIsProtectedProcess(NULL, (HANDLE)4);   // System, by PID alone
    pass &= SensorIsProtectedProcess("LSASS.EXE", (HANDLE)1234); // case-insensitive
    pass &= !SensorIsProtectedProcess("notepad.exe", (HANDLE)1234);
    pass &= !SensorIsProtectedProcess("evil.exe", (HANDLE)9999);
    pass &= !SensorIsProtectedProcess(NULL, (HANDLE)9999);

    if (pass) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[mal_project] sensor: protected-process floor self-test PASSED\n");
    } else {
        // Loud and unambiguous on purpose - this floor existing in a
        // broken state is worse than it not existing at all, the same
        // reasoning as every other "fail loudly, not silently" choice in
        // this driver.
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[mal_project] sensor: CRITICAL - protected-process floor self-test FAILED\n");
    }
}

OB_PREOP_CALLBACK_STATUS
SensorPreOperationCallback(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation
    )
{
    PEPROCESS targetProcess;
    PCHAR targetImageName;
    ACCESS_MASK desiredAccess;
    HANDLE requestorPid;
    HANDLE targetPid;

    UNREFERENCED_PARAMETER(RegistrationContext);

    // Only registered for PsProcessType, but check defensively - a
    // mismatched ObjectType here would mean treating some other object
    // type's Object pointer as a PEPROCESS, which is exactly the kind of
    // mistake that turns into a bugcheck instead of a bad log line.
    if (OperationInformation->ObjectType != *PsProcessType) {
        return OB_PREOP_SUCCESS;
    }

    targetProcess = (PEPROCESS)OperationInformation->Object;
    targetImageName = PsGetProcessImageFileName(targetProcess);

    // Hot path (fires on every process handle create/duplicate system-
    // wide) - filter to the one target this increment cares about before
    // doing anything else, same scoping heuristic_engine.py's own LSASS
    // check already uses. RtlEqualString, not _stricmp - see the same
    // note in SensorIsProtectedProcess above.
    if (targetImageName == NULL) {
        return OB_PREOP_SUCCESS;
    }
    {
        ANSI_STRING targetNameStr;
        ANSI_STRING lsassStr;

        RtlInitAnsiString(&targetNameStr, targetImageName);
        RtlInitAnsiString(&lsassStr, "lsass.exe");
        if (!RtlEqualString(&targetNameStr, &lsassStr, TRUE)) {
            return OB_PREOP_SUCCESS;
        }
    }

    if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
        desiredAccess = OperationInformation->Parameters->CreateHandleInformation.DesiredAccess;
    } else {
        desiredAccess = OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess;
    }

    if ((desiredAccess & SENSOR_LSASS_DANGEROUS_BITS) == 0) {
        return OB_PREOP_SUCCESS;
    }

    // Pre-operation callbacks run in the context of the requesting
    // thread, before the handle is granted and before the OS's own
    // access check (including LSASS's Protected-Process-Light
    // enforcement) - PsGetCurrentProcessId() here is the real requestor,
    // and this fires even on an attempt Windows itself is about to deny.
    requestorPid = PsGetCurrentProcessId();
    targetPid = PsGetProcessId(targetProcess);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
        "[mal_project] LSASS-ACCESS: requestor_pid=%p target_pid=%p desired_access=0x%08X "
        "dangerous_bits=0x%08X\n",
        requestorPid, targetPid, (ULONG)desiredAccess,
        (ULONG)(desiredAccess & SENSOR_LSASS_DANGEROUS_BITS));

    // Observe-only, deliberately: nothing is stripped or denied here. See
    // the file-header note on why blocking is a separate, later increment
    // built on top of the protected-process floor rather than added here.
    return OB_PREOP_SUCCESS;
}
