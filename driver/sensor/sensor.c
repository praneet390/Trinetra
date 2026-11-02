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

// Exported by ntoskrnl but declared in ntifs.h; including ntifs.h with
// ntddk.h causes redefinition conflicts. Declared directly (standard pattern).
NTKERNELAPI
PCHAR
PsGetProcessImageFileName(
    _In_ PEPROCESS Process
    );

// ---------------------------------------------------------------------------
// Comms channel: device + IOCTL_MALPROJECT_GET_EVENT polled by the Python
// agent. THREAD-CREATE/EXIT and user-mode IMAGE-LOAD stay DbgPrintEx-only -
// thousands/sec under ordinary activity (confirmed Phase 2), too noisy.
// ---------------------------------------------------------------------------

#define SENSOR_DEVICE_NAME       L"\\Device\\malprojectsensor"
#define SENSOR_SYMLINK_NAME      L"\\DosDevices\\malprojectsensor"

// 0x8000+ is the vendor-defined IOCTL function-code range per the WDK.
#define IOCTL_MALPROJECT_GET_EVENT \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Self-protection IOCTLs: protected PID is always PsGetCurrentProcessId(),
// never caller-supplied - a malicious caller can't protect a different
// process by sending its own PID in the input buffer.
#define IOCTL_MALPROJECT_REGISTER_SELF \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MALPROJECT_UNREGISTER_SELF \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef enum _SENSOR_EVENT_TYPE {
    SensorEventProcessCreate = 1,  // also carries the PPID-spoof flag
    SensorEventLsassAccess   = 2,
    SensorEventDriverLoad    = 3,
} SENSOR_EVENT_TYPE;

#define SENSOR_EVENT_IMAGE_NAME_MAX_CHARS 260  // MAX_PATH; long NT paths are
                                                // truncated - disclosed, not
                                                // silently lossy (see
                                                // ImageNameTruncated below).

// Fixed-size, flat (no unions) so the layout is simple and stable to mirror
// with a Python ctypes.Structure - plain generic fields, meaning documented
// per EventType below rather than a C union, which would be one more thing
// for the two languages' struct layouts to silently disagree about.
typedef struct _SENSOR_EVENT {
    ULONG64 SequenceNumber;    // monotonically increasing from driver load;
                                // the user-mode side detects drops the same
                                // way sensor_health.record_drop() already
                                // does for Sysmon/ETW - a gap in this
                                // sequence means events were dropped, not
                                // "nothing happened".
    ULONG   EventType;         // SENSOR_EVENT_TYPE
    ULONG   PpidSpoofDetected; // ProcessCreate only: claimed_parent !=
                                // real_creator (0/1, not BOOLEAN - fixed
                                // width across the kernel/user boundary)
    ULONG64 Pid;                // ProcessCreate: new pid. LsassAccess:
                                // target pid. DriverLoad: pid the image
                                // mapped into (often PID 4/System).
    ULONG64 ClaimedParentOrRequestorPid;  // ProcessCreate: claimed parent.
                                           // LsassAccess: requestor pid.
                                           // DriverLoad: unused (0).
    ULONG64 RealCreatorPid;    // ProcessCreate only: the real creator from
                                // CreatingThreadId.UniqueProcess. Unused
                                // (0) for the other event types.
    ULONG64 DesiredAccessOrImageBase;  // LsassAccess: raw DesiredAccess.
                                        // DriverLoad: ImageBase. Unused (0)
                                        // for ProcessCreate.
    ULONG   ImageNameTruncated;  // 0/1 - the real name was longer than
                                  // SENSOR_EVENT_IMAGE_NAME_MAX_CHARS-1 and
                                  // got cut off; explicit, not silent.
    ULONG   Reserved;             // padding/future use, always 0 for now.
    WCHAR   ImageName[SENSOR_EVENT_IMAGE_NAME_MAX_CHARS];  // NUL-terminated.
} SENSOR_EVENT, *PSENSOR_EVENT;

// Bounded circular queue, spinlock-protected. A spinlock, not a FAST_MUTEX
// or regular mutex, is the one safe choice here: PsSetCreateProcessNotify
// RoutineEx/PsSetLoadImageNotifyRoutine run at PASSIVE_LEVEL, but
// ObRegisterCallbacks' pre-operation callback is documented to run at
// IRQL <= DISPATCH_LEVEL - a lock that can only be safely acquired at
// PASSIVE_LEVEL would be a guaranteed bugcheck the first time the Ob
// callback (which also enqueues, for LSASS-ACCESS) fires from a raised-
// IRQL caller. KeAcquireSpinLock is correct regardless of the calling
// IRQL, which is exactly why every producer here uses the same one lock.
#define SENSOR_QUEUE_CAPACITY 256

static KSPIN_LOCK g_QueueLock;
static SENSOR_EVENT g_Queue[SENSOR_QUEUE_CAPACITY];
static ULONG g_QueueHead = 0;   // next slot to dequeue
static ULONG g_QueueCount = 0;  // entries currently queued
static volatile LONG64 g_NextSequenceNumber = 1;
static volatile LONG64 g_DroppedEventCount = 0;

static PDEVICE_OBJECT g_DeviceObject = NULL;
static BOOLEAN g_DeviceCreated = FALSE;
static BOOLEAN g_SymlinkCreated = FALSE;

// ---------------------------------------------------------------------------
// A separate spinlock from g_QueueLock: the two protect independent state
// and are never held together; sharing them would extend critical sections.
//
// WHAT THIS DOES NOT DO: cannot protect the driver against `sc stop` by an
// admin - that needs Microsoft ELAM attestation (out of reach for a test-
// signed driver). Process protection exists only while the driver runs.
// ---------------------------------------------------------------------------
#define SENSOR_MAX_PROTECTED_SELF_PIDS 8
#define SENSOR_PROCESS_TERMINATE       0x0001
#define SENSOR_PROCESS_SUSPEND_RESUME  0x0800
// Reuses SENSOR_PROCESS_CREATE_THREAD/VM_OPERATION/VM_WRITE already defined
// above for LSASS_DANGEROUS_BITS - the same rights that let an external
// process inject code/a thread into a target are exactly what would let
// an attacker neutralize the agent without a literal TerminateProcess call
// (e.g. injecting a thread that calls ExitProcess from inside).
#define SENSOR_SELF_PROTECT_STRIP_BITS \
    (SENSOR_PROCESS_TERMINATE | SENSOR_PROCESS_SUSPEND_RESUME | \
     SENSOR_PROCESS_CREATE_THREAD | SENSOR_PROCESS_VM_OPERATION | SENSOR_PROCESS_VM_WRITE)

static KSPIN_LOCK g_ProtectedSelfLock;
static ULONG64 g_ProtectedSelfPids[SENSOR_MAX_PROTECTED_SELF_PIDS];
static ULONG g_ProtectedSelfCount = 0;

VOID
SensorRegisterSelfProtected(
    _In_ HANDLE Pid
    );

VOID
SensorUnregisterSelfProtected(
    _In_ HANDLE Pid
    );

BOOLEAN
SensorIsSelfProtected(
    _In_ HANDLE Pid
    );

VOID
SensorEnqueueEvent(
    _In_ PSENSOR_EVENT Event
    );

NTSTATUS
SensorDispatchCreateClose(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
    );

NTSTATUS
SensorDispatchDeviceControl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
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

// Arbitrary altitude - fine for dev/test VMs with no other AV/EDR; production
// needs a properly assigned one (collisions → STATUS_FLT_INSTANCE_ALTITUDE_COLLISION).
#define SENSOR_OB_ALTITUDE L"389456"

VOID
SensorUnload(
    _In_ PDRIVER_OBJECT DriverObject
    )
{
    NTSTATUS status;
    BOOLEAN allClean = TRUE;

    UNREFERENCED_PARAMETER(DriverObject);

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
        // ObUnRegisterCallbacks returns VOID - no status to check.
        ObUnRegisterCallbacks(g_ObRegistrationHandle);
    }

    if (g_SymlinkCreated) {
        UNICODE_STRING symlinkName;
        RtlInitUnicodeString(&symlinkName, SENSOR_SYMLINK_NAME);
        IoDeleteSymbolicLink(&symlinkName);
    }
    if (g_DeviceCreated && g_DeviceObject != NULL) {
        IoDeleteDevice(g_DeviceObject);
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
    UNICODE_STRING deviceName;
    UNICODE_STRING symlinkName;
    BOOLEAN commsChannelReady = FALSE;

    UNREFERENCED_PARAMETER(RegistryPath);

    KeInitializeSpinLock(&g_QueueLock);
    KeInitializeSpinLock(&g_ProtectedSelfLock);

    // Done before any notify routine so SensorEnqueueEvent can safely check
    // g_DeviceCreated without a race on its initialization.
    RtlInitUnicodeString(&deviceName, SENSOR_DEVICE_NAME);
    status = IoCreateDevice(DriverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN,
                             FILE_DEVICE_SECURE_OPEN, FALSE, &g_DeviceObject);
    if (NT_SUCCESS(status)) {
        g_DeviceCreated = TRUE;
        RtlInitUnicodeString(&symlinkName, SENSOR_SYMLINK_NAME);
        status = IoCreateSymbolicLink(&symlinkName, &deviceName);
        if (NT_SUCCESS(status)) {
            g_SymlinkCreated = TRUE;
            DriverObject->MajorFunction[IRP_MJ_CREATE] = SensorDispatchCreateClose;
            DriverObject->MajorFunction[IRP_MJ_CLOSE] = SensorDispatchCreateClose;
            DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = SensorDispatchDeviceControl;
            commsChannelReady = TRUE;
        } else {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                "[mal_project] sensor: IoCreateSymbolicLink failed, status=0x%08X - "
                "continuing without the user-mode comms channel\n", status);
        }
    } else {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[mal_project] sensor: IoCreateDevice failed, status=0x%08X - "
            "continuing without the user-mode comms channel\n", status);
    }

    // Core capability - required. Fail the load rather than come up silently
    // in a partial state with no process-create visibility.
    status = PsSetCreateProcessNotifyRoutineEx(SensorProcessNotify, FALSE);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[mal_project] sensor: PsSetCreateProcessNotifyRoutineEx failed, status=0x%08X\n", status);
        if (g_SymlinkCreated) {
            UNICODE_STRING cleanupSymlinkName;
            RtlInitUnicodeString(&cleanupSymlinkName, SENSOR_SYMLINK_NAME);
            IoDeleteSymbolicLink(&cleanupSymlinkName);
        }
        if (g_DeviceCreated && g_DeviceObject != NULL) {
            IoDeleteDevice(g_DeviceObject);
        }
        return status;
    }

    // Best-effort additions: an altitude/resource conflict on one sensor
    // must not take the core process-create capability down with it.
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

    // Prove the floor before any future blocking capability relies on it.
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
            // STATUS_FLT_INSTANCE_ALTITUDE_COLLISION if another AV/EDR
            // is installed - log and continue rather than fail the load.
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                "[mal_project] sensor: ObRegisterCallbacks failed, status=0x%08X - "
                "continuing without LSASS handle-access visibility\n", bestEffortStatus);
        }
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
        "[mal_project] sensor: DriverEntry reached, process-create callback registered "
        "(thread-notify=%d, image-load=%d, ob-handle-access=%d, comms-channel=%d), built %s %s\n",
        g_ThreadNotifyRegistered, g_ImageLoadNotifyRegistered, g_ObCallbacksRegistered,
        commsChannelReady, __DATE__, __TIME__);

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
        // Process exit: free the slot so a reused PID can't silently
        // inherit protection. Also the crash path - no clean shutdown runs.
        SensorUnregisterSelfProtected(ProcessId);
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

    {
        SENSOR_EVENT event;
        RtlZeroMemory(&event, sizeof(event));
        event.EventType = SensorEventProcessCreate;
        event.PpidSpoofDetected = (CreateInfo->ParentProcessId != realCreatorPid) ? 1 : 0;
        event.Pid = (ULONG64)(ULONG_PTR)ProcessId;
        event.ClaimedParentOrRequestorPid = (ULONG64)(ULONG_PTR)CreateInfo->ParentProcessId;
        event.RealCreatorPid = (ULONG64)(ULONG_PTR)realCreatorPid;
        if (imageName != NULL && imageName->Buffer != NULL && imageName->Length > 0) {
            USHORT copyChars = imageName->Length / sizeof(WCHAR);
            if (copyChars > SENSOR_EVENT_IMAGE_NAME_MAX_CHARS - 1) {
                copyChars = SENSOR_EVENT_IMAGE_NAME_MAX_CHARS - 1;
                event.ImageNameTruncated = 1;
            }
            RtlCopyMemory(event.ImageName, imageName->Buffer, copyChars * sizeof(WCHAR));
            event.ImageName[copyChars] = L'\0';
        }
        SensorEnqueueEvent(&event);
    }
}

VOID
SensorThreadNotify(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId,
    _In_ BOOLEAN Create
    )
{
    // See file header HONESTY NOTE: proves a thread appeared, not who
    // created it. Tag named to avoid implying an injection verdict.
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
        if (FullImageName != NULL) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                "[mal_project] DRIVER-LOAD: pid=%p base=%p image=%wZ\n",
                ProcessId, imageBase, FullImageName);
        } else {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                "[mal_project] DRIVER-LOAD: pid=%p base=%p image=(none)\n",
                ProcessId, imageBase);
        }

        {
            SENSOR_EVENT event;
            RtlZeroMemory(&event, sizeof(event));
            event.EventType = SensorEventDriverLoad;
            event.Pid = (ULONG64)(ULONG_PTR)ProcessId;
            event.DesiredAccessOrImageBase = (ULONG64)(ULONG_PTR)imageBase;
            if (FullImageName != NULL && FullImageName->Buffer != NULL && FullImageName->Length > 0) {
                USHORT copyChars = FullImageName->Length / sizeof(WCHAR);
                if (copyChars > SENSOR_EVENT_IMAGE_NAME_MAX_CHARS - 1) {
                    copyChars = SENSOR_EVENT_IMAGE_NAME_MAX_CHARS - 1;
                    event.ImageNameTruncated = 1;
                }
                RtlCopyMemory(event.ImageName, FullImageName->Buffer, copyChars * sizeof(WCHAR));
                event.ImageName[copyChars] = L'\0';
            }
            SensorEnqueueEvent(&event);
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
    // Logged at load time so a regression is caught in WinDbg before any
    // blocking capability relies on this floor.
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
    HANDLE requestorPid;
    HANDLE targetPid;
    BOOLEAN isCreate;

    UNREFERENCED_PARAMETER(RegistrationContext);

    // Only registered for PsProcessType, but check defensively - a
    // mismatched ObjectType here would mean treating some other object
    // type's Object pointer as a PEPROCESS, which is exactly the kind of
    // mistake that turns into a bugcheck instead of a bad log line.
    if (OperationInformation->ObjectType != *PsProcessType) {
        return OB_PREOP_SUCCESS;
    }

    targetProcess = (PEPROCESS)OperationInformation->Object;
    targetPid = PsGetProcessId(targetProcess);
    requestorPid = PsGetCurrentProcessId();
    isCreate = (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE);

    // ExitProcess/returning from main is not a handle-open - it bypasses
    // this callback. requestorPid == targetPid is never stripped (guard).
    //
    // VERIFIED (not assumed): a diagnostic build that logged every Ob
    // callback invocation unconditionally confirmed this path is correct -
    // a live taskkill /F against a registered PID, launched mid-window
    // (its own PROC-CREATE visible on the comms channel), left the target
    // running uninterrupted through the rest of its test window, which it
    // then exited from entirely on its own (self-termination, not an
    // external kill). The two earlier rounds that appeared to fail were a
    // TEST-harness timing race - a fixed 2-second sleep between launching
    // the harness and attempting the kill sometimes ran before
    // registration had completed (first-launch disk/AV-scan overhead on a
    // freshly rebuilt binary), not a flaw in this stripping logic.
    if (requestorPid != targetPid && SensorIsSelfProtected(targetPid)) {
        PACCESS_MASK desiredAccessPtr = isCreate
            ? &OperationInformation->Parameters->CreateHandleInformation.DesiredAccess
            : &OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess;
        ACCESS_MASK before = *desiredAccessPtr;
        ACCESS_MASK stripped = before & SENSOR_SELF_PROTECT_STRIP_BITS;

        if (stripped != 0) {
            *desiredAccessPtr = before & ~SENSOR_SELF_PROTECT_STRIP_BITS;
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                "[mal_project] SELF-PROTECT: requestor_pid=%p target_pid=%p "
                "stripped=0x%08X (was 0x%08X, now 0x%08X)\n",
                requestorPid, targetPid, (ULONG)stripped, (ULONG)before,
                (ULONG)*desiredAccessPtr);
        }
    }

    targetImageName = PsGetProcessImageFileName(targetProcess);
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

    {
        ACCESS_MASK desiredAccess = isCreate
            ? OperationInformation->Parameters->CreateHandleInformation.DesiredAccess
            : OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess;

        if ((desiredAccess & SENSOR_LSASS_DANGEROUS_BITS) == 0) {
            return OB_PREOP_SUCCESS;
        }

        // Pre-operation callbacks run in the context of the requesting
        // thread, before the handle is granted. NOTE: for LSASS
        // specifically this callback is only reached when the requestor's
        // protection level is comparable to or higher than LSASS's own
        // PPL level - see the HONESTY NOTE in the file header for the
        // empirically-confirmed detail on what this does and does not
        // observe.
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[mal_project] LSASS-ACCESS: requestor_pid=%p target_pid=%p desired_access=0x%08X "
            "dangerous_bits=0x%08X\n",
            requestorPid, targetPid, (ULONG)desiredAccess,
            (ULONG)(desiredAccess & SENSOR_LSASS_DANGEROUS_BITS));

        {
            SENSOR_EVENT event;
            RtlZeroMemory(&event, sizeof(event));
            event.EventType = SensorEventLsassAccess;
            event.Pid = (ULONG64)(ULONG_PTR)targetPid;
            event.ClaimedParentOrRequestorPid = (ULONG64)(ULONG_PTR)requestorPid;
            event.DesiredAccessOrImageBase = (ULONG64)desiredAccess;
            SensorEnqueueEvent(&event);
        }
    }

    return OB_PREOP_SUCCESS;
}

VOID
SensorRegisterSelfProtected(
    _In_ HANDLE Pid
    )
{
    KIRQL oldIrql;
    ULONG i;
    BOOLEAN alreadyPresent = FALSE;

    KeAcquireSpinLock(&g_ProtectedSelfLock, &oldIrql);

    for (i = 0; i < g_ProtectedSelfCount; i++) {
        if (g_ProtectedSelfPids[i] == (ULONG64)(ULONG_PTR)Pid) {
            alreadyPresent = TRUE;
            break;
        }
    }

    if (!alreadyPresent && g_ProtectedSelfCount < SENSOR_MAX_PROTECTED_SELF_PIDS) {
        g_ProtectedSelfPids[g_ProtectedSelfCount] = (ULONG64)(ULONG_PTR)Pid;
        g_ProtectedSelfCount++;
    }

    KeReleaseSpinLock(&g_ProtectedSelfLock, oldIrql);

    if (alreadyPresent) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[mal_project] sensor: SELF-PROTECT register pid=%p (already registered)\n", Pid);
    } else {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[mal_project] sensor: SELF-PROTECT register pid=%p\n", Pid);
    }
}

VOID
SensorUnregisterSelfProtected(
    _In_ HANDLE Pid
    )
{
    KIRQL oldIrql;
    ULONG i;
    BOOLEAN removed = FALSE;

    KeAcquireSpinLock(&g_ProtectedSelfLock, &oldIrql);

    for (i = 0; i < g_ProtectedSelfCount; i++) {
        if (g_ProtectedSelfPids[i] == (ULONG64)(ULONG_PTR)Pid) {
            // Swap the last entry into this slot and shrink - order
            // doesn't matter for an unordered protected-PID set, and this
            // avoids shifting the rest of a tiny fixed array.
            g_ProtectedSelfPids[i] = g_ProtectedSelfPids[g_ProtectedSelfCount - 1];
            g_ProtectedSelfCount--;
            removed = TRUE;
            break;
        }
    }

    KeReleaseSpinLock(&g_ProtectedSelfLock, oldIrql);

    if (removed) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[mal_project] sensor: SELF-PROTECT unregister pid=%p\n", Pid);
    }
    // Not logging the not-found case: SensorProcessNotify calls this
    // unconditionally on EVERY process exit (not just protected ones) to
    // guarantee PID-reuse cleanup, so "not found" is the overwhelmingly
    // common, totally unremarkable case - logging it would just be noise.
}

BOOLEAN
SensorIsSelfProtected(
    _In_ HANDLE Pid
    )
{
    KIRQL oldIrql;
    ULONG i;
    BOOLEAN found = FALSE;
    ULONG64 pidValue = (ULONG64)(ULONG_PTR)Pid;

    KeAcquireSpinLock(&g_ProtectedSelfLock, &oldIrql);
    for (i = 0; i < g_ProtectedSelfCount; i++) {
        if (g_ProtectedSelfPids[i] == pidValue) {
            found = TRUE;
            break;
        }
    }
    KeReleaseSpinLock(&g_ProtectedSelfLock, oldIrql);

    return found;
}

VOID
SensorEnqueueEvent(
    _In_ PSENSOR_EVENT Event
    )
{
    KIRQL oldIrql;
    ULONG tailIndex;

    // g_DeviceCreated set once in DriverEntry before any notify routine
    // is registered - no race; skip if no consumer can reach the queue.
    if (!g_DeviceCreated) {
        return;
    }

    // Spinlock required - ObRegisterCallbacks pre-op can run at raised IRQL.
    KeAcquireSpinLock(&g_QueueLock, &oldIrql);

    Event->SequenceNumber = (ULONG64)g_NextSequenceNumber;
    g_NextSequenceNumber++;

    if (g_QueueCount == SENSOR_QUEUE_CAPACITY) {
        // Drop oldest (notify routines can't block). Gap in SequenceNumber
        // surfaces the drop to user mode, same as Sysmon/ETW queue overflow.
        g_QueueHead = (g_QueueHead + 1) % SENSOR_QUEUE_CAPACITY;
        g_QueueCount--;
        g_DroppedEventCount++;
    }

    tailIndex = (g_QueueHead + g_QueueCount) % SENSOR_QUEUE_CAPACITY;
    RtlCopyMemory(&g_Queue[tailIndex], Event, sizeof(SENSOR_EVENT));
    g_QueueCount++;

    KeReleaseSpinLock(&g_QueueLock, oldIrql);
}

NTSTATUS
SensorDispatchCreateClose(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
    )
{
    UNREFERENCED_PARAMETER(DeviceObject);

    // Access restriction is enforced by the device's security descriptor
    // (FILE_DEVICE_SECURE_OPEN), not in this handler.
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS
SensorDispatchDeviceControl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
    )
{
    PIO_STACK_LOCATION stack;
    NTSTATUS status;
    ULONG_PTR information;
    KIRQL oldIrql;

    UNREFERENCED_PARAMETER(DeviceObject);

    stack = IoGetCurrentIrpStackLocation(Irp);
    information = 0;

    if (stack->Parameters.DeviceIoControl.IoControlCode == IOCTL_MALPROJECT_GET_EVENT) {
        if (stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(SENSOR_EVENT)) {
            status = STATUS_BUFFER_TOO_SMALL;
        } else {
            BOOLEAN haveEvent = FALSE;
            SENSOR_EVENT localEvent;
            RtlZeroMemory(&localEvent, sizeof(localEvent));

            KeAcquireSpinLock(&g_QueueLock, &oldIrql);
            if (g_QueueCount > 0) {
                RtlCopyMemory(&localEvent, &g_Queue[g_QueueHead], sizeof(SENSOR_EVENT));
                g_QueueHead = (g_QueueHead + 1) % SENSOR_QUEUE_CAPACITY;
                g_QueueCount--;
                haveEvent = TRUE;
            }
            KeReleaseSpinLock(&g_QueueLock, oldIrql);

            if (haveEvent) {
                RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, &localEvent, sizeof(SENSOR_EVENT));
                information = sizeof(SENSOR_EVENT);
            }
            // Queue empty: STATUS_SUCCESS with 0 bytes - polling model;
            // "nothing right now" is the normal result the caller retries.
            status = STATUS_SUCCESS;
        }
    } else if (stack->Parameters.DeviceIoControl.IoControlCode == IOCTL_MALPROJECT_REGISTER_SELF) {
        // PsGetCurrentProcessId(), not from the input buffer - see the IOCTL
        // definition: caller-supplied PIDs are a spoofing vector.
        SensorRegisterSelfProtected(PsGetCurrentProcessId());
        status = STATUS_SUCCESS;
    } else if (stack->Parameters.DeviceIoControl.IoControlCode == IOCTL_MALPROJECT_UNREGISTER_SELF) {
        SensorUnregisterSelfProtected(PsGetCurrentProcessId());
        status = STATUS_SUCCESS;
    } else {
        status = STATUS_INVALID_DEVICE_REQUEST;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = information;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}
