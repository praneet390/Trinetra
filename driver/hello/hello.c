/*
 * Phase 1 "hello world" driver: proves the whole toolchain (build -> sign ->
 * deploy -> load -> observe in the live kernel debugger -> unload) with the
 * smallest possible amount of code. No device, no callbacks, no IOCTLs -
 * loaded as a bare legacy kernel-driver service (`sc create` / `sc start`,
 * no INF/PnP involved). Once this round-trips cleanly, Phase 2 replaces this
 * file with the real sensor driver (process/handle/registry callbacks) on
 * top of a toolchain already proven to work.
 *
 * DbgPrintEx at DPFLTR_ERROR_LEVEL is used deliberately instead of plain
 * DbgPrint: error-level messages always reach an attached kernel debugger
 * regardless of the Kd_*_Mask filter settings, so there is nothing extra to
 * configure in WinDbg to see this driver's output.
 */
#include <ntddk.h>

DRIVER_UNLOAD HelloUnload;
DRIVER_INITIALIZE DriverEntry;

VOID
HelloUnload(
    _In_ PDRIVER_OBJECT DriverObject
    )
{
    UNREFERENCED_PARAMETER(DriverObject);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
        "[mal_project] hello: unloading cleanly\n");
}

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
{
    UNREFERENCED_PARAMETER(RegistryPath);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
        "[mal_project] hello: DriverEntry reached, built %s %s\n", __DATE__, __TIME__);

    DriverObject->DriverUnload = HelloUnload;

    return STATUS_SUCCESS;
}
