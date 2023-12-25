#include <ntddk.h>

#define DRIVER_PREFIX "Tester: "

void DriverUnload(_In_ PDRIVER_OBJECT DriverObject);

//
// Driver routines
//
extern "C"
NTSTATUS DriverEntry(
	_In_ PDRIVER_OBJECT  DriverObject,
	_In_ PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(RegistryPath);
	DriverObject->DriverUnload = DriverUnload;
	KdPrint((DRIVER_PREFIX "Driver is loaded successfully.\n"));

	return STATUS_SUCCESS;
}

void DriverUnload(_In_ PDRIVER_OBJECT DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);
	KdPrint((DRIVER_PREFIX "Driver is unloaded.\n"));
}