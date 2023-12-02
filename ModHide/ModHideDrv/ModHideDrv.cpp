#include <ntddk.h>

#define DRIVER_PREFIX "ModHideDrv: "
#define DEVICE_PATH L"\\Device\\ModHide"
#define SYMLINK_PATH L"\\??\\ModHide"

// Offset of _DRIVER_OBJECT
#define DRIVER_SECTION_OFFSET 0x28
// Offset of _MODULE_ENTRY
#define FULL_PATH_NAME_OFFSET 0x48
#define FILE_NAME_OFFSET 0x58

//
// Ioctl code definition
//
#define IOCTL_HIDE_MODULE_BY_NAME CTL_CODE(0x8000, 0x0800, METHOD_BUFFERED, FILE_ANY_ACCESS)

//
// Custom struct definition
//
typedef struct _MODULE_NAME_INFO
{
	WCHAR ImageFileName[256];
} MODULE_NAME_INFO, *PMODULE_NAME_INFO;

// 
// Global variables
//
PVOID g_ModuleEntry = nullptr;

//
// Prototypes
//
void DriverUnload(_In_ PDRIVER_OBJECT DriverObject);
NTSTATUS OnCreateClose(
	_Inout_ PDEVICE_OBJECT DeviceObject,
	_Inout_ PIRP Irp
);
NTSTATUS OnDeviceControl(
	_Inout_ PDEVICE_OBJECT DeviceObject,
	_Inout_ PIRP Irp
);
void UnlinkListEntry(PLIST_ENTRY pListEntry);

//
// Driver routines
//
extern "C"
NTSTATUS DriverEntry(
	_In_ PDRIVER_OBJECT  DriverObject,
	_In_ PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(RegistryPath);

	NTSTATUS ntstatus = STATUS_FAILED_DRIVER_ENTRY;
	PDEVICE_OBJECT pDeviceObject = nullptr;

	do
	{
		RTL_OSVERSIONINFOW versionInfo{ 0 };
		UNICODE_STRING devicePath = RTL_CONSTANT_STRING(DEVICE_PATH);
		UNICODE_STRING symlinkPath = RTL_CONSTANT_STRING(SYMLINK_PATH);
		g_ModuleEntry = *(PVOID*)((ULONG_PTR)DriverObject + DRIVER_SECTION_OFFSET);

		ntstatus = ::IoCreateDevice(
			DriverObject,
			NULL,
			&devicePath,
			FILE_DEVICE_UNKNOWN,
			NULL,
			FALSE,
			&pDeviceObject);

		if (!NT_SUCCESS(ntstatus))
		{
			pDeviceObject = nullptr;
			KdPrint((DRIVER_PREFIX "Failed to create device (NTSTATUS = 0x%08X).\n", ntstatus));
			break;
		}

		ntstatus = ::IoCreateSymbolicLink(&symlinkPath, &devicePath);

		if (!NT_SUCCESS(ntstatus))
		{
			KdPrint((DRIVER_PREFIX "Failed to create symbolic link (NTSTATUS = 0x%08X).\n", ntstatus));
			break;
		}

		DriverObject->DriverUnload = DriverUnload;
		DriverObject->MajorFunction[IRP_MJ_CREATE] = OnCreateClose;
		DriverObject->MajorFunction[IRP_MJ_CLOSE] = OnCreateClose;
		DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = OnDeviceControl;

		KdPrint((DRIVER_PREFIX "Driver is loaded successfully.\n"));
	} while (false);

	if (!NT_SUCCESS(ntstatus) && (pDeviceObject != nullptr))
		::IoDeleteDevice(pDeviceObject);

	return ntstatus;
}


void DriverUnload(_In_ PDRIVER_OBJECT DriverObject)
{
	UNICODE_STRING symlinkPath = RTL_CONSTANT_STRING(SYMLINK_PATH);
	::IoDeleteSymbolicLink(&symlinkPath);
	::IoDeleteDevice(DriverObject->DeviceObject);

	KdPrint((DRIVER_PREFIX "Driver is unloaded.\n"));
}


NTSTATUS OnCreateClose(
	_Inout_ PDEVICE_OBJECT DeviceObject,
	_Inout_ PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	NTSTATUS ntstatus = STATUS_SUCCESS;
	Irp->IoStatus.Status = ntstatus;
	Irp->IoStatus.Information = 0u;
	IoCompleteRequest(Irp, 0);

	return ntstatus;
}


NTSTATUS OnDeviceControl(
	_Inout_ PDEVICE_OBJECT DeviceObject,
	_Inout_ PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	NTSTATUS ntstatus = STATUS_INVALID_DEVICE_REQUEST;
	ULONG_PTR info = NULL;
	PIO_STACK_LOCATION irpSp = ::IoGetCurrentIrpStackLocation(Irp);
	auto& dic = irpSp->Parameters.DeviceIoControl;
	WCHAR imageFileName[257]{ 0 }; // ensure null-terminator at the end
	UNICODE_STRING targetModuleName{ 0 };
	PLIST_ENTRY pStartEntry = nullptr;
	PLIST_ENTRY pCurrentEntry = nullptr;
	PUNICODE_STRING pCurrentModuleName = nullptr;
	KIRQL irql = NULL;

	switch (dic.IoControlCode)
	{
	case IOCTL_HIDE_MODULE_BY_NAME:
		if (dic.InputBufferLength < sizeof(MODULE_NAME_INFO))
		{
			ntstatus = STATUS_BUFFER_TOO_SMALL;
			KdPrint((DRIVER_PREFIX "Input buffer is too small.\n"));
			break;
		}

		::memcpy(&imageFileName, Irp->AssociatedIrp.SystemBuffer, sizeof(WCHAR) * 256);
		::RtlInitUnicodeString(&targetModuleName, imageFileName);
		KdPrint((DRIVER_PREFIX "Target module name: %wZ\n", &targetModuleName));

		pStartEntry = (PLIST_ENTRY)g_ModuleEntry;
		pCurrentEntry = pStartEntry;
		KdPrint((DRIVER_PREFIX "_MODULE_ENTRY struct is at 0x%p.\n", g_ModuleEntry));

		// To suppress race condition, raise IRQL to DISPATCH_LEVEL temporary.
		irql = ::KeRaiseIrqlToDpcLevel();
		KdPrint((DRIVER_PREFIX "IRQL is raised to DISPATCH_LEVEL (Original IRQL = %u).\n", (ULONG)irql));
		KdPrint((DRIVER_PREFIX "Current IRQL = %u.\n", (ULONG)::KeGetCurrentIrql()));

		do
		{
			pCurrentModuleName = (PUNICODE_STRING)((ULONG_PTR)pCurrentEntry + FILE_NAME_OFFSET);

			if (::RtlCompareUnicodeString(pCurrentModuleName, &targetModuleName, TRUE))
			{
				ntstatus = STATUS_SUCCESS;
				info = pCurrentModuleName->Length;
				UnlinkListEntry(pCurrentEntry);

				KdPrint((DRIVER_PREFIX "Found _MODULE_ENTRY for the target module at 0x%p.\n", pCurrentEntry));

				break;
			}

			pCurrentEntry = pCurrentEntry->Flink;
		} while (pCurrentEntry != pStartEntry);

		// Revert IRQL
		::KeLowerIrql(irql);

		KdPrint((DRIVER_PREFIX "IRQL is reverted.\n"));

		if (NT_SUCCESS(ntstatus))
			KdPrint((DRIVER_PREFIX "%wZ module is unlinked.\n", pCurrentModuleName));
		else
			KdPrint((DRIVER_PREFIX "Target module is not found.\n"));
	}

	Irp->IoStatus.Status = ntstatus;
	Irp->IoStatus.Information = info;
	IoCompleteRequest(Irp, 0);

	return ntstatus;
}

//
// Helper functions
//
void UnlinkListEntry(PLIST_ENTRY pListEntry)
{
	PLIST_ENTRY pForwardEntry = pListEntry->Flink;
	PLIST_ENTRY pBackwardEntry = pListEntry->Blink;
	pForwardEntry->Blink = pListEntry->Blink;
	pBackwardEntry->Flink = pListEntry->Flink;

	// To avoid referenced memory corruption when unlinked module is unloaded, 
	// unlinked LIST_ENTRY should reference itself.
	pListEntry->Flink = pListEntry;
	pListEntry->Blink = pListEntry;
}