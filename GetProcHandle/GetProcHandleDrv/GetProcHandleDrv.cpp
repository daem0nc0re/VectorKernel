#include <ntddk.h>

#define DRIVER_PREFIX "GetProcHandleDrv: "
#define DEVICE_PATH L"\\Device\\GetProcHandle"
#define SYMLINK_PATH L"\\??\\GetProcHandle"

//
// Ioctl code definition
//
#define IOCTL_GET_PROC_HANDLE CTL_CODE(0x8000, 0x0100, METHOD_BUFFERED, FILE_ANY_ACCESS)

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
		UNICODE_STRING devicePath = RTL_CONSTANT_STRING(DEVICE_PATH);
		UNICODE_STRING symlinkPath = RTL_CONSTANT_STRING(SYMLINK_PATH);

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

	switch (dic.IoControlCode)
	{
	case IOCTL_GET_PROC_HANDLE:
		if (dic.InputBufferLength < sizeof(ULONG))
		{
			ntstatus = STATUS_BUFFER_TOO_SMALL;
			KdPrint((DRIVER_PREFIX "Input buffer is too small.\n"));
			break;
		}

		if (dic.OutputBufferLength < sizeof(HANDLE))
		{
			ntstatus = STATUS_BUFFER_TOO_SMALL;
			KdPrint((DRIVER_PREFIX "Output buffer is too small.\n"));
			break;
		}

		HANDLE hProcess = nullptr;
		auto pid = *(ULONG*)Irp->AssociatedIrp.SystemBuffer;
		OBJECT_ATTRIBUTES objectAttributes{ 0 };
		CLIENT_ID clientId{ 0 };
		clientId.UniqueProcess = ULongToHandle(pid);

		ntstatus = ::ZwOpenProcess(
			&hProcess,
			PROCESS_ALL_ACCESS,
			&objectAttributes,
			&clientId);

		if (!NT_SUCCESS(ntstatus))
		{
			*(HANDLE*)Irp->AssociatedIrp.SystemBuffer = nullptr;
			KdPrint((DRIVER_PREFIX "Failed to ZwOpenProcess() (NTSTATUS = 0x%08X).\n", ntstatus));
			break;
		}

		*(HANDLE*)Irp->AssociatedIrp.SystemBuffer = hProcess;
		info = sizeof(HANDLE);
		KdPrint((DRIVER_PREFIX "ZwOpenProcess() is successful.\n"));
	}

	Irp->IoStatus.Status = ntstatus;
	Irp->IoStatus.Information = info;
	IoCompleteRequest(Irp, 0);

	return ntstatus;
}