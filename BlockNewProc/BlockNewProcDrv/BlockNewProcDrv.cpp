#include <ntifs.h>

#define DRIVER_PREFIX "BlockNewProcDrv: "
#define DEVICE_PATH L"\\Device\\BlockNewProc"
#define SYMLINK_PATH L"\\??\\BlockNewProc"

#pragma warning(disable: 4996) // This warning is caused when use old ExAllocatePoolWithTag() API.

//
// Ioctl code definition
//
#define IOCTL_SET_PROCESS_FILENAME CTL_CODE(0x8000, 0x0900, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_UNREGISTER_CALLBACK CTL_CODE(0x8000, 0x0901, METHOD_BUFFERED, FILE_ANY_ACCESS)

//
// Custom sturct definition
//
typedef struct _BLOCK_FILENAME_INFO
{
	WCHAR ImageFileName[256];
} BLOCK_FILENAME_INFO, * PBLOCK_FILENAME_INFO;

//
// Global variables
//
WCHAR g_ImageFileNameSuffix[258]{ 0 }; // top byte for '\', last byte for null-terminator
BOOLEAN g_CallbackRegistered = FALSE;

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
void ProcessBlockRoutine(
	_Inout_ PEPROCESS Process,
	_In_ HANDLE ProcessId,
	_Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
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

#ifndef _WIN64
	KdPrint((DRIVER_PREFIX "32bit OS is not supported.\n"));
	return STATUS_NOT_SUPPORTED;
#endif

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

	if (g_CallbackRegistered)
	{
		::PsSetCreateProcessNotifyRoutineEx2(
			PsCreateProcessNotifySubsystems,
			(PVOID)ProcessBlockRoutine,
			TRUE);
	}

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
	PIO_STACK_LOCATION irpSp = ::IoGetCurrentIrpStackLocation(Irp);
	auto& dic = irpSp->Parameters.DeviceIoControl;
	ULONG_PTR info = NULL;

	switch (dic.IoControlCode)
	{
	case IOCTL_SET_PROCESS_FILENAME:
		if (dic.InputBufferLength < sizeof(BLOCK_FILENAME_INFO))
		{
			ntstatus = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		::memset(g_ImageFileNameSuffix, 0, sizeof(WCHAR) * 258);
		g_ImageFileNameSuffix[0] = L'\\';
		::memcpy(&g_ImageFileNameSuffix[1], Irp->AssociatedIrp.SystemBuffer, sizeof(BLOCK_FILENAME_INFO));
		g_ImageFileNameSuffix[257] = L'\0';

		KdPrint((DRIVER_PREFIX "Target ImageFileName pattern is updated to \"%ws\".\n", &g_ImageFileNameSuffix));

		if (!g_CallbackRegistered)
		{
			ntstatus = ::PsSetCreateProcessNotifyRoutineEx2(
				PsCreateProcessNotifySubsystems,
				(PVOID)ProcessBlockRoutine,
				FALSE);

			if (!NT_SUCCESS(ntstatus))
			{
				KdPrint((DRIVER_PREFIX "Failed to register Process Notify Routine (NTSTATUS = 0x%08X).", ntstatus));
				break;
			}
			else
			{
				g_CallbackRegistered = TRUE;
				KdPrint((DRIVER_PREFIX "Process Notify Callback is registered successfully.\n"));
			}
		}

		info = ::wcslen(g_ImageFileNameSuffix) * sizeof(WCHAR);
		ntstatus = STATUS_SUCCESS;

		break;

	case IOCTL_UNREGISTER_CALLBACK:
		if (g_CallbackRegistered)
		{
			::memset(g_ImageFileNameSuffix, 0, sizeof(WCHAR) * 258);
			ntstatus = ::PsSetCreateProcessNotifyRoutineEx2(
				PsCreateProcessNotifySubsystems,
				(PVOID)ProcessBlockRoutine,
				TRUE);

			if (!NT_SUCCESS(ntstatus))
			{
				KdPrint((DRIVER_PREFIX "Failed to unregister Process Notify Callback (NTSTATUS = 0x%08X).\n", ntstatus));
			}
			else
			{
				g_CallbackRegistered = FALSE;
				KdPrint((DRIVER_PREFIX "Process Notify Callback is unregistered successfully.\n"));
			}
		}
		else
		{
			KdPrint((DRIVER_PREFIX "Process Notify Callback is not registered.\n"));
		}
	}

	Irp->IoStatus.Status = ntstatus;
	Irp->IoStatus.Information = info;
	IoCompleteRequest(Irp, 0);

	return ntstatus;
}


//
// Process Notify Routines
//
void ProcessBlockRoutine(
	_Inout_ PEPROCESS Process,
	_In_ HANDLE ProcessId,
	_Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo)
{
	UNREFERENCED_PARAMETER(Process);
	UNREFERENCED_PARAMETER(ProcessId);

	if (CreateInfo != nullptr)
	{
		if (::wcslen(g_ImageFileNameSuffix) > 0)
		{
			UNICODE_STRING suffix{ 0 };
			::RtlInitUnicodeString(&suffix, g_ImageFileNameSuffix);

			if (::RtlSuffixUnicodeString(&suffix, (PUNICODE_STRING)CreateInfo->ImageFileName, TRUE))
			{
				CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
				KdPrint((DRIVER_PREFIX "Blocked Process: %wZ\n", (PUNICODE_STRING)CreateInfo->ImageFileName));
			}
			else
			{
				KdPrint((DRIVER_PREFIX "Allowed Process: %wZ\n", (PUNICODE_STRING)CreateInfo->ImageFileName));
			}
		}
		else
		{
			KdPrint((DRIVER_PREFIX "Allowed Process: %wZ\n", (PUNICODE_STRING)CreateInfo->ImageFileName));
		}
	}
}