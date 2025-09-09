#include <ntifs.h>

#define DRIVER_PREFIX "BlockNewProcDrv: "
#define DEVICE_PATH L"\\Device\\BlockNewProc"
#define SYMLINK_PATH L"\\??\\BlockNewProc"

#define MAXIMUM_BLOCKNAME_LENGTH 256

//
// Ioctl code definition
//
#define IOCTL_SET_PROCESS_FILENAME CTL_CODE(0x8000, 0x0900, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_UNREGISTER_CALLBACK CTL_CODE(0x8000, 0x0901, METHOD_BUFFERED, FILE_ANY_ACCESS)

//
// Custom sturct definition
//
typedef struct _BLOCK_IMAGE_INFO
{
	ULONG NameBytesLength;
	WCHAR ImageFileName[ANY_SIZE];
} BLOCK_IMAGE_INFO, * PBLOCK_IMAGE_INFO;

typedef struct _BLOCK_IMAGENAME_MANAGER
{
	FAST_MUTEX FastMutex;
	BOOLEAN Registered;
	UNICODE_STRING Name;
	WCHAR NameBuffer[MAXIMUM_BLOCKNAME_LENGTH + 1];
} BLOCK_IMAGENAME_MANAGER, *PBLOCK_IMAGENAME_MANAGER;

//
// Global variables
//
BLOCK_IMAGENAME_MANAGER g_Manager = { 0 };

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
NTSTATUS RemoveBlockProcessImageName();
NTSTATUS SetBlockProcessImageName(
	_In_ PBLOCK_IMAGE_INFO ImageName,
	_In_ ULONG InputLength,
	_Out_ PULONG_PTR Information
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

		::ExInitializeFastMutex(&g_Manager.FastMutex);
		g_Manager.Registered = FALSE;
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
	RemoveBlockProcessImageName();
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
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

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
	PVOID pInputBuffer = Irp->AssociatedIrp.SystemBuffer;
	ULONG nInputLength = dic.InputBufferLength;

	switch (dic.IoControlCode)
	{
	case IOCTL_SET_PROCESS_FILENAME:
	{
		KdPrint((DRIVER_PREFIX "IOCTL_SET_PROCESS_FILENAME is called.\n"));
		ntstatus = SetBlockProcessImageName((PBLOCK_IMAGE_INFO)pInputBuffer, nInputLength, &info);
		break;
	}
	case IOCTL_UNREGISTER_CALLBACK:
	{
		KdPrint((DRIVER_PREFIX "IOCTL_UNREGISTER_CALLBACK is called.\n"));
		ntstatus = RemoveBlockProcessImageName();
		break;
	}
	}

	Irp->IoStatus.Status = ntstatus;
	Irp->IoStatus.Information = info;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return ntstatus;
}


//
// IOCTL functions
//
NTSTATUS RemoveBlockProcessImageName()
{
	NTSTATUS ntstatus = STATUS_SUCCESS;

	::ExAcquireFastMutex(&g_Manager.FastMutex);

	if (g_Manager.Registered)
	{
		ntstatus = ::PsSetCreateProcessNotifyRoutineEx2(
			PsCreateProcessNotifySubsystems,
			(PVOID)ProcessBlockRoutine,
			TRUE);
		g_Manager.Name.Length = 0;
		g_Manager.Name.MaximumLength = g_Manager.Name.Length;
		g_Manager.Name.Buffer = nullptr;
		::memset(&g_Manager.NameBuffer, 0, sizeof(g_Manager.NameBuffer));

		if (!NT_SUCCESS(ntstatus))
		{
			KdPrint((DRIVER_PREFIX "Failed to unregister Process Notify Callback (NTSTATUS = 0x%08X).\n", ntstatus));
		}
		else
		{
			g_Manager.Registered = FALSE;
			KdPrint((DRIVER_PREFIX "Process Notify Callback is unregistered successfully.\n"));
		}
	}
	else
	{
		KdPrint((DRIVER_PREFIX "Process Notify Callback is not registered.\n"));
	}

	::ExReleaseFastMutex(&g_Manager.FastMutex);

	return ntstatus;
}


NTSTATUS SetBlockProcessImageName(
	_In_ PBLOCK_IMAGE_INFO ImageName,
	_In_ ULONG InputLength,
	_Out_ PULONG_PTR Information)
{
	NTSTATUS ntstatus = STATUS_SUCCESS;
	ULONG nNameBytesLength = 0u;
	ULONG nMinimumLength = FIELD_OFFSET(BLOCK_IMAGE_INFO, ImageFileName);
	*Information = NULL;

	if (ImageName == nullptr)
		return STATUS_INVALID_ADDRESS;
	else if (InputLength < nMinimumLength)
		return STATUS_BUFFER_TOO_SMALL;

	nNameBytesLength = ImageName->NameBytesLength;

	if (nNameBytesLength > MAXIMUM_BLOCKNAME_LENGTH + sizeof(WCHAR))
		return STATUS_NAME_TOO_LONG;
	else if (nNameBytesLength > (MAXUINT16 - sizeof(WCHAR)))
		return STATUS_NAME_TOO_LONG;
	else if (InputLength < nMinimumLength + nNameBytesLength)
		return STATUS_BUFFER_TOO_SMALL;

	::ExAcquireFastMutex(&g_Manager.FastMutex);
	::memset(&g_Manager.NameBuffer, 0, sizeof(g_Manager.NameBuffer));
	g_Manager.Name.Length = (USHORT)(nNameBytesLength + sizeof(WCHAR));
	g_Manager.Name.MaximumLength = g_Manager.Name.Length;
	g_Manager.Name.Buffer = (PWCHAR)&g_Manager.NameBuffer;
	g_Manager.NameBuffer[0] = L'\\';
	::memcpy(&g_Manager.NameBuffer[1], &ImageName->ImageFileName, nNameBytesLength);

	KdPrint((DRIVER_PREFIX "Target ImageFileName pattern is updated to \"%wZ\".\n", &g_Manager.Name));

	if (!g_Manager.Registered)
	{
		ntstatus = ::PsSetCreateProcessNotifyRoutineEx2(
			PsCreateProcessNotifySubsystems,
			(PVOID)ProcessBlockRoutine,
			FALSE);

		if (!NT_SUCCESS(ntstatus))
		{
			KdPrint((DRIVER_PREFIX "Failed to register Process Notify Routine (NTSTATUS = 0x%08X).", ntstatus));
			g_Manager.Name.Length = 0;
			g_Manager.Name.MaximumLength = g_Manager.Name.Length;
			g_Manager.Name.Buffer = nullptr;
			::memset(&g_Manager.NameBuffer, 0, sizeof(g_Manager.NameBuffer));
		}
		else
		{
			KdPrint((DRIVER_PREFIX "Process Notify Callback is registered successfully.\n"));
			*Information = g_Manager.Name.Length;
			g_Manager.Registered = TRUE;
		}
	}
	else
	{
		*Information = g_Manager.Name.Length;
	}

	::ExReleaseFastMutex(&g_Manager.FastMutex);

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
		::ExAcquireFastMutex(&g_Manager.FastMutex);

		if ((g_Manager.Name.Length > 0) && (g_Manager.Name.Buffer != nullptr))
		{
			if (::RtlSuffixUnicodeString(&g_Manager.Name, (PUNICODE_STRING)CreateInfo->ImageFileName, TRUE))
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

		::ExReleaseFastMutex(&g_Manager.FastMutex);
	}
}