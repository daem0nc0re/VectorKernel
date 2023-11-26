#include <ntifs.h>
#include <aux_klib.h>

#define DRIVER_PREFIX "QueryModuleDrv: "
#define DEVICE_PATH L"\\Device\\QueryModule"
#define SYMLINK_PATH L"\\??\\QueryModule"
#define DRIVER_TAG 'lnKV'

//
// Ioctl code definition
//
#define IOCTL_QUERY_MODULE_INFO CTL_CODE(0x8000, 0x0500, METHOD_BUFFERED, FILE_ANY_ACCESS)

//
// Custom struct definition
//
typedef struct _SYSTEM_MODULE_INFO
{
	ULONG ReturnedLength;
	AUX_MODULE_EXTENDED_INFO Information[ANYSIZE_ARRAY];
} SYSTEM_MODULE_INFO, * PSYSTEM_MODULE_INFO;

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

#ifndef _WIN64
	KdPrint((DRIVER_PREFIX "32bit OS is not supported.\n"));
	return STATUS_NOT_SUPPORTED;
#endif

	do
	{
		RTL_OSVERSIONINFOW versionInfo{ 0 };
		UNICODE_STRING devicePath{ 0 };
		UNICODE_STRING symlinkPath{ 0 };
		::RtlInitUnicodeString(&devicePath, DEVICE_PATH);
		::RtlInitUnicodeString(&symlinkPath, SYMLINK_PATH);

		ntstatus = ::RtlGetVersion(&versionInfo);

		if (!NT_SUCCESS(ntstatus))
		{
			KdPrint((DRIVER_PREFIX "Failed to get OS version information (NTSTATUS = 0x%08X).\n", ntstatus));
			break;
		}
		else
		{
			KdPrint((DRIVER_PREFIX "OS Version - %u.%u.%u\n",
				versionInfo.dwMajorVersion,
				versionInfo.dwMinorVersion,
				versionInfo.dwBuildNumber));

			// This module use ExAllocatePool2 API for memory allocation.
			// ExAllocatePool2 API was introduced from Windows 10 2004.
			// If youw want to try this module older OS, change ExAllocatePool2 API
			// call to ExAllocatePoolWithTag API, and comment out this verification.
			bool bSupported = (versionInfo.dwMajorVersion == 10) && (versionInfo.dwMinorVersion >= 19041);

			if (!bSupported)
			{
				ntstatus = STATUS_NOT_SUPPORTED;
				break;
			}
		}

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
	PVOID pInfoBuffer = nullptr;

	switch (dic.IoControlCode)
	{
	case IOCTL_QUERY_MODULE_INFO:
		ULONG nBufferSize = 0u;
		auto nEntryOffset = (ULONG)FIELD_OFFSET(SYSTEM_MODULE_INFO, Information);

		// Output buffer must have enough space to get notification about required size
		if (dic.OutputBufferLength < sizeof(ULONG))
		{
			ntstatus = STATUS_BUFFER_TOO_SMALL;
			KdPrint((DRIVER_PREFIX "Output buffer is too small.\n"));
			break;
		}
		else if (dic.OutputBufferLength > nEntryOffset)
		{
			nBufferSize = dic.OutputBufferLength - nEntryOffset;
			pInfoBuffer = ::ExAllocatePool2(POOL_FLAG_PAGED, nBufferSize, (ULONG)DRIVER_TAG);

			if (pInfoBuffer == nullptr)
			{
				ntstatus = STATUS_INSUFFICIENT_RESOURCES;
				break;
			}
		}

		ntstatus = ::AuxKlibInitialize();

		if (!NT_SUCCESS(ntstatus))
		{
			KdPrint((DRIVER_PREFIX "Failed to AuxKlibInitialize() (NTSTATUS = 0x%08X).\n", ntstatus));
			break;
		}

		ntstatus = ::AuxKlibQueryModuleInformation(
			&nBufferSize,
			sizeof(AUX_MODULE_EXTENDED_INFO),
			pInfoBuffer);

		if (!NT_SUCCESS(ntstatus))
		{
			nBufferSize += nEntryOffset;
			*(ULONG*)Irp->AssociatedIrp.SystemBuffer = nBufferSize;

			KdPrint((DRIVER_PREFIX "Failed to AuxKlibQueryModuleInformation() (NTSTATUS = 0x%08X).\n", ntstatus));
		}
		else
		{
			if (pInfoBuffer == nullptr)
			{
				// This block should not be reached.
				KdPrint((DRIVER_PREFIX "Got STATUS_SUCCESS but buffer pointer is null. Something wrong.\n"));
				break;
			}

			::memset(Irp->AssociatedIrp.SystemBuffer, 0, nEntryOffset);
			::memcpy(
				(PVOID)((ULONG_PTR)Irp->AssociatedIrp.SystemBuffer + nEntryOffset),
				pInfoBuffer,
				nBufferSize);
			nBufferSize += nEntryOffset;
			*(ULONG*)Irp->AssociatedIrp.SystemBuffer = nBufferSize;
			info = nBufferSize;

			KdPrint((DRIVER_PREFIX "Got module information.\n"));
		}
	}

	if (pInfoBuffer != nullptr)
		::ExFreePool(pInfoBuffer);

	Irp->IoStatus.Status = ntstatus;
	Irp->IoStatus.Information = info;
	IoCompleteRequest(Irp, 0);

	return ntstatus;
}