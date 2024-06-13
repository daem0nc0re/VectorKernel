#include <ntifs.h>

#pragma warning(disable : 4201)

#define DRIVER_PREFIX "ElevateHandleDrv: "
#define DEVICE_PATH L"\\Device\\ElevateHandle"
#define SYMLINK_PATH L"\\??\\ElevateHandle"

#define VALID_GRANTED_ACCESS_BITS_MASK 0x01FFFFFFu

//
// Windows definition
//
typedef struct _HANDLE_TABLE_ENTRY
{
	union
	{
		VOID* Object;
		ULONG ObAttributes;
		struct _HANDLE_TABLE_ENTRY_INFO* InfoTable;
		ULONGLONG Value;
	};
	union
	{
		ULONG GrantedAccess;
		struct
		{
			USHORT GrantedAccessIndex;
			USHORT CreatorBackTraceIndex;
		};
		LONG NextFreeTableEntry;
	};
} HANDLE_TABLE_ENTRY, * PHANDLE_TABLE_ENTRY;


//
// Global Variables
//
ULONG g_ObjectTableOffset = 0u; // nt!_EPROCESS
ULONG g_NextHandleNeedingPoolOffset = 0u; // nt!_HANDLE_TABLE
ULONG g_TableCodeOffset = 0u; // nt!_HANDLE_TABLE

//
// Struct definition
//
typedef struct _ELEVATE_HANDLE_INPUT
{
	HANDLE UniqueProcessId;
	HANDLE HandleValue;
	ULONG AccessMask;
} ELEVATE_HANDLE_INPUT, * PELEVATE_HANDLE_INPUT;

//
// Ioctl code definition
//
#define IOCTL_ELEVATE_HANDLE CTL_CODE(0x8000, 0x0D00, METHOD_BUFFERED, FILE_ANY_ACCESS)

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

			if ((versionInfo.dwMajorVersion == 6))
			{
				if (versionInfo.dwMinorVersion == 0)
				{
					// For Windows Vista
					g_ObjectTableOffset = 0x160u;
					g_NextHandleNeedingPoolOffset = 0x5Cu;
					g_TableCodeOffset = 0u;
				}
				else if (versionInfo.dwMinorVersion == 1)
				{
					// For Windows 7 and Server 2008 R2
					g_ObjectTableOffset = 0x200u;
					g_NextHandleNeedingPoolOffset = 0x5Cu;
					g_TableCodeOffset = 0u;
				}
				else if (versionInfo.dwMinorVersion == 2)
				{
					// For Windows 8 and Server 2012
					g_ObjectTableOffset = 0x408u;
					g_NextHandleNeedingPoolOffset = 0u;
					g_TableCodeOffset = 0x8u;
				}
				else if (versionInfo.dwMinorVersion == 3)
				{
					// For Windows 8.1 and Server 2012 R2
					g_ObjectTableOffset = 0x408u;
					g_NextHandleNeedingPoolOffset = 0u;
					g_TableCodeOffset = 0x8u;
				}
			}
			else if ((versionInfo.dwMajorVersion == 10) && (versionInfo.dwMinorVersion == 0))
			{
				if (versionInfo.dwBuildNumber == 10240)
				{
					// For Windows 10 1507
					g_ObjectTableOffset = 0x418u;
					g_NextHandleNeedingPoolOffset = 0u;
					g_TableCodeOffset = 0x8u;
				}
				else if (versionInfo.dwBuildNumber == 10586)
				{
					// For Windows 10 1511
					g_ObjectTableOffset = 0x418u;
					g_NextHandleNeedingPoolOffset = 0u;
					g_TableCodeOffset = 0x8u;
				}
				else if (versionInfo.dwBuildNumber == 14393)
				{
					// For Windows 10 1607
					g_ObjectTableOffset = 0x418u;
					g_NextHandleNeedingPoolOffset = 0u;
					g_TableCodeOffset = 0x8u;
				}
				else if (versionInfo.dwBuildNumber == 15063)
				{
					// For Windows 10 1703
					g_ObjectTableOffset = 0x418u;
					g_NextHandleNeedingPoolOffset = 0u;
					g_TableCodeOffset = 0x8u;
				}
				else if (versionInfo.dwBuildNumber == 16299)
				{
					// For Windows 10 1709
					g_ObjectTableOffset = 0x418u;
					g_NextHandleNeedingPoolOffset = 0u;
					g_TableCodeOffset = 0x8u;
				}
				else if (versionInfo.dwBuildNumber == 17134)
				{
					// For Windows 10 1803
					g_ObjectTableOffset = 0x418u;
					g_NextHandleNeedingPoolOffset = 0u;
					g_TableCodeOffset = 0x8u;
				}
				else if (versionInfo.dwBuildNumber == 17763)
				{
					// For Windows 10 1809
					g_ObjectTableOffset = 0x418u;
					g_NextHandleNeedingPoolOffset = 0u;
					g_TableCodeOffset = 0x8u;
				}
				else if (versionInfo.dwBuildNumber == 18362)
				{
					// For Windows 10 1903
					g_ObjectTableOffset = 0x418u;
					g_NextHandleNeedingPoolOffset = 0u;
					g_TableCodeOffset = 0x8u;
				}
				else if (versionInfo.dwBuildNumber == 18363)
				{
					// For Windows 10 1909
					g_ObjectTableOffset = 0x418u;
					g_NextHandleNeedingPoolOffset = 0u;
					g_TableCodeOffset = 0x8u;
				}
				else if (versionInfo.dwBuildNumber == 19041)
				{
					// For Windows 10 2004
					g_ObjectTableOffset = 0x570u;
					g_NextHandleNeedingPoolOffset = 0u;
					g_TableCodeOffset = 0x8u;
				}
				else if (versionInfo.dwBuildNumber == 19042)
				{
					// For Windows 10 20H2
					g_ObjectTableOffset = 0x570u;
					g_NextHandleNeedingPoolOffset = 0u;
					g_TableCodeOffset = 0x8u;
				}
				else if (versionInfo.dwBuildNumber == 19043)
				{
					// For Windows 10 21H1
					g_ObjectTableOffset = 0x570u;
					g_NextHandleNeedingPoolOffset = 0u;
					g_TableCodeOffset = 0x8u;
				}
				else if (versionInfo.dwBuildNumber == 19044)
				{
					// For Windows 10 21H2
					g_ObjectTableOffset = 0x570u;
					g_NextHandleNeedingPoolOffset = 0u;
					g_TableCodeOffset = 0x8u;
				}
				else if (versionInfo.dwBuildNumber == 19045)
				{
					// For Windows 10 22H2
					g_ObjectTableOffset = 0x570u;
					g_NextHandleNeedingPoolOffset = 0u;
					g_TableCodeOffset = 0x8u;
				}
				else if (versionInfo.dwBuildNumber == 22000)
				{
					// For Windows 11 21H2
					g_ObjectTableOffset = 0x570u;
					g_NextHandleNeedingPoolOffset = 0u;
					g_TableCodeOffset = 0x8u;
				}
				else if (versionInfo.dwBuildNumber == 22621)
				{
					// For Windows 11 22H2
					g_ObjectTableOffset = 0x570u;
					g_NextHandleNeedingPoolOffset = 0u;
					g_TableCodeOffset = 0x8u;
				}
				else if (versionInfo.dwBuildNumber == 22631)
				{
					// For Windows 11 23H2
					g_ObjectTableOffset = 0x570u;
					g_NextHandleNeedingPoolOffset = 0u;
					g_TableCodeOffset = 0x8u;
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

	switch (dic.IoControlCode)
	{
	case IOCTL_ELEVATE_HANDLE:
		if (dic.InputBufferLength < sizeof(ELEVATE_HANDLE_INPUT))
		{
			ntstatus = STATUS_BUFFER_TOO_SMALL;
			KdPrint((DRIVER_PREFIX "Input buffer is too small.\n"));
			break;
		}

		PEPROCESS pEprocess = nullptr;
		auto context = (PELEVATE_HANDLE_INPUT)Irp->AssociatedIrp.SystemBuffer;
		HANDLE pid = context->UniqueProcessId;
		HANDLE handleValue = context->HandleValue;
		ULONG accessMask = context->AccessMask & VALID_GRANTED_ACCESS_BITS_MASK;

		if ((handleValue == NULL) || (((ULONG_PTR)handleValue & 3) != NULL))
		{
			ntstatus = STATUS_INVALID_PARAMETER;
			break;
		}

		ntstatus = ::PsLookupProcessByProcessId(pid, &pEprocess);

		if (!NT_SUCCESS(ntstatus))
		{
			KdPrint((DRIVER_PREFIX "Failed to PsLookupProcessByProcessId() (NTSTATUS = 0x%08X).\n", ntstatus));
			break;
		}
		else
		{
			ULONG_PTR pBaseBuffer;
			PHANDLE_TABLE_ENTRY pEntry;
			ULONG nOriginalAccess;
			auto pObjectTable = *(ULONG_PTR*)((ULONG_PTR)pEprocess + g_ObjectTableOffset);
			auto pEntries = *(ULONG_PTR*)((ULONG_PTR)pObjectTable + g_TableCodeOffset);
			auto nonce = (ULONG)(pEntries & 3);
			auto nFactor = (ULONG_PTR)handleValue >> 0xA;

			if (HandleToULong(handleValue) >= *(ULONG*)((ULONG_PTR)pObjectTable + g_NextHandleNeedingPoolOffset))
			{
				ntstatus = STATUS_NOT_FOUND;
				break;
			}

			KdPrint((DRIVER_PREFIX "UniqueProcessId = 0x%X, HandleValue = 0x%X\n", HandleToULong(pid), HandleToUlong(handleValue)));

			// This routine is written with reference to nt!ExpLookupHandleTableEntry
			if (nonce == 1)
			{
				pBaseBuffer = *(ULONG_PTR*)(pEntries + (nFactor << 3) - 1);
				pEntry = (PHANDLE_TABLE_ENTRY)(pBaseBuffer + ((ULONG_PTR)(HandleToULong(handleValue) & 0x3FFu) << 2));
			}
			else if (nonce > 1)
			{
				pBaseBuffer = *(ULONG_PTR*)((pEntries + ((nFactor >> 9) << 3)) - 2) + ((nFactor & 0x1FFu) << 3);
				pEntry = (PHANDLE_TABLE_ENTRY)(pBaseBuffer + ((ULONG_PTR)(HandleToULong(handleValue) & 0x3FFu) << 2));
			}
			else
			{
				pEntry = (PHANDLE_TABLE_ENTRY)(pEntries + ((ULONG_PTR)handleValue << 2));
			}

			KdPrint((DRIVER_PREFIX "nt!_HANDLE_TABLE_ENTRY is at 0x%p.\n", (VOID*)pEntry));

			nOriginalAccess = pEntry->GrantedAccess;
			pEntry->GrantedAccess |= accessMask;
			ntstatus = STATUS_SUCCESS;

			KdPrint((DRIVER_PREFIX "GrantedAccess is updated from 0x%08X to 0x%08X.\n", nOriginalAccess, pEntry->GrantedAccess));

			ObDereferenceObject(pEprocess);
		}
	}

	Irp->IoStatus.Status = ntstatus;
	Irp->IoStatus.Information = info;
	IoCompleteRequest(Irp, 0);

	return ntstatus;
}