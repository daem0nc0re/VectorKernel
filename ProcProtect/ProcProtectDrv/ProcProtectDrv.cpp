#include <ntifs.h>

#define DRIVER_PREFIX "ProcProtectDrv: "
#define DEVICE_PATH L"\\Device\\ProcProtect"
#define SYMLINK_PATH L"\\??\\ProcProtect"

#pragma warning(disable : 4201) // Caused by _PS_PROTECTION definition

//
// Global Variables
//
ULONG g_SignatureLevelOffset = 0u;
ULONG g_SectionSignatureLevelOffset = 0u;
ULONG g_ProtectionOffset = 0u;

//
// Ioctl code definition
//
#define IOCTL_UPDATE_PROTECTION_LEVEL CTL_CODE(0x8000, 0x0300, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GET_PROTECTION_LEVEL CTL_CODE(0x8000, 0x0301, METHOD_BUFFERED, FILE_ANY_ACCESS)

//
// Kernel struct and enum definition
//
typedef struct _PS_PROTECTION
{
	union
	{
		UCHAR Level;
		struct
		{
			UCHAR Type : 3;
			UCHAR Audit : 1;
			UCHAR Signer : 4;
		};
	};
} PS_PROTECTION, * PPS_PROTECTION;

typedef enum _PS_PROTECTED_SIGNER
{
	PsProtectedSignerNone = 0,
	PsProtectedSignerAuthenticode = 1,
	PsProtectedSignerCodeGen = 2,
	PsProtectedSignerAntimalware = 3,
	PsProtectedSignerLsa = 4,
	PsProtectedSignerWindows = 5,
	PsProtectedSignerWinTcb = 6,
	PsProtectedSignerWinSystem = 7,
	PsProtectedSignerApp = 8,
	PsProtectedSignerMax = 9
} PS_PROTECTED_SIGNER, * PPS_PROTECTED_SIGNER;

typedef enum _PS_PROTECTED_TYPE
{
	PsProtectedTypeNone = 0,
	PsProtectedTypeProtectedLight = 1,
	PsProtectedTypeProtected = 2,
	PsProtectedTypeMax = 3
} PS_PROTECTED_TYPE, * PPS_PROTECTED_TYPE;

//
// Custom struct definition
//

// For input of IOCTL_UPDATE_PROTECTION_LEVEL
// and output of IOCTL_GET_PROTECTION_LEVEL
typedef struct _PROTECTION_INFO
{
	ULONG ProcessId;
	UCHAR /* PS_PROTECTED_TYPE */ ProtectedType;
	UCHAR /* PS_PROTECTED_SIGNER */ ProtectedSigner;
	UCHAR SignatureLevel;
	UCHAR SectionSignatureLevel;
} PROTECTION_INFO, * PPROTECTION_INFO;


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
			if ((versionInfo.dwMajorVersion == 6) && (versionInfo.dwMinorVersion == 3))
			{
				// For Windows 8.1 and Server 2012 R2
				g_SignatureLevelOffset = 0x678u;
				g_SectionSignatureLevelOffset = 0x679u;
				g_ProtectionOffset = 0x67Au;
			}
			else if ((versionInfo.dwMajorVersion == 10) && (versionInfo.dwMinorVersion == 0))
			{
				if (versionInfo.dwBuildNumber == 10240)
				{
					// For Windows 10 1507
					g_SignatureLevelOffset = 0x6A8u;
					g_SectionSignatureLevelOffset = 0x6A9u;
					g_ProtectionOffset = 0x6AAu;
				}
				else if (versionInfo.dwBuildNumber == 10586)
				{
					// For Windows 10 1511
					g_SignatureLevelOffset = 0x6B0u;
					g_SectionSignatureLevelOffset = 0x6B1u;
					g_ProtectionOffset = 0x6B2u;
				}
				else if (versionInfo.dwBuildNumber == 14393)
				{
					// For Windows 10 1607
					g_SignatureLevelOffset = 0x6C0u;
					g_SectionSignatureLevelOffset = 0x6C1u;
					g_ProtectionOffset = 0x6C2u;
				}
				else if (versionInfo.dwBuildNumber == 15063)
				{
					// For Windows 10 1703
					g_SignatureLevelOffset = 0x6C8u;
					g_SectionSignatureLevelOffset = 0x6C9u;
					g_ProtectionOffset = 0x6CAu;
				}
				else if (versionInfo.dwBuildNumber == 16299)
				{
					// For Windows 10 1709
					g_SignatureLevelOffset = 0x6C8u;
					g_SectionSignatureLevelOffset = 0x6C9u;
					g_ProtectionOffset = 0x6CAu;
				}
				else if (versionInfo.dwBuildNumber == 17134)
				{
					// For Windows 10 1803
					g_SignatureLevelOffset = 0x6C8u;
					g_SectionSignatureLevelOffset = 0x6C9u;
					g_ProtectionOffset = 0x6CAu;
				}
				else if (versionInfo.dwBuildNumber == 17763)
				{
					// For Windows 10 1809
					g_SignatureLevelOffset = 0x6C8u;
					g_SectionSignatureLevelOffset = 0x6C9u;
					g_ProtectionOffset = 0x6CAu;
				}
				else if (versionInfo.dwBuildNumber == 18362)
				{
					// For Windows 10 1903
					g_SignatureLevelOffset = 0x6F8u;
					g_SectionSignatureLevelOffset = 0x6F9u;
					g_ProtectionOffset = 0x6FAu;
				}
				else if (versionInfo.dwBuildNumber == 18363)
				{
					// For Windows 10 1909
					g_SignatureLevelOffset = 0x6F8u;
					g_SectionSignatureLevelOffset = 0x6F9u;
					g_ProtectionOffset = 0x6FAu;
				}
				else if (versionInfo.dwBuildNumber == 19041)
				{
					// For Windows 10 2004
					g_SignatureLevelOffset = 0x878u;
					g_SectionSignatureLevelOffset = 0x879u;
					g_ProtectionOffset = 0x87Au;
				}
				else if (versionInfo.dwBuildNumber == 19042)
				{
					// For Windows 10 20H2
					g_SignatureLevelOffset = 0x878u;
					g_SectionSignatureLevelOffset = 0x879u;
					g_ProtectionOffset = 0x87Au;
				}
				else if (versionInfo.dwBuildNumber == 19043)
				{
					// For Windows 10 21H1
					g_SignatureLevelOffset = 0x878u;
					g_SectionSignatureLevelOffset = 0x879u;
					g_ProtectionOffset = 0x87Au;
				}
				else if (versionInfo.dwBuildNumber == 19044)
				{
					// For Windows 10 21H2
					g_SignatureLevelOffset = 0x878u;
					g_SectionSignatureLevelOffset = 0x879u;
					g_ProtectionOffset = 0x87Au;
				}
				else if (versionInfo.dwBuildNumber == 19045)
				{
					// For Windows 10 22H2
					g_SignatureLevelOffset = 0x878u;
					g_SectionSignatureLevelOffset = 0x879u;
					g_ProtectionOffset = 0x87Au;
				}
				else if (versionInfo.dwBuildNumber == 22000)
				{
					// For Windows 11 21H2
					g_SignatureLevelOffset = 0x878u;
					g_SectionSignatureLevelOffset = 0x879u;
					g_ProtectionOffset = 0x87Au;
				}
				else if (versionInfo.dwBuildNumber == 22621)
				{
					// For Windows 11 22H2
					g_SignatureLevelOffset = 0x878u;
					g_SectionSignatureLevelOffset = 0x879u;
					g_ProtectionOffset = 0x87Au;
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
	auto protectionInfo = PROTECTION_INFO{ 0 };
	PEPROCESS pEprocess = nullptr;
	PPS_PROTECTION pPsProtection = nullptr;
	PPROTECTION_INFO pProtectionInfo = nullptr;
	HANDLE pid = nullptr;

	switch (dic.IoControlCode)
	{
	case IOCTL_UPDATE_PROTECTION_LEVEL:
		if (dic.InputBufferLength < sizeof(PROTECTION_INFO))
		{
			ntstatus = STATUS_BUFFER_TOO_SMALL;
			KdPrint((DRIVER_PREFIX "Input buffer is too small.\n"));
			break;
		}

		pProtectionInfo = (PPROTECTION_INFO)Irp->AssociatedIrp.SystemBuffer;
		pid = ULongToHandle(pProtectionInfo->ProcessId);

		if (pProtectionInfo->ProtectedType >= PsProtectedTypeMax)
		{
			KdPrint((DRIVER_PREFIX "Invalid PsProtectedType.\n"));
			break;
		}

		if (pProtectionInfo->ProtectedSigner >= PsProtectedTypeMax)
		{
			KdPrint((DRIVER_PREFIX "Invalid ProtectedSigner.\n"));
			break;
		}

		ntstatus = ::PsLookupProcessByProcessId(pid, &pEprocess);

		if (!NT_SUCCESS(ntstatus))
		{
			pEprocess = nullptr;
			KdPrint((DRIVER_PREFIX "Failed to PsLookupProcessByProcessId() (NTSTATUS = 0x%08X).\n", ntstatus));
		}
		else
		{
			KdPrint((DRIVER_PREFIX "nt!_EPROCESS for PID %u is at %p.\n", HandleToULong(pid), pEprocess));

			auto pSignatureLevel = (PUCHAR)((ULONG_PTR)pEprocess + g_SignatureLevelOffset);
			auto pSectionSignatureLevel = (PUCHAR)((ULONG_PTR)pEprocess + g_SectionSignatureLevelOffset);
			pPsProtection = (PPS_PROTECTION)((ULONG_PTR)pEprocess + g_ProtectionOffset);
			pPsProtection->Type = pProtectionInfo->ProtectedType;
			pPsProtection->Signer = pProtectionInfo->ProtectedSigner;
			*pSignatureLevel = pProtectionInfo->SignatureLevel;
			*pSectionSignatureLevel = pProtectionInfo->SectionSignatureLevel;

			KdPrint((DRIVER_PREFIX "Protection level for PID %u is updated.\n", HandleToULong(pid)));
		}

		break;

	case IOCTL_GET_PROTECTION_LEVEL:
		if (dic.InputBufferLength < sizeof(ULONG))
		{
			ntstatus = STATUS_BUFFER_TOO_SMALL;
			KdPrint((DRIVER_PREFIX "Input buffer is too small.\n"));
			break;
		}

		if (dic.OutputBufferLength < sizeof(PROTECTION_INFO))
		{
			ntstatus = STATUS_BUFFER_TOO_SMALL;
			KdPrint((DRIVER_PREFIX "Output buffer is too small.\n"));
			break;
		}

		protectionInfo.ProcessId = *(ULONG*)Irp->AssociatedIrp.SystemBuffer;
		pid = ULongToHandle(protectionInfo.ProcessId);

		ntstatus = ::PsLookupProcessByProcessId(pid, &pEprocess);

		if (!NT_SUCCESS(ntstatus))
		{
			pEprocess = nullptr;
			KdPrint((DRIVER_PREFIX "Failed to PsLookupProcessByProcessId() (NTSTATUS = 0x%08X).\n", ntstatus));
		}
		else
		{
			KdPrint((DRIVER_PREFIX "nt!_EPROCESS for PID %u is at %p.\n", HandleToULong(pid), pEprocess));

			pPsProtection = (PPS_PROTECTION)((ULONG_PTR)pEprocess + g_ProtectionOffset);
			protectionInfo.ProtectedType = pPsProtection->Type;
			protectionInfo.ProtectedSigner = pPsProtection->Signer;
			protectionInfo.SignatureLevel = *(PUCHAR)((ULONG_PTR)pEprocess + g_SignatureLevelOffset);
			protectionInfo.SectionSignatureLevel = *(PUCHAR)((ULONG_PTR)pEprocess + g_SectionSignatureLevelOffset);
			info = sizeof(PROTECTION_INFO);

			KdPrint((DRIVER_PREFIX "Got protection information from PID %u.\n", HandleToULong(pid)));
		}

		::memcpy(Irp->AssociatedIrp.SystemBuffer, &protectionInfo, sizeof(PROTECTION_INFO));
	}

	if (pEprocess != nullptr)
		ObDereferenceObject(pEprocess);

	Irp->IoStatus.Status = ntstatus;
	Irp->IoStatus.Information = info;
	IoCompleteRequest(Irp, 0);

	return ntstatus;
}