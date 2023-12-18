#include <ntifs.h>

#define DRIVER_PREFIX "DropProcAccess: "
#define DEVICE_PATH L"\\Device\\DropProcAccess"
#define SYMLINK_PATH L"\\??\\DropProcAccess"

//
// ACCESS_MASK
//
#define PROCESS_QUERY_LIMITED_INFORMATION 0x00001000u;

//
// Ioctl code definition
//
#define IOCTL_SET_PROCESS_GUARD CTL_CODE(0x8000, 0x0B00, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_CLEAR_PROCESS_GUARD CTL_CODE(0x8000, 0x0B01, METHOD_BUFFERED, FILE_ANY_ACCESS)

//
// Function type definition
//
typedef PCHAR (NTAPI *PPsGetProcessImageFileName)(_In_ PEPROCESS Process);

//
// Global variables
//
HANDLE g_TargetPid = nullptr;
PVOID g_RegistrationHandle = nullptr;
PPsGetProcessImageFileName PsGetProcessImageFileName = nullptr;

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
OB_PREOP_CALLBACK_STATUS AccessDropRoutine( // PobPreOperationCallback
	_In_ PVOID RegistrationContext,
	_In_ POB_PRE_OPERATION_INFORMATION OperationInformation
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
		UNICODE_STRING devicePath = RTL_CONSTANT_STRING(DEVICE_PATH);
		UNICODE_STRING symlinkPath = RTL_CONSTANT_STRING(SYMLINK_PATH);
		UNICODE_STRING apiName{};

		::RtlInitUnicodeString(&apiName, L"PsGetProcessImageFileName");
		PsGetProcessImageFileName = (PPsGetProcessImageFileName)::MmGetSystemRoutineAddress(&apiName);

		if (PsGetProcessImageFileName == nullptr)
		{
			KdPrint((DRIVER_PREFIX "Failed to resolve PsGetProcessImageFileName() API.\n"));
			break;
		}
		else
		{
			KdPrint((DRIVER_PREFIX "PsGetProcessImageFileName() API is at 0x%p.\n", (PVOID)PsGetProcessImageFileName));
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

	if (g_RegistrationHandle != nullptr)
	{
		::ObUnRegisterCallbacks(g_RegistrationHandle);
		g_RegistrationHandle = nullptr;
		KdPrint((DRIVER_PREFIX "Object Notification Callback is removed.\n"));
	}

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
	case IOCTL_SET_PROCESS_GUARD:
		if (dic.InputBufferLength < sizeof(ULONG))
		{
			ntstatus = STATUS_BUFFER_TOO_SMALL;
			KdPrint((DRIVER_PREFIX "Input buffer is too small.\n"));
			break;
		}

		g_TargetPid = ULongToHandle(*(ULONG*)Irp->AssociatedIrp.SystemBuffer);

		if (g_RegistrationHandle == nullptr)
		{
			OB_CALLBACK_REGISTRATION callbackRegistration{};
			OB_OPERATION_REGISTRATION operationRegistration[1]{};

			operationRegistration[0].ObjectType = PsProcessType;
			operationRegistration[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
			operationRegistration[0].PreOperation = AccessDropRoutine;
			operationRegistration[0].PostOperation = nullptr;

			callbackRegistration.Version = OB_FLT_REGISTRATION_VERSION;
			callbackRegistration.OperationRegistrationCount = 1;
			::RtlInitUnicodeString(&callbackRegistration.Altitude, L"");
			callbackRegistration.RegistrationContext = nullptr;
			callbackRegistration.OperationRegistration = operationRegistration;

			ntstatus = ::ObRegisterCallbacks(&callbackRegistration, &g_RegistrationHandle);

			if (!NT_SUCCESS(ntstatus))
			{
				g_TargetPid = nullptr;

				if (ntstatus == STATUS_FLT_INSTANCE_ALTITUDE_COLLISION)
					KdPrint((DRIVER_PREFIX "Altitude collision. Change altitude value and rebuild this driver.\n"));
				else
					KdPrint((DRIVER_PREFIX "Failed to register Object Notification Callback (NTSTATUS = 0x%08X).\n", ntstatus));
			}
			else
			{
				KdPrint((DRIVER_PREFIX "Object Notification Callback is registered successfully (Registration Handle = 0x%p).\n", g_RegistrationHandle));
				info = sizeof(PVOID);
			}
		}
		else
		{
			ntstatus = STATUS_SUCCESS;
			info = sizeof(ULONG);
		}

		break;

	case IOCTL_CLEAR_PROCESS_GUARD:
		::ObUnRegisterCallbacks(g_RegistrationHandle);
		g_RegistrationHandle = nullptr;
		g_TargetPid = ULongToHandle(0u);
		ntstatus = STATUS_SUCCESS;
		info = sizeof(PVOID);

		KdPrint((DRIVER_PREFIX "Object Notification Callback is removed.\n"));
	}

	Irp->IoStatus.Status = ntstatus;
	Irp->IoStatus.Information = info;
	IoCompleteRequest(Irp, 0);

	return ntstatus;
}


//
// Object Notify Callback routines
//
OB_PREOP_CALLBACK_STATUS AccessDropRoutine(
	_In_ PVOID RegistrationContext,
	_In_ POB_PRE_OPERATION_INFORMATION OperationInformation
)
{
	UNREFERENCED_PARAMETER(RegistrationContext);

	if ((OperationInformation->ObjectType == *PsProcessType) &&
		(OperationInformation->Object != nullptr))
	{
		ULONG originalAccess = 0u;
		BOOLEAN bIsKernel = OperationInformation->KernelHandle ? TRUE : FALSE;
		BOOLEAN bIsCreateOperation = (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE);
		HANDLE pid = ::PsGetProcessId((PEPROCESS)OperationInformation->Object);
		PULONG pAccess = nullptr;

		if (bIsCreateOperation)
		{
			pAccess = &OperationInformation->Parameters->CreateHandleInformation.DesiredAccess;
			originalAccess = OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess;
		}
		else
		{
			pAccess = &OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess;
			originalAccess = OperationInformation->Parameters->DuplicateHandleInformation.OriginalDesiredAccess;
		}

		if (pid == g_TargetPid)
		{
			*pAccess = SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION;

			KdPrint((DRIVER_PREFIX "%s handle access from %s (PID: %u) to %s (PID: %u) is dropped (Operation: %s).\n",
				bIsKernel ? "Kernel" : "User",
				PsGetProcessImageFileName(::PsGetCurrentProcess()),
				HandleToULong(::PsGetCurrentProcessId()),
				PsGetProcessImageFileName((PEPROCESS)OperationInformation->Object),
				HandleToULong(pid),
				bIsCreateOperation ? "Create" : "Duplicate"));
		}
	}

	return OB_PREOP_SUCCESS;
}