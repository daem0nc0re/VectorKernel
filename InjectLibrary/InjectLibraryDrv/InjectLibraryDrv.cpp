#include <ntifs.h>

#define DRIVER_PREFIX "InjectLibraryDrv: "
#define DEVICE_PATH L"\\Device\\InjectLibrary"
#define SYMLINK_PATH L"\\??\\InjectLibrary"
#define DRIVER_TAG 'lnKV'

#pragma warning(disable: 4996) // This warning is caused when use old ExAllocatePoolWithTag() API.

//
// Ioctl code definition
//
#define IOCTL_INJECT_LIBRARY CTL_CODE(0x8000, 0x0600, METHOD_BUFFERED, FILE_ANY_ACCESS)

//
// Custom sturct definition
//
typedef struct _INJECT_CONTEXT
{
	ULONG ThreadId;
	WCHAR LibraryPath[256];
} INJECT_CONTEXT, *PINJECT_CONTEXT;

//
// Windows structs from winternl.h
//
typedef struct _PEB_LDR_DATA
{
	UCHAR Reserved1[8];
	PVOID Reserved2[3];
	LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY
{
	PVOID Reserved1[2];
	LIST_ENTRY InMemoryOrderLinks;
	PVOID Reserved2[2];
	PVOID DllBase;
	PVOID Reserved3[2];
	UNICODE_STRING FullDllName;
	UCHAR Reserved4[8];
	PVOID Reserved5[3];
#pragma warning(push)
#pragma warning(disable: 4201) // we'll always use the Microsoft compiler
	union {
		ULONG CheckSum;
		PVOID Reserved6;
	} DUMMYUNIONNAME;
#pragma warning(pop)
	ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB
{
	UCHAR Reserved1[2];
	UCHAR BeingDebugged;
	UCHAR Reserved2[1];
	PVOID Reserved3[2];
	PPEB_LDR_DATA Ldr;
} PEB, *PPEB;

//
// enum definition
//
typedef enum _KAPC_ENVIRONMENT
{
	OriginalApcEnvironment,
	AttachedApcEnvironment,
	CurrentApcEnvironment,
	InsertApcEnvironment
} KAPC_ENVIRONMENT, * PKAPC_ENVIRONMENT;

//
// Function type definition
//
typedef VOID (NTAPI *PKNORMAL_ROUTINE)(
	_In_opt_ PVOID NormalContext,
	_In_opt_ PVOID SystemArgument1,
	_In_opt_ PVOID SystemArgument2
);
typedef VOID (NTAPI *PKKERNEL_ROUTINE)(
	_In_ PKAPC *Apc,
	_Inout_ PKNORMAL_ROUTINE *NormalRoutine,
	_Inout_ PVOID *NormalContext,
	_Inout_ PVOID *SystemArgument1,
	_Inout_ PVOID *SystemArgument2
);
typedef VOID (NTAPI *PKRUNDOWN_ROUTINE)(_In_opt_ PKAPC Apc);
typedef NTSTATUS (NTAPI *PLdrLoadDll)(
	_In_opt_ PWSTR DllPath,
	_In_opt_ PULONG DllCharacteristics,
	_In_ PUNICODE_STRING DllName,
	_Out_ PVOID *DllHandle
);
typedef PVOID (NTAPI *PRtlFindExportedRoutineByName)(
	_In_ PVOID ImageBase,
	_In_ PCHAR RoutineName
);
typedef PPEB (NTAPI *PPsGetProcessPeb)(_In_ PEPROCESS Process);
typedef BOOLEAN (NTAPI *PKeAlertThread)(
	_In_ PKTHREAD Thread,
	_In_ KPROCESSOR_MODE AlertMode
);
typedef VOID (NTAPI *PKeInitializeApc)(
	_Out_ PKAPC Apc,
	_In_ PKTHREAD Thread,
	_In_ KAPC_ENVIRONMENT Environment,
	_In_ PKKERNEL_ROUTINE KernelRoutine,
	_In_opt_ PKRUNDOWN_ROUTINE RundownRoutine,
	_In_opt_ PKNORMAL_ROUTINE NormalRoutine,
	_In_opt_ KPROCESSOR_MODE ProcessorMode,
	_In_opt_ PVOID NormalContext
);
typedef BOOLEAN (NTAPI *PKeInsertQueueApc)(
	_In_ PKAPC Apc,
	_In_opt_ PVOID SystemArgument1,
	_In_opt_ PVOID SystemArgument2,
	_In_ KPRIORITY Increment
);

//
// API address storage
//
PLdrLoadDll LdrLoadDll = nullptr;
PRtlFindExportedRoutineByName RtlFindExportedRoutineByName = nullptr;
PPsGetProcessPeb PsGetProcessPeb = nullptr;
PKeAlertThread KeAlertThread = nullptr;
PKeInitializeApc KeInitializeApc = nullptr;
PKeInsertQueueApc KeInsertQueueApc = nullptr;

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
PVOID GetLdrLoadDllAddress();
VOID NTAPI ApcRoutine(
	_In_ PKAPC* Apc,
	_Inout_ PKNORMAL_ROUTINE* NormalRoutine,
	_Inout_ PVOID* NormalContext,
	_Inout_ PVOID* SystemArgument1,
	_Inout_ PVOID* SystemArgument2);

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
		UNICODE_STRING routineName{ 0 };

		::RtlInitUnicodeString(&routineName, L"PsGetProcessPeb");
		PsGetProcessPeb = (PPsGetProcessPeb)::MmGetSystemRoutineAddress(&routineName);

		if (PsGetProcessPeb == nullptr)
		{
			KdPrint((DRIVER_PREFIX "Failed to resolve %wZ() API.\n", routineName));
			break;
		}
		else
		{
			KdPrint((DRIVER_PREFIX "%wZ() API is at 0x%p.\n", routineName, (PVOID)PsGetProcessPeb));
		}

		::RtlInitUnicodeString(&routineName, L"RtlFindExportedRoutineByName");
		RtlFindExportedRoutineByName = (PRtlFindExportedRoutineByName)::MmGetSystemRoutineAddress(&routineName);

		if (RtlFindExportedRoutineByName == nullptr)
		{
			KdPrint((DRIVER_PREFIX "Failed to resolve %wZ() API.\n", routineName));
			break;
		}
		else
		{
			KdPrint((DRIVER_PREFIX "%wZ() API is at 0x%p.\n", routineName, (PVOID)RtlFindExportedRoutineByName));
		}

		::RtlInitUnicodeString(&routineName, L"KeAlertThread");
		KeAlertThread = (PKeAlertThread)::MmGetSystemRoutineAddress(&routineName);

		if (KeAlertThread == nullptr)
		{
			KdPrint((DRIVER_PREFIX "Failed to resolve %wZ() API.\n", routineName));
			break;
		}
		else
		{
			KdPrint((DRIVER_PREFIX "%wZ() API is at 0x%p.\n", routineName, (PVOID)KeAlertThread));
		}

		::RtlInitUnicodeString(&routineName, L"KeInitializeApc");
		KeInitializeApc = (PKeInitializeApc)::MmGetSystemRoutineAddress(&routineName);

		if (KeInitializeApc == nullptr)
		{
			KdPrint((DRIVER_PREFIX "Failed to resolve %wZ() API.\n", routineName));
			break;
		}
		else
		{
			KdPrint((DRIVER_PREFIX "%wZ() API is at 0x%p.\n", routineName, (PVOID)KeInitializeApc));
		}

		::RtlInitUnicodeString(&routineName, L"KeInsertQueueApc");
		KeInsertQueueApc = (PKeInsertQueueApc)::MmGetSystemRoutineAddress(&routineName);

		if (KeInsertQueueApc == nullptr)
		{
			KdPrint((DRIVER_PREFIX "Failed to resolve %wZ() API.\n", routineName));
			break;
		}
		else
		{
			KdPrint((DRIVER_PREFIX "%wZ() API is at 0x%p.\n", routineName, (PVOID)KeInsertQueueApc));
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
	PIO_STACK_LOCATION irpSp = ::IoGetCurrentIrpStackLocation(Irp);
	auto& dic = irpSp->Parameters.DeviceIoControl;
	ULONG_PTR info = NULL;
	PINJECT_CONTEXT pContext = nullptr;
	PETHREAD pThread = nullptr;
	PVOID pPathBuffer = nullptr;
	PKAPC pKapc = nullptr;
	HANDLE hProcess = nullptr;
	SIZE_T nBufferSize = sizeof(UNICODE_STRING) + (sizeof(WCHAR) * 256) + sizeof(WCHAR); // Add null-terminator at the end.
	KAPC_STATE apcState{ 0 };
	CLIENT_ID clientId{ 0 };
	OBJECT_ATTRIBUTES objectAttributes{ 0 };
	objectAttributes.Length = (ULONG)sizeof(OBJECT_ATTRIBUTES);
	objectAttributes.Attributes = OBJ_KERNEL_HANDLE;

	switch (dic.IoControlCode)
	{
	case IOCTL_INJECT_LIBRARY:
		if (dic.InputBufferLength < sizeof(INJECT_CONTEXT))
		{
			ntstatus = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		pContext = (PINJECT_CONTEXT)Irp->AssociatedIrp.SystemBuffer;
		//pKapc = (PKAPC)::ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(KAPC), (ULONG)DRIVER_TAG);
		pKapc = (PKAPC)::ExAllocatePoolWithTag(NonPagedPool, sizeof(KAPC), (ULONG)DRIVER_TAG);

		if (pKapc == nullptr)
		{
			KdPrint((DRIVER_PREFIX "Failed to allocate non-paged pool for _KAPC.\n"));
			break;
		}
		else
		{
			KdPrint((DRIVER_PREFIX "Non-paged pool for _KAPC is allocated at 0x%p.\n", pKapc));
		}

		if (LdrLoadDll == nullptr)
			LdrLoadDll = (PLdrLoadDll)GetLdrLoadDllAddress();

		if (LdrLoadDll == nullptr)
		{
			KdPrint((DRIVER_PREFIX "Failed to get LdrLoadDll() address.\n"));
			break;
		}
		else
		{
			KdPrint((DRIVER_PREFIX "LdrLoadDll() is at 0x%p.\n", (PVOID)LdrLoadDll));
		}

		ntstatus = ::PsLookupThreadByThreadId(ULongToHandle(pContext->ThreadId), &pThread);
		
		if (!NT_SUCCESS(ntstatus))
		{
			pThread = nullptr;
			KdPrint((DRIVER_PREFIX "Failed to lookup nt!_ETHREAD for thread ID %u (NTSTATUS = 0x%08X).\n",
				pContext->ThreadId,
				ntstatus));
			break;
		}
		else
		{
			KdPrint((DRIVER_PREFIX "nt!_ETHREAD for thread ID %u is at 0x%p.\n", pContext->ThreadId, pThread));
		}

		clientId.UniqueProcess = ::PsGetThreadProcessId(pThread);
		ntstatus = ::ZwOpenProcess(
			&hProcess,
			PROCESS_ALL_ACCESS,
			&objectAttributes,
			&clientId);

		if (!NT_SUCCESS(ntstatus))
		{
			hProcess = nullptr;
			KdPrint((DRIVER_PREFIX "Failed to lookup get process handle of thread (NTSTATUS = 0x%08X).\n", ntstatus));
			break;
		}
		else
		{
			KdPrint((DRIVER_PREFIX "Got process handle for PID %u.\n", HandleToULong(clientId.UniqueProcess)));
		}

		ntstatus = ::ZwAllocateVirtualMemory(
			hProcess,
			&pPathBuffer,
			NULL,
			&nBufferSize,
			MEM_COMMIT | MEM_RESERVE,
			PAGE_READWRITE);

		if (!NT_SUCCESS(ntstatus))
		{
			pPathBuffer = nullptr;
			KdPrint((DRIVER_PREFIX "Failed to allocate buffer in PID %u (NTSTATUS = 0x%08X).\n",
				HandleToULong(clientId.UniqueProcess),
				ntstatus));
			break;
		}
		else
		{
			KdPrint((DRIVER_PREFIX "%u bytes buffer is allocate at 0x%p in PID %u.\n",
				HandleToULong((HANDLE)nBufferSize),
				pPathBuffer,
				HandleToULong(clientId.UniqueProcess)));

			// Write DLL path (_UNICODE_STRING) in the target thread memory.
			::KeStackAttachProcess(::PsGetThreadProcess(pThread), &apcState);

			auto pLibraryPath = (PUNICODE_STRING)pPathBuffer;
			pLibraryPath->MaximumLength = (USHORT)(sizeof(WCHAR) * 256);
			pLibraryPath->Buffer = (PWCH)((ULONG_PTR)pPathBuffer + sizeof(UNICODE_STRING));
			::memcpy(pLibraryPath->Buffer, &pContext->LibraryPath, sizeof(WCHAR) * 256);
			((WCHAR*)pLibraryPath->Buffer)[256] = NULL; // ensure null-terminator for wcslen()
			pLibraryPath->Length = (USHORT)(sizeof(WCHAR) * ::wcslen(pLibraryPath->Buffer));

			KdPrint((DRIVER_PREFIX "Library to inject: %wZ.\n", pPathBuffer));

			::KeUnstackDetachProcess(&apcState);
		}

		KeInitializeApc(
			pKapc,
			pThread,
			OriginalApcEnvironment,
			ApcRoutine,
			nullptr,
			(PKNORMAL_ROUTINE)LdrLoadDll,
			UserMode,
			nullptr);

		if (KeInsertQueueApc(pKapc, nullptr, pPathBuffer, IO_NO_INCREMENT))
		{
			KdPrint((DRIVER_PREFIX "APC queue is inserted successfully.\n"));
			KeAlertThread(pThread, UserMode);
		}
		else
		{
			KdPrint((DRIVER_PREFIX "Failed to insert APC queue.\n"));
		}
	}

	if (!NT_SUCCESS(ntstatus) && (pKapc != nullptr))
		::ExFreePoolWithTag(pKapc, (ULONG)DRIVER_TAG);

	if (hProcess != nullptr)
	{
		if (!NT_SUCCESS(ntstatus) && (pPathBuffer != nullptr))
			::ZwFreeVirtualMemory(hProcess, &pPathBuffer, &nBufferSize, MEM_RELEASE);

		::ZwClose(hProcess);
	}

	if (pThread != nullptr)
		ObDereferenceObject(pThread);

	Irp->IoStatus.Status = ntstatus;
	Irp->IoStatus.Information = info;
	IoCompleteRequest(Irp, 0);

	return ntstatus;
}


//
// Helper functions
//
PVOID GetLdrLoadDllAddress()
{
	PVOID pLdrLoadDll = nullptr;

	do
	{
		PLIST_ENTRY pTopEntry = nullptr;
		PLIST_ENTRY pCurrentEntry = nullptr;
		PVOID pNtdll = nullptr;
		ULONG nModuleListOffset = FIELD_OFFSET(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
		UNICODE_STRING ntdllName = RTL_CONSTANT_STRING(L"\\NTDLL.DLL");
		PEPROCESS pCurrentProcess = ::IoGetCurrentProcess();

		if (pCurrentProcess == nullptr)
			break;

		PPEB pCurrentPeb = PsGetProcessPeb(pCurrentProcess);

		if (pCurrentPeb == nullptr)
			break;

		pTopEntry = pCurrentPeb->Ldr->InMemoryOrderModuleList.Flink;
		pCurrentEntry = pTopEntry;

		while (pCurrentEntry->Flink != pTopEntry)
		{
			auto entry = (PLDR_DATA_TABLE_ENTRY)((ULONG_PTR)pCurrentEntry - nModuleListOffset);

			if (::RtlSuffixUnicodeString(&ntdllName, &entry->FullDllName, TRUE))
			{
				pNtdll = entry->DllBase;
				break;
			}

			pCurrentEntry = pCurrentEntry->Flink;
		}

		if (pNtdll == nullptr)
			break;

		pLdrLoadDll = RtlFindExportedRoutineByName(pNtdll, "LdrLoadDll");
	} while (false);

	return pLdrLoadDll;
}


VOID NTAPI ApcRoutine(
	_In_ PKAPC* Apc,
	_Inout_ PKNORMAL_ROUTINE* NormalRoutine,
	_Inout_ PVOID* NormalContext,
	_Inout_ PVOID* SystemArgument1,
	_Inout_ PVOID* SystemArgument2)
{
	UNREFERENCED_PARAMETER(Apc);
	UNREFERENCED_PARAMETER(NormalRoutine);
	UNREFERENCED_PARAMETER(NormalContext);
	UNREFERENCED_PARAMETER(SystemArgument1);
	UNREFERENCED_PARAMETER(SystemArgument2);

	KdPrint((DRIVER_PREFIX "Kernel APC routine is called.\n"));
}