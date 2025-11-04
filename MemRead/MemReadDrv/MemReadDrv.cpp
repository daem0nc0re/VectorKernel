#include <ntifs.h>

#define DRIVER_PREFIX "MemReadDrv: "
#define DEVICE_PATH L"\\Device\\MemRead"
#define SYMLINK_PATH L"\\??\\MemRead"
#define DRIVER_TAG 'lnKV'

#define MemoryMappedFilenameInformation 2
#define MEM_MAPPED 0x00040000  
#define MEM_IMAGE 0x01000000 

#define IOCTL_GET_MEMORY_MAPPING CTL_CODE(0x8000, 0x0F00, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_READ_MEMORY CTL_CODE(0x8000, 0x0F01, METHOD_BUFFERED, FILE_ANY_ACCESS)

//
// Custom structs
//
typedef struct _MEMORY_INFORMATION_MANAGER
{
	LIST_ENTRY ListHead;
	ULONG NumberOfEntries;
	ULONG TotalSize;
	FAST_MUTEX FastMutex;
} MEMORY_INFORMATION_MANAGER, *PMEMORY_INFORMATION_MANAGER;

// Struct size is aligned by sizeof(ULONG_PTR)
typedef struct _MEMORY_MAPPING_INFO
{
	ULONG Size;
	ULONG NameLength;
	MEMORY_BASIC_INFORMATION Information;
	WCHAR Filename[ANY_SIZE]; // Mapped filename is stored here
} MEMORY_MAPPING_INFO, *PMEMORY_MAPPING_INFO;

typedef struct _MEMORY_MAPPING_INFO_FULL
{
	LIST_ENTRY Link;
	MEMORY_MAPPING_INFO Entry;
} MEMORY_MAPPING_INFO_FULL, *PMEMORY_MAPPING_INFO_FULL;

typedef struct _IOCTL_QUERY_INPUT
{
	ULONG ProcessId;
} IOCTL_QUERY_INPUT, *PIOCTL_QUERY_INPUT;

typedef struct _IOCTL_QUERY_OUTPUT_HEADER
{
	ULONG EntryCount;
	ULONG DataLength;
	PVOID Peb;
	PVOID Peb32;
} IOCTL_QUERY_OUTPUT_HEADER, *PIOCTL_QUERY_OUTPUT_HEADER;

typedef struct _IOCTL_QUERY_OUTPUT
{
	IOCTL_QUERY_OUTPUT_HEADER Header;
	MEMORY_MAPPING_INFO Entries[ANY_SIZE];
} IOCTL_QUERY_OUTPUT, *PIOCTL_QUERY_OUTPUT;

typedef struct _IOCTL_READ_MEMORY_INPUT
{
	ULONG ProcessId;
	ULONG ReadBytes;
	PVOID BaseAddress;
} IOCTL_READ_MEMORY_INPUT, *PIOCTL_READ_MEMORY_INPUT;

// Struct size and Data field offset are aligned by sizeof(ULONG_PTR)
typedef struct _IOCTL_READ_MEMORY_OUTPUT
{
	ULONG Size;
	ULONG ReadBytes;
	ULONG NameLength;
	ULONG DataOffset;
	MEMORY_BASIC_INFORMATION Information;
	WCHAR Filename[ANY_SIZE];
	UCHAR Data[ANY_SIZE];
} IOCTL_READ_MEMORY_OUTPUT, *PIOCTL_READ_MEMORY_OUTPUT;

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
PVOID AllocateNonPagedPool(_In_ SIZE_T nPoolSize);
NTSTATUS GetMappedFilename(
	_In_ HANDLE ProcessHandle,
	_In_ PVOID BaseAddress,
	_Out_ PUNICODE_STRING* NameBuffer
);
NTSTATUS GetMemoryMappingInformation(
	_In_ ULONG ProcessId,
	_Out_ PVOID *Peb,
	_Out_ PVOID *Peb32
);
NTSTATUS GetMemoryBasicInformation(
	_In_ HANDLE ProcessHandle,
	_Out_ PVOID *Buffer,
	_Out_ ULONG *Length
);
PVOID GetPebAddress(_In_ HANDLE ProcessHandle, _Out_ PVOID *Peb32);
NTSTATUS ReadMemoryFromProcess(
	_In_ ULONG ProcessId,
	_In_ PVOID BaseAddress,
	_In_ ULONG NumberOfBytesToRead,
	_Out_ PIOCTL_READ_MEMORY_OUTPUT *MemoryData
);
VOID ReleaseMemoryInformationBuffer();
BOOLEAN IsUserAddress(_In_ PVOID BaseAddress);

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
typedef NTSTATUS(NTAPI* PZwQueryInformationProcess)(
	_In_      HANDLE           ProcessHandle,
	_In_      PROCESSINFOCLASS ProcessInformationClass,
	_Out_     PVOID            ProcessInformation,
	_In_      ULONG            ProcessInformationLength,
	_Out_opt_ PULONG           ReturnLength
	);

//
// API address storage
//
PExAllocatePool2 pExAllocatePool2 = nullptr;
PExAllocatePoolWithTag pExAllocatePoolWithTag = nullptr;
PZwQueryInformationProcess ZwQueryInformationProcess = nullptr;

//
// Global variables
//
MEMORY_INFORMATION_MANAGER g_Manager { 0 };

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
		UNICODE_STRING routineName{ 0 };

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

		::RtlInitUnicodeString(&routineName, L"ZwQueryInformationProcess");
		ZwQueryInformationProcess = (PZwQueryInformationProcess)::MmGetSystemRoutineAddress(&routineName);

		if (ZwQueryInformationProcess == nullptr)
		{
			KdPrint((DRIVER_PREFIX "Failed to resolve ZwQueryInformationProcess() API.\n"));
			break;
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

		::InitializeListHead(&g_Manager.ListHead);
		::ExInitializeFastMutex(&g_Manager.FastMutex);
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
	ReleaseMemoryInformationBuffer();

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
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

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
	case IOCTL_GET_MEMORY_MAPPING:
	{
		PVOID pQueryInOutBuffer = Irp->AssociatedIrp.SystemBuffer;
		ULONG nQueryInputLength = dic.InputBufferLength;
		ULONG nQueryOutputLength = dic.OutputBufferLength;
		PVOID pPeb = nullptr;
		PVOID pPeb32 = nullptr;
		info = sizeof(IOCTL_QUERY_OUTPUT_HEADER);

		if (nQueryInputLength < sizeof(IOCTL_QUERY_INPUT))
		{
			ntstatus = STATUS_INVALID_BUFFER_SIZE;
			KdPrint((DRIVER_PREFIX "[IOCTL_GET_MEMORY_MAPPING] Input buffer is too small.\n"));
			break;
		}
		else if (nQueryOutputLength < sizeof(IOCTL_QUERY_OUTPUT_HEADER))
		{
			ntstatus = STATUS_INVALID_BUFFER_SIZE;
			KdPrint((DRIVER_PREFIX "[IOCTL_GET_MEMORY_MAPPING] Output buffer is too small.\n"));
			break;
		}
		else if (pQueryInOutBuffer == nullptr)
		{
			ntstatus = STATUS_INVALID_ADDRESS;
			KdPrint((DRIVER_PREFIX "[IOCTL_GET_MEMORY_MAPPING] Invalid input buffer address.\n"));
			break;
		}

		ntstatus = GetMemoryMappingInformation(
			((PIOCTL_QUERY_INPUT)pQueryInOutBuffer)->ProcessId,
			&pPeb,
			&pPeb32);

		if (!NT_SUCCESS(ntstatus))
		{
			KdPrint((DRIVER_PREFIX "[IOCTL_GET_MEMORY_MAPPING] Failed with NTSTATUS 0x%08X.\n", ntstatus));
		}
		else
		{
			::ExAcquireFastMutex(&g_Manager.FastMutex);
			auto pQueryOutputBuffer = (PIOCTL_QUERY_OUTPUT)pQueryInOutBuffer;
			auto nRequiredSize = (ULONG)(g_Manager.TotalSize + FIELD_OFFSET(IOCTL_QUERY_OUTPUT, Entries));
			info = nRequiredSize;
			pQueryOutputBuffer->Header.EntryCount = g_Manager.NumberOfEntries;
			pQueryOutputBuffer->Header.DataLength = g_Manager.TotalSize + FIELD_OFFSET(IOCTL_QUERY_OUTPUT, Entries);
			pQueryOutputBuffer->Header.Peb = pPeb;
			pQueryOutputBuffer->Header.Peb32 = pPeb32;

			if (nQueryOutputLength >= nRequiredSize)
			{
				auto pEntryBuffer = (PMEMORY_MAPPING_INFO)(&pQueryOutputBuffer->Entries);

				for (ULONG i = 0; i < g_Manager.NumberOfEntries; i++)
				{
					auto pMemoryInfo = (PMEMORY_MAPPING_INFO_FULL)::RemoveHeadList(&g_Manager.ListHead);
					ULONG nEntrySize = pMemoryInfo->Entry.Size;

					::memcpy(pEntryBuffer, &pMemoryInfo->Entry, nEntrySize);
					::ExFreePoolWithTag(pMemoryInfo, (ULONG)DRIVER_TAG);

					pEntryBuffer = (PMEMORY_MAPPING_INFO)((ULONG_PTR)pEntryBuffer + nEntrySize);
				}
			}
			else
			{
				ntstatus = STATUS_BUFFER_TOO_SMALL;
			}

			::ExReleaseFastMutex(&g_Manager.FastMutex);
		}

		ReleaseMemoryInformationBuffer();
		break;
	}
	case IOCTL_READ_MEMORY:
	{
		PVOID pReadInOutBuffer = Irp->AssociatedIrp.SystemBuffer;
		ULONG nReadInputLength = dic.InputBufferLength;
		ULONG nReadOutputLength = dic.OutputBufferLength;
		ULONG nMinimumOutputSize = FIELD_OFFSET(IOCTL_READ_MEMORY_OUTPUT, Filename);
		PIOCTL_READ_MEMORY_OUTPUT pMemoryData = nullptr;
		info = FIELD_OFFSET(IOCTL_READ_MEMORY_OUTPUT, Filename);

		if (nReadInputLength < sizeof(IOCTL_READ_MEMORY_INPUT))
		{
			ntstatus = STATUS_INVALID_BUFFER_SIZE;
			KdPrint((DRIVER_PREFIX "[IOCTL_READ_MEMORY] Input buffer is too small.\n"));
			break;
		}
		
		nMinimumOutputSize += ((PIOCTL_READ_MEMORY_INPUT)pReadInOutBuffer)->ReadBytes;
		
		if (nReadOutputLength < nMinimumOutputSize)
		{
			ntstatus = STATUS_INVALID_BUFFER_SIZE;
			KdPrint((DRIVER_PREFIX "[IOCTL_READ_MEMORY] Output buffer is too small.\n"));
			break;
		}
		else if (pReadInOutBuffer == nullptr)
		{
			ntstatus = STATUS_INVALID_ADDRESS;
			KdPrint((DRIVER_PREFIX "[IOCTL_READ_MEMORY] Invalid input buffer address.\n"));
			break;
		}

		ntstatus = ReadMemoryFromProcess(
			((PIOCTL_READ_MEMORY_INPUT)pReadInOutBuffer)->ProcessId,
			((PIOCTL_READ_MEMORY_INPUT)pReadInOutBuffer)->BaseAddress,
			((PIOCTL_READ_MEMORY_INPUT)pReadInOutBuffer)->ReadBytes,
			&pMemoryData);

		if (!NT_SUCCESS(ntstatus))
		{
			KdPrint((DRIVER_PREFIX "[IOCTL_READ_MEMORY] Failed with NTSTATUS 0x%08X.\n", ntstatus));
			break;
		}
		else
		{
			info = pMemoryData->Size;

			if (nReadOutputLength < pMemoryData->Size)
			{
				ntstatus = STATUS_BUFFER_TOO_SMALL;
				KdPrint((DRIVER_PREFIX "[IOCTL_READ_MEMORY] Output buffer is too small (required 0x%X bytes)\n", pMemoryData->Size));
			}
			else
			{
				::memcpy(pReadInOutBuffer, pMemoryData, pMemoryData->Size);
			}

			::ExFreePoolWithTag(pMemoryData, (ULONG)DRIVER_TAG);
		}
	}
	}

	Irp->IoStatus.Status = ntstatus;
	Irp->IoStatus.Information = info;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return ntstatus;
}

//
// IOCTL functions
//
NTSTATUS GetMemoryMappingInformation(
	_In_ ULONG ProcessId,
	_Out_ PVOID *Peb,
	_Out_ PVOID *Peb32)
{
	NTSTATUS ntstatus = STATUS_ACCESS_DENIED;
	HANDLE hProcess = NULL;
	PUNICODE_STRING pPathBuffer = nullptr;
	PVOID pBasicInfo = nullptr;
	ULONG nBasicInfoLength = 0;
	OBJECT_ATTRIBUTES objectAttributes{ 0 };
	auto clientId = CLIENT_ID{ ULongToHandle(ProcessId), NULL };
	InitializeObjectAttributes(
		&objectAttributes,
		nullptr,
		OBJ_KERNEL_HANDLE,
		NULL,
		nullptr);

	ntstatus = ::ZwOpenProcess(
		&hProcess,
		PROCESS_ALL_ACCESS,
		&objectAttributes,
		&clientId);

	if (!NT_SUCCESS(ntstatus))
	{
		KdPrint((DRIVER_PREFIX "Failed to get handle of the target process (NTSTATUS = 0x%08X).\n", ntstatus));
		return ntstatus;
	}

	*Peb = GetPebAddress(hProcess, Peb32);

	do
	{
		ULONG nEntryCount = 0;
		ULONG nUnitSize = sizeof(MEMORY_BASIC_INFORMATION);
		ntstatus =  GetMemoryBasicInformation(hProcess, &pBasicInfo, &nBasicInfoLength);

		if (!NT_SUCCESS(ntstatus))
		{
			KdPrint((DRIVER_PREFIX "Failed to get memory basic information (NTSTATUS = 0x%08X).\n", ntstatus));
			pBasicInfo = nullptr;
			nBasicInfoLength = 0;
			break;
		}

		nEntryCount = (ULONG)(nBasicInfoLength / (ULONG)nUnitSize);
		pPathBuffer = (PUNICODE_STRING)AllocateNonPagedPool(0x800);
		KdPrint((DRIVER_PREFIX "Number of entries is 0x%X.\n", nEntryCount));

		if (pPathBuffer != nullptr)
		{
			for (ULONG i = 0; i < nEntryCount; i++)
			{
				SIZE_T nReturnedLength = 0;
				PMEMORY_MAPPING_INFO_FULL pEntryBuffer = nullptr;
				auto nEntrySize = (FIELD_OFFSET(MEMORY_MAPPING_INFO_FULL, Entry) + FIELD_OFFSET(MEMORY_MAPPING_INFO, Filename));
				auto pMbi = (PMEMORY_BASIC_INFORMATION)((ULONG_PTR)pBasicInfo + (ULONG_PTR)(nUnitSize * i));
				::memset(pPathBuffer, 0, sizeof(UNICODE_STRING));

				if ((pMbi->Type & (MEM_MAPPED | MEM_IMAGE)) != 0)
				{
					NTSTATUS ret = ::ZwQueryVirtualMemory(
						hProcess,
						pMbi->BaseAddress,
						(MEMORY_INFORMATION_CLASS)MemoryMappedFilenameInformation,
						pPathBuffer,
						0x800,
						&nReturnedLength);

					if (NT_SUCCESS(ret) && (pPathBuffer->Length > 0) && (pPathBuffer->Buffer != nullptr))
					{
						nEntrySize += pPathBuffer->Length + 2; // Add NULL terminator for convenience
						nEntrySize += (sizeof(ULONG_PTR) - (nEntrySize % sizeof(ULONG_PTR)));
					}
				}

				pEntryBuffer = (PMEMORY_MAPPING_INFO_FULL)AllocateNonPagedPool(nEntrySize);

				if (pEntryBuffer != nullptr)
				{
					pEntryBuffer->Entry.Size = (ULONG)(nEntrySize - FIELD_OFFSET(MEMORY_MAPPING_INFO_FULL, Entry));
					pEntryBuffer->Entry.NameLength = pPathBuffer->Length;
					::memcpy((PVOID)(&pEntryBuffer->Entry.Information), pMbi, nUnitSize);

					if ((pPathBuffer->Length > 0) && (pPathBuffer->Buffer != nullptr))
						::memcpy(&pEntryBuffer->Entry.Filename, pPathBuffer->Buffer, pPathBuffer->Length);

					::ExAcquireFastMutex(&g_Manager.FastMutex);
					::InsertTailList(&g_Manager.ListHead, &pEntryBuffer->Link);
					g_Manager.NumberOfEntries++;
					g_Manager.TotalSize += pEntryBuffer->Entry.Size;
					::ExReleaseFastMutex(&g_Manager.FastMutex);
				}
			}

			::ExFreePoolWithTag(pPathBuffer, (ULONG)DRIVER_TAG);
		}
		else
		{
			ntstatus = STATUS_INSUFFICIENT_RESOURCES;
			KdPrint((DRIVER_PREFIX "Failed to allocate path buffer.\n"));
		}

		::ExFreePoolWithTag(pBasicInfo, (ULONG)DRIVER_TAG);
	} while (false);

	::ZwClose(hProcess);

	return ntstatus;
}


NTSTATUS ReadMemoryFromProcess(
	_In_ ULONG ProcessId,
	_In_ PVOID BaseAddress,
	_In_ ULONG NumberOfBytesToRead,
	_Out_ PIOCTL_READ_MEMORY_OUTPUT *MemoryData)
{
	NTSTATUS ntstatus = STATUS_ACCESS_DENIED;
	HANDLE hProcess = NULL;
	PEPROCESS pEProcess = NULL;
	PUNICODE_STRING pPathBuffer = nullptr;
	OBJECT_ATTRIBUTES objectAttributes{ 0 };
	KAPC_STATE apcState{ 0 };
	auto clientId = CLIENT_ID{ ULongToHandle(ProcessId), NULL };
	InitializeObjectAttributes(
		&objectAttributes,
		nullptr,
		OBJ_KERNEL_HANDLE,
		NULL,
		nullptr);
	*MemoryData = nullptr;

	if (!IsUserAddress(BaseAddress))
		return STATUS_INVALID_ADDRESS;

	ntstatus = ::ZwOpenProcess(
		&hProcess,
		PROCESS_ALL_ACCESS,
		&objectAttributes,
		&clientId);

	if (!NT_SUCCESS(ntstatus))
	{
		KdPrint((DRIVER_PREFIX "Failed to get handle of the target process (NTSTATUS = 0x%08X).\n", ntstatus));
		return ntstatus;
	}

	ntstatus = ::PsLookupProcessByProcessId(ULongToHandle(ProcessId), &pEProcess);

	if (!NT_SUCCESS(ntstatus))
	{
		KdPrint((DRIVER_PREFIX "Failed to lookup EPROCESS for the target process (NTSTATUS = 0x%08X).\n", ntstatus));
		::ZwClose(hProcess);
		return ntstatus;
	}

	do
	{
		MEMORY_BASIC_INFORMATION mbi{ 0 };
		SIZE_T nReturnedLength = 0;
		ULONG nOutputBufferLength = FIELD_OFFSET(IOCTL_READ_MEMORY_OUTPUT, Filename) + NumberOfBytesToRead;
		ULONG nReadOffset = 0;
		ntstatus = ::ZwQueryVirtualMemory(
			hProcess,
			BaseAddress,
			MemoryBasicInformation,
			&mbi,
			sizeof(mbi),
			&nReturnedLength);

		if (!NT_SUCCESS(ntstatus))
		{
			KdPrint((DRIVER_PREFIX "Failed to query memory basic information (NTSTATUS = 0x%08X).\n", ntstatus));
			break;
		}

		nReadOffset = (ULONG)((ULONG_PTR)BaseAddress - (ULONG_PTR)mbi.BaseAddress);

		if ((NumberOfBytesToRead + nReadOffset) > (ULONG)mbi.RegionSize)
			NumberOfBytesToRead = (ULONG)mbi.RegionSize - nReadOffset;

		if ((mbi.Type & (MEM_MAPPED | MEM_IMAGE)) != 0)
		{
			GetMappedFilename(hProcess, BaseAddress, &pPathBuffer);

			if (pPathBuffer != nullptr)
			{
				nOutputBufferLength += pPathBuffer->Length + 2;
				nOutputBufferLength += (ULONG)(sizeof(ULONG_PTR) - (nOutputBufferLength % sizeof(ULONG_PTR)));
			}
		}

		*MemoryData = (PIOCTL_READ_MEMORY_OUTPUT)AllocateNonPagedPool((SIZE_T)nOutputBufferLength);

		if (*MemoryData == nullptr)
		{
			ntstatus = STATUS_INSUFFICIENT_RESOURCES;
			KdPrint((DRIVER_PREFIX "Failed to allocate output buffer.\n"));
			break;
		}

		(*MemoryData)->DataOffset = nOutputBufferLength - NumberOfBytesToRead;
		::memcpy(&(*MemoryData)->Information, &mbi, sizeof(mbi));

		if (pPathBuffer != nullptr)
		{
			(*MemoryData)->NameLength = pPathBuffer->Length;
			::memcpy(&(*MemoryData)->Filename, pPathBuffer->Buffer, pPathBuffer->Length);
		}

		::KeStackAttachProcess(pEProcess, &apcState);

		__try
		{
			auto pBufferToRead = (PVOID)((ULONG_PTR)(*MemoryData) + (*MemoryData)->DataOffset);
			::memcpy(pBufferToRead, BaseAddress, NumberOfBytesToRead);
			(*MemoryData)->Size = nOutputBufferLength + HandleToULong((HANDLE)nReturnedLength);
			(*MemoryData)->ReadBytes = NumberOfBytesToRead;
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			ntstatus = STATUS_ACCESS_VIOLATION;
			::ExFreePoolWithTag(*MemoryData, (ULONG)DRIVER_TAG);
			*MemoryData = nullptr;
			KdPrint((DRIVER_PREFIX "Failed to read memory (NTSTATUS = 0x%08X).\n", ntstatus));
		}

		::KeUnstackDetachProcess(&apcState);
	} while (false);

	if (pPathBuffer != nullptr)
		::ExFreePoolWithTag(pPathBuffer, (ULONG)DRIVER_TAG);

	ObDereferenceObject(pEProcess);
	::ZwClose(hProcess);

	return ntstatus;
}


VOID ReleaseMemoryInformationBuffer()
{
	::ExAcquireFastMutex(&g_Manager.FastMutex);

	while (g_Manager.ListHead.Flink != &g_Manager.ListHead)
	{
		auto pBufferToFree = ::RemoveHeadList(&g_Manager.ListHead);
		::ExFreePoolWithTag(pBufferToFree, DRIVER_TAG);
	}

	g_Manager.NumberOfEntries = 0;
	g_Manager.TotalSize = 0;

	::ExReleaseFastMutex(&g_Manager.FastMutex);
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

		if (pNonPagedPool)
			RtlZeroMemory(pNonPagedPool, nPoolSize);
	}

	return pNonPagedPool;
}


NTSTATUS GetMappedFilename(
	_In_ HANDLE ProcessHandle,
	_In_ PVOID BaseAddress,
	_Out_ PUNICODE_STRING *NameBuffer)
{
	NTSTATUS ntstatus = STATUS_UNSUCCESSFUL;
	SIZE_T nNameBufferSize = 0x400;
	SIZE_T nReturnedSize = 0;

	do
	{
		*NameBuffer = (PUNICODE_STRING)AllocateNonPagedPool(nNameBufferSize);

		if (*NameBuffer == nullptr)
		{
			ntstatus = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}

		ntstatus = ::ZwQueryVirtualMemory(
			ProcessHandle,
			BaseAddress,
			(MEMORY_INFORMATION_CLASS)MemoryMappedFilenameInformation,
			*NameBuffer,
			nNameBufferSize,
			&nReturnedSize);

		if (!NT_SUCCESS(ntstatus))
		{
			::ExFreePoolWithTag(*NameBuffer, DRIVER_TAG);
			*NameBuffer = nullptr;
			nNameBufferSize <<= 1;
		}
	} while (ntstatus == STATUS_BUFFER_OVERFLOW);

	return ntstatus;
}


NTSTATUS GetMemoryBasicInformation(
	_In_ HANDLE ProcessHandle,
	_Out_ PVOID *Buffer,
	_Out_ ULONG *Length)
{
	NTSTATUS ntstatus = STATUS_BUFFER_TOO_SMALL;
	PVOID pBaseAddress = nullptr;
	PVOID pInfoBuffer = nullptr;
	ULONG nInfoLength = 0x1000;
	ULONG nCurrentLength = 0;
	SIZE_T nUnitSize = sizeof(MEMORY_BASIC_INFORMATION);
	MEMORY_BASIC_INFORMATION mbi{ 0 };
	*Buffer = nullptr;
	*Length = 0;

	do
	{
		PVOID pEntryBuffer = nullptr;
		PVOID pNewInfoBuffer = nullptr;
		SIZE_T nReturnedLength = 0;
		ntstatus = ::ZwQueryVirtualMemory(
			ProcessHandle,
			pBaseAddress,
			MemoryBasicInformation,
			(PVOID)&mbi,
			nUnitSize,
			&nReturnedLength);

		if (!NT_SUCCESS(ntstatus))
			break;

		if (pInfoBuffer == nullptr)
			pInfoBuffer = AllocateNonPagedPool((SIZE_T)nInfoLength);

		if (pInfoBuffer == nullptr)
		{
			ntstatus = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}

		if ((nCurrentLength + (ULONG)nReturnedLength) > nInfoLength)
		{
			nInfoLength += 0x1000;
			pNewInfoBuffer = AllocateNonPagedPool((SIZE_T)nInfoLength);

			if (pNewInfoBuffer == nullptr)
			{
				::ExFreePoolWithTag(pInfoBuffer, (ULONG)DRIVER_TAG);
				pInfoBuffer = nullptr;
				ntstatus = STATUS_INSUFFICIENT_RESOURCES;
				break;
			}
			else
			{
				::memcpy(pNewInfoBuffer, pInfoBuffer, nCurrentLength);
				::ExFreePoolWithTag(pInfoBuffer, (ULONG)DRIVER_TAG);
				pInfoBuffer = pNewInfoBuffer;
			}
		}

		pEntryBuffer = (PVOID)((ULONG_PTR)pInfoBuffer + nCurrentLength);
		::memcpy(pEntryBuffer, &mbi, nReturnedLength);
		nCurrentLength += (ULONG)nReturnedLength;
		pBaseAddress = (PVOID)((ULONG_PTR)pBaseAddress + mbi.RegionSize);
	} while (NT_SUCCESS(ntstatus));

	if (pInfoBuffer != nullptr)
	{
		*Buffer = pInfoBuffer;
		*Length = nCurrentLength;
		ntstatus = STATUS_SUCCESS;
	}

	return ntstatus;
}


PVOID GetPebAddress(_In_ HANDLE ProcessHandle, _Out_ PVOID *Peb32)
{
	PVOID pPeb = nullptr;
	PROCESS_BASIC_INFORMATION pbi{ 0 };
	ULONG nReturnedLength = 0;
	NTSTATUS ntstatus = ZwQueryInformationProcess(
		ProcessHandle,
		ProcessBasicInformation,
		&pbi,
		sizeof(pbi),
		&nReturnedLength);
	*Peb32 = nullptr;

	if (NT_SUCCESS(ntstatus))
	{
		PVOID pPeb32 = nullptr;
		pPeb = pbi.PebBaseAddress;
		ntstatus = ZwQueryInformationProcess(
			ProcessHandle,
			ProcessWow64Information,
			&pPeb32,
			sizeof(PVOID),
			&nReturnedLength);

		if (NT_SUCCESS(ntstatus))
			*Peb32 = pPeb32;
	}

	return pPeb;
}


BOOLEAN IsUserAddress(_In_ PVOID BaseAddress)
{
	return (((ULONG_PTR)BaseAddress & 0xFFFF800000000000) == 0);
}