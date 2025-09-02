#include <fltkernel.h>

#define DRIVER_PREFIX "FileDirHideDrv: "
#define DEVICE_PATH L"\\Device\\FileDirHide"
#define SYMLINK_PATH L"\\??\\FileDirHide"
#define DRIVER_TAG 'lnKV'

#define IOCTL_LIST_REGISTERED_FILEDIR CTL_CODE(0x8000, 0x0E00, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_REGISTER_FILEDIR CTL_CODE(0x8000, 0x0E01, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_REMOVE_ALL_REGISTERED_FILEDIR CTL_CODE(0x8000, 0x0E02, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_REMOVE_REGISTERED_FILEDIR CTL_CODE(0x8000, 0x0E03, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define MAXIMUM_FILE_DIRECTORY_ENTRIES 16

typedef struct _FILE_DIRECTORY_MANAGER
{
	LIST_ENTRY ListHead; // Link with HIDE_ENTRY.ListEntry
	PFLT_FILTER Filter;
	PDRIVER_OBJECT DriverObject;
	ULONG EntryCount;
	BOOLEAN IndexOccupiedStatus[MAXIMUM_FILE_DIRECTORY_ENTRIES];
	FAST_MUTEX FastMutex;
} FILE_DIRECTORY_MANAGER, * PFILE_DIRECTORY_MANAGER;

typedef struct _HIDE_ENTRY
{
	LIST_ENTRY ListEntry;
	ULONG Index;
	ULONG ParentPathLength;
	UNICODE_STRING Path;
	WCHAR PathBytes[ANY_SIZE];
} HIDE_ENTRY, * PHIDE_ENTRY;

//
// Struct for IOCTL code
//
typedef struct _LIST_FILEDIR_ENTRIES_OUTPUT
{
	ULONG Index;
	ULONG PathBytesLength;
	ULONG NextOffset;
	WCHAR Path[ANY_SIZE];
} LIST_FILEDIR_ENTRIES_OUTPUT, * PLIST_FILEDIR_ENTRIES_OUTPUT;

typedef struct _LIST_FILEDIR_ENTRIES_OUTPUT_EX
{
	ULONG Count;
	LIST_FILEDIR_ENTRIES_OUTPUT Entries[ANY_SIZE];
} LIST_FILEDIR_ENTRIES_OUTPUT_EX, * PLIST_FILEDIR_ENTRIES_OUTPUT_EX;

typedef struct _REGISTER_FILEDIR_ENTRY_INPUT
{
	ULONG PathBytesLength;
	WCHAR Path[ANY_SIZE];
} REGISTER_FILEDIR_ENTRY_INPUT, * PREGISTER_FILEDIR_ENTRY_INPUT;

typedef struct _REGISTER_FILEDIR_ENTRY_OUTPUT
{
	ULONG Index;
} REGISTER_FILEDIR_ENTRY_OUTPUT, * PREGISTER_FILEDIR_ENTRY_OUTPUT;

typedef struct _REMOVE_FILEDIR_ENTRY_INPUT
{
	ULONG Index;
} REMOVE_FILEDIR_ENTRY_INPUT, * PREMOVE_FILEDIR_ENTRY_INPUT;

//
// Prototypes
//
NTSTATUS OnCreateClose(
	_Inout_ PDEVICE_OBJECT DeviceObject,
	_Inout_ PIRP Irp
);
NTSTATUS OnDeviceControl(
	_Inout_ PDEVICE_OBJECT DeviceObject,
	_Inout_ PIRP Irp
);
NTSTATUS ListFileDirectoryEntry(
	_Out_ PVOID OutputBuffer,
	_Inout_ PULONG OutputBufferLength
);
NTSTATUS RegisterFileDirectoryEntry(
	_In_ PWCHAR Path,
	_In_ ULONG PathBytesLength,
	_Out_ PULONG RegisteredIndex
);
VOID RemoveAllFileDierctoryEntries();
NTSTATUS RemoveFileDirectoryEntry(_In_ ULONG IndexToRemove);
NTSTATUS InitMiniFilter(
	_In_ PDRIVER_OBJECT DriverObject,
	_In_ PUNICODE_STRING RegistryPath
);
NTSTATUS FilterUnload(FLT_FILTER_UNLOAD_FLAGS Flags);
FLT_POSTOP_CALLBACK_STATUS OnPostDirectoryControl(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_opt_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
);
PVOID AllocateNonPagedPool(_In_ SIZE_T PoolSize);
VOID GetFileInformationDefinitionByClass(
	_In_ FILE_INFORMATION_CLASS Class,
	_Out_ PFILE_INFORMATION_DEFINITION Information
);
ULONG GetParentDirectoryPathLength(_In_ PWCHAR BasePathName);
NTSTATUS SetMiniFilterRegistry(
	_In_ PUNICODE_STRING RegistryPath,
	_In_ PUNICODE_STRING DefaultInstanceValue,
	_In_ PUNICODE_STRING AltitudeValue
);

//
// Function Type Definition
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
// API Address Storage
//
PExAllocatePool2 g_ExAllocatePool2 = nullptr;
PExAllocatePoolWithTag g_ExAllocatePoolWithTag = nullptr;

//
// Global Variables
//
FILE_DIRECTORY_MANAGER g_Manager = { 0 };
UNICODE_STRING g_DefaultInstance = RTL_CONSTANT_STRING(L"FileDirHide DefaultInstance");
UNICODE_STRING g_Altitude = RTL_CONSTANT_STRING(L"420000");
FLT_OPERATION_REGISTRATION const g_Callbacks[] =
{
	{ IRP_MJ_DIRECTORY_CONTROL, 0, nullptr, OnPostDirectoryControl },
	{ IRP_MJ_OPERATION_END }
};
FLT_REGISTRATION const g_FltRegister =
{
	sizeof(FLT_REGISTRATION),
	FLT_REGISTRATION_VERSION,
	0,
	nullptr,
	g_Callbacks,
	FilterUnload,
	nullptr,
	nullptr,
	nullptr,
	nullptr
};

//
// Driver Entry
//
extern "C"
NTSTATUS DriverEntry(
	_In_ PDRIVER_OBJECT  DriverObject,
	_In_ PUNICODE_STRING RegistryPath)
{
	NTSTATUS ntstatus = STATUS_UNSUCCESSFUL;
	UNICODE_STRING symLink = RTL_CONSTANT_STRING(SYMLINK_PATH);
	PDEVICE_OBJECT deviceObject = nullptr;
	bool bSymLinkCreated = false;

	KdPrint((DRIVER_PREFIX "Manager object is at 0x%p.\n", &g_Manager));

	do
	{
		UNICODE_STRING deviceName = RTL_CONSTANT_STRING(DEVICE_PATH);
		UNICODE_STRING routineName{ 0 };

		::RtlInitUnicodeString(&routineName, L"ExAllocatePool2");
		g_ExAllocatePool2 = (PExAllocatePool2)::MmGetSystemRoutineAddress(&routineName);

		if (g_ExAllocatePool2 == nullptr)
		{
			KdPrint((DRIVER_PREFIX "Failed to resolve ExAllocatePool2() API. Trying to resolve ExAllocatePoolWithTag() API.\n"));
			::RtlInitUnicodeString(&routineName, L"ExAllocatePoolWithTag");
			g_ExAllocatePoolWithTag = (PExAllocatePoolWithTag)::MmGetSystemRoutineAddress(&routineName);
		}

		if (g_ExAllocatePool2)
		{
			KdPrint((DRIVER_PREFIX "ExAllocatePool2() API is at 0x%p.\n", (PVOID)g_ExAllocatePool2));
		}
		else if (g_ExAllocatePoolWithTag)
		{
			KdPrint((DRIVER_PREFIX "ExAllocatePoolWithTag() API is at 0x%p.\n", (PVOID)g_ExAllocatePoolWithTag));
		}
		else
		{
			KdPrint((DRIVER_PREFIX "Failed to resolve ExAllocatePool2() API and ExAllocatePoolWithTag() API.\n"));
			break;
		}

		::InitializeListHead(&g_Manager.ListHead);
		::ExInitializeFastMutex(&g_Manager.FastMutex);
		ntstatus = InitMiniFilter(DriverObject, RegistryPath);

		if (!NT_SUCCESS(ntstatus))
		{
			KdPrint((DRIVER_PREFIX "Failed to initialize mini-filter (NTSTATUS = 0x%08X).\n", ntstatus));
			break;
		}

		ntstatus = ::IoCreateDevice(
			DriverObject,
			0,
			&deviceName,
			FILE_DEVICE_UNKNOWN,
			0,
			FALSE,
			&deviceObject);

		if (!NT_SUCCESS(ntstatus))
		{
			deviceObject = nullptr;
			KdPrint((DRIVER_PREFIX "Failed to create device (NTSTATUS = 0x%08X).\n", ntstatus));
			break;
		}

		ntstatus = ::IoCreateSymbolicLink(&symLink, &deviceName);

		if (!NT_SUCCESS(ntstatus))
		{
			KdPrint((DRIVER_PREFIX "Failed to create symbolic link (NTSTATUS = 0x%08X).\n", ntstatus));
			break;
		}

		bSymLinkCreated = true;
		ntstatus = ::FltStartFiltering(g_Manager.Filter);

		if (!NT_SUCCESS(ntstatus))
		{
			KdPrint((DRIVER_PREFIX "Failed to start filter (NTSTATUS = 0x%08X).\n", ntstatus));
			break;
		}

		DriverObject->MajorFunction[IRP_MJ_CREATE] = OnCreateClose;
		DriverObject->MajorFunction[IRP_MJ_CLOSE] = OnCreateClose;
		DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = OnDeviceControl;
		g_Manager.DriverObject = DriverObject;
	} while (false);

	if (!NT_SUCCESS(ntstatus))
	{
		if (g_Manager.Filter)
			::FltUnregisterFilter(g_Manager.Filter);

		if (bSymLinkCreated)
			::IoDeleteSymbolicLink(&symLink);

		if (deviceObject)
			::IoDeleteDevice(deviceObject);
	}

	return ntstatus;
}

//
// Major Functions
//
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
	case IOCTL_LIST_REGISTERED_FILEDIR:
	{
		PVOID pOutputBuffer = Irp->AssociatedIrp.SystemBuffer;
		ULONG nOutputBufferLength = dic.OutputBufferLength;
		ntstatus = ListFileDirectoryEntry(pOutputBuffer, &nOutputBufferLength);
		info = nOutputBufferLength;

		KdPrint((DRIVER_PREFIX "IOCTL_LIST_REGISTERED_FILEDIR: NTSTATUS = 0x%08X.\n", ntstatus));

		break;
	}
	case IOCTL_REGISTER_FILEDIR:
	{
		auto pRegisterInput = (PREGISTER_FILEDIR_ENTRY_INPUT)Irp->AssociatedIrp.SystemBuffer;
		ULONG nBaseInputSize = FIELD_OFFSET(REGISTER_FILEDIR_ENTRY_INPUT, Path);
		ULONG nInputBufferLength = dic.InputBufferLength;
		ULONG nOutputBufferLength = dic.OutputBufferLength;
		REGISTER_FILEDIR_ENTRY_OUTPUT registerOutput = { 0 };

		if (nOutputBufferLength < sizeof(REGISTER_FILEDIR_ENTRY_OUTPUT))
		{
			ntstatus = STATUS_BUFFER_TOO_SMALL;
		}
		else if (nInputBufferLength < (nBaseInputSize + pRegisterInput->PathBytesLength))
		{
			ntstatus = STATUS_INVALID_PARAMETER;
		}
		else
		{
			ntstatus = RegisterFileDirectoryEntry(
				(PWCHAR)&pRegisterInput->Path,
				pRegisterInput->PathBytesLength,
				&registerOutput.Index);
			info = registerOutput.Index;
			::memcpy((PVOID)pRegisterInput, &registerOutput, sizeof(REGISTER_FILEDIR_ENTRY_OUTPUT));
		}

		KdPrint((DRIVER_PREFIX "IOCTL_REGISTER_FILEDIR: NTSTATUS = 0x%08X.\n", ntstatus));

		break;
	}
	case IOCTL_REMOVE_ALL_REGISTERED_FILEDIR:
	{
		RemoveAllFileDierctoryEntries();
		ntstatus = STATUS_SUCCESS;

		KdPrint((DRIVER_PREFIX "IOCTL_REMOVE_ALL_REGISTERED_FILEDIR: NTSTATUS = 0x%08X.\n", ntstatus));

		break;
	}
	case IOCTL_REMOVE_REGISTERED_FILEDIR:
	{
		auto removeInput = (PREMOVE_FILEDIR_ENTRY_INPUT)Irp->AssociatedIrp.SystemBuffer;
		ntstatus = RemoveFileDirectoryEntry(removeInput->Index);

		KdPrint((DRIVER_PREFIX "IOCTL_REMOVE_REGISTERED_FILEDIR: NTSTATUS = 0x%08X.\n", ntstatus));

		break;
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
NTSTATUS ListFileDirectoryEntry(
	_Out_ PVOID OutputBuffer,
	_Inout_ PULONG OutputBufferLength)
{
	NTSTATUS ntstatus = STATUS_SUCCESS;
	ULONG nEntryOffset = FIELD_OFFSET(LIST_FILEDIR_ENTRIES_OUTPUT_EX, Entries);
	ULONG nRequiredBufferLength = nEntryOffset;

	if ((OutputBuffer == nullptr) || (OutputBufferLength == nullptr))
		return STATUS_INVALID_PARAMETER;

	if (*OutputBufferLength < nEntryOffset)
		return STATUS_BUFFER_TOO_SMALL;

	::ExAcquireFastMutex(&g_Manager.FastMutex);

	do
	{
		auto pIoctlListEntryEx = (PLIST_FILEDIR_ENTRIES_OUTPUT_EX)OutputBuffer;
		ULONG_PTR pBufferToWrite = (ULONG_PTR)OutputBuffer + nEntryOffset;
		PLIST_ENTRY pCurrentEntry = g_Manager.ListHead.Flink;
		::memset(OutputBuffer, 0, *OutputBufferLength);

		while (pCurrentEntry != &g_Manager.ListHead)
		{
			nRequiredBufferLength += FIELD_OFFSET(LIST_FILEDIR_ENTRIES_OUTPUT, Path);
			nRequiredBufferLength += ((PHIDE_ENTRY)pCurrentEntry)->Path.MaximumLength;
			pCurrentEntry = pCurrentEntry->Flink;
		}

		if (nRequiredBufferLength > *OutputBufferLength)
		{
			KdPrint((DRIVER_PREFIX "Output buffer is too small. Requrired buffer size is 0x%x bytes.\n",
				nRequiredBufferLength));
			ntstatus = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		pCurrentEntry = g_Manager.ListHead.Flink;
		pIoctlListEntryEx->Count = 0;

		while (pCurrentEntry != &g_Manager.ListHead)
		{
			auto pIoctlListEntry = (PLIST_FILEDIR_ENTRIES_OUTPUT)pBufferToWrite;
			auto pEntryBuffer = (PHIDE_ENTRY)pCurrentEntry;
			ULONG nPathBufferLength = pEntryBuffer->Path.MaximumLength;
			ULONG nBlockSize = FIELD_OFFSET(LIST_FILEDIR_ENTRIES_OUTPUT, Path) + nPathBufferLength;

			pIoctlListEntry->Index = pEntryBuffer->Index;
			pIoctlListEntry->PathBytesLength = pEntryBuffer->Path.Length;
			pIoctlListEntry->NextOffset = nBlockSize;
			::memcpy(
				(PVOID)&pIoctlListEntry->Path,
				pEntryBuffer->Path.Buffer,
				pEntryBuffer->Path.Length);

			pBufferToWrite += nBlockSize;
			pIoctlListEntryEx->Count++;
			pCurrentEntry = pCurrentEntry->Flink;
		}
	} while (false);

	*OutputBufferLength = nRequiredBufferLength;
	::ExReleaseFastMutex(&g_Manager.FastMutex);

	return ntstatus;
}


NTSTATUS RegisterFileDirectoryEntry(
	_In_ PWCHAR Path,
	_In_ ULONG PathBytesLength,
	_Out_ PULONG RegisteredIndex)
{
	NTSTATUS ntstatus = STATUS_SUCCESS;
	ULONG nEntryIndex = (ULONG)-1;

	if (RegisteredIndex == nullptr)
		return STATUS_INVALID_PARAMETER;

	::ExAcquireFastMutex(&g_Manager.FastMutex);

	do
	{
		PHIDE_ENTRY pEntryBuffer = nullptr;
		// Add a NULL byte at the end of entry
		ULONG nEntrySize = FIELD_OFFSET(HIDE_ENTRY, PathBytes) + PathBytesLength + sizeof(WCHAR);
		ULONG nReminder = nEntrySize % sizeof(ULONG_PTR);

		// Adjust memory alignment
		if (nReminder != 0)
			nEntrySize += sizeof(ULONG_PTR) - nReminder;

		if (g_Manager.EntryCount > MAXIMUM_FILE_DIRECTORY_ENTRIES)
		{
			KdPrint((DRIVER_PREFIX "File/Directory list was reached to maximum.\n"));
			ntstatus = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}

		for (ULONG nIndex = 0; nIndex < MAXIMUM_FILE_DIRECTORY_ENTRIES; nIndex++)
		{
			if (!g_Manager.IndexOccupiedStatus[nIndex])
			{
				nEntryIndex = nIndex;
				break;
			}
		}

		if (nEntryIndex == (ULONG)-1)
		{
			KdPrint((DRIVER_PREFIX "Failed to specify index for new entry.\n"));
			ntstatus = STATUS_NOT_FOUND;
			break;
		}

		pEntryBuffer = (PHIDE_ENTRY)AllocateNonPagedPool(nEntrySize);

		if (pEntryBuffer == nullptr)
		{
			KdPrint((DRIVER_PREFIX "Failed to allocate memory for HIDE_ENTRY.\n"));
			ntstatus = STATUS_NO_MEMORY;
			break;
		}

		// Build HIDE_ENTRY struct
		pEntryBuffer->Index = nEntryIndex;
		pEntryBuffer->Path.Length = (USHORT)PathBytesLength;
		pEntryBuffer->Path.MaximumLength = (USHORT)(nEntrySize - FIELD_OFFSET(HIDE_ENTRY, PathBytes));
		pEntryBuffer->Path.Buffer = (PWCHAR)&pEntryBuffer->PathBytes;
		::memcpy(pEntryBuffer->Path.Buffer, Path, PathBytesLength);
		pEntryBuffer->ParentPathLength = GetParentDirectoryPathLength(pEntryBuffer->Path.Buffer);

		// Link HIDE_ENTRY struct
		::InsertTailList(&g_Manager.ListHead, &pEntryBuffer->ListEntry);
		g_Manager.IndexOccupiedStatus[nEntryIndex] = TRUE;
		g_Manager.EntryCount++;
		KdPrint((DRIVER_PREFIX "An entry is registered successfuly (Index = %u, Path = %wZ).\n",
			nEntryIndex,
			&pEntryBuffer->Path));
	} while (false);

	*RegisteredIndex = nEntryIndex;
	::ExReleaseFastMutex(&g_Manager.FastMutex);

	return ntstatus;
}


VOID RemoveAllFileDierctoryEntries()
{
	::ExAcquireFastMutex(&g_Manager.FastMutex);

	while (g_Manager.ListHead.Flink != &g_Manager.ListHead)
	{
		auto pBufferToFree = ::RemoveHeadList(&g_Manager.ListHead);
		::ExFreePoolWithTag(pBufferToFree, DRIVER_TAG);
		g_Manager.EntryCount--;
	}

	for (auto nIndex = 0; nIndex < MAXIMUM_FILE_DIRECTORY_ENTRIES; nIndex++)
		g_Manager.IndexOccupiedStatus[nIndex] = FALSE;

	KdPrint((DRIVER_PREFIX "Removed all entries (Count = %u).\n", g_Manager.EntryCount));
	::ExReleaseFastMutex(&g_Manager.FastMutex);
}


NTSTATUS RemoveFileDirectoryEntry(_In_ ULONG IndexToRemove)
{
	NTSTATUS ntstatus = STATUS_SUCCESS;
	::ExAcquireFastMutex(&g_Manager.FastMutex);

	do
	{
		ULONG nEntryIndex = (ULONG)-1;
		PLIST_ENTRY pCurrentEntry = g_Manager.ListHead.Flink;

		while (pCurrentEntry != &g_Manager.ListHead)
		{
			ULONG nCurrentIndex = ((PHIDE_ENTRY)pCurrentEntry)->Index;

			if (nCurrentIndex == IndexToRemove)
			{
				nEntryIndex = nCurrentIndex;
				break;
			}

			pCurrentEntry = pCurrentEntry->Flink;
		}

		if (nEntryIndex == (ULONG)-1)
		{
			KdPrint((DRIVER_PREFIX "Failed to find the specified index.\n"));
			ntstatus = STATUS_NOT_FOUND;
			break;
		}

		::RemoveEntryList(pCurrentEntry);
		::ExFreePoolWithTag(pCurrentEntry, DRIVER_TAG);
		g_Manager.IndexOccupiedStatus[nEntryIndex] = FALSE;
		g_Manager.EntryCount--;
		KdPrint((DRIVER_PREFIX "An entry is removed successfuly (Index = %u).\n", nEntryIndex));
	} while (false);

	::ExReleaseFastMutex(&g_Manager.FastMutex);

	return ntstatus;
}

//
// Mini-Filter Routines
//
NTSTATUS InitMiniFilter(
	_In_ PDRIVER_OBJECT DriverObject,
	_In_ PUNICODE_STRING RegistryPath)
{
	NTSTATUS ntstatus = SetMiniFilterRegistry(
		RegistryPath,
		&g_DefaultInstance,
		&g_Altitude);

	if (!NT_SUCCESS(ntstatus))
	{
		KdPrint((DRIVER_PREFIX "Failed to set registry key.\n"));
	}
	else
	{
		ntstatus = ::FltRegisterFilter(
			DriverObject,
			&g_FltRegister,
			&g_Manager.Filter);
	}

	return ntstatus;
}


NTSTATUS FilterUnload(FLT_FILTER_UNLOAD_FLAGS Flags)
{
	UNREFERENCED_PARAMETER(Flags);
	UNICODE_STRING symLink = RTL_CONSTANT_STRING(SYMLINK_PATH);

	RemoveAllFileDierctoryEntries();
	::FltUnregisterFilter(g_Manager.Filter);
	::IoDeleteSymbolicLink(&symLink);
	::IoDeleteDevice(g_Manager.DriverObject->DeviceObject);

	return STATUS_SUCCESS;
};


FLT_POSTOP_CALLBACK_STATUS OnPostDirectoryControl(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_opt_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags)
{
	UNREFERENCED_PARAMETER(CompletionContext);

	if (Data->RequestorMode == KernelMode)
		return FLT_POSTOP_FINISHED_PROCESSING;

	if (Data->Iopb->MinorFunction != IRP_MN_QUERY_DIRECTORY)
		return FLT_POSTOP_FINISHED_PROCESSING;

	if (Flags & FLTFL_POST_OPERATION_DRAINING)
		return FLT_POSTOP_FINISHED_PROCESSING;

	auto& params = Data->Iopb->Parameters.DirectoryControl.QueryDirectory;
	POBJECT_NAME_INFORMATION pDosPath = nullptr;
	NTSTATUS ntstatus = ::IoQueryFileDosDeviceName(
		FltObjects->FileObject,
		&pDosPath);

	if (!NT_SUCCESS(ntstatus))
	{
		KdPrint((DRIVER_PREFIX "Failed to resolve post processing filename.\n"));
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	KdPrint((DRIVER_PREFIX "Received a query (Path: %wZ)\n", &pDosPath->Name));

	do
	{
		FILE_INFORMATION_DEFINITION info;
		ULONG nCount = 0;
		ULONG nNextOffset = 0;
		PVOID pPreviousEntry = nullptr;
		PVOID pDataBuffer = nullptr;
		PHIDE_ENTRY pPathToHide[MAXIMUM_FILE_DIRECTORY_ENTRIES] = { nullptr };
		UNICODE_STRING rootDirectory = { 0 };
		auto pCurrentEntry = (PHIDE_ENTRY)g_Manager.ListHead.Flink;

		GetFileInformationDefinitionByClass(params.FileInformationClass, &info);

		if (info.Class == 0)
		{
			KdPrint((DRIVER_PREFIX "Invalid FileInformationClass is detected (FileInformationClass = %d).\n",
				(LONG)params.FileInformationClass));
			break;
		}

		if (params.MdlAddress)
			pDataBuffer = ::MmGetSystemAddressForMdlSafe(params.MdlAddress, NormalPagePriority);
		else
			pDataBuffer = params.DirectoryBuffer;

		if (pDataBuffer == nullptr)
			break;

		while ((PLIST_ENTRY)pCurrentEntry != &g_Manager.ListHead)
		{
			UNICODE_STRING directoryPath = { 0 };
			directoryPath.Length = (USHORT)pCurrentEntry->ParentPathLength;

			if (directoryPath.Length != (sizeof(WCHAR) * 3)) // Case for non-root directory path
				directoryPath.Length -= sizeof(WCHAR);

			directoryPath.MaximumLength = directoryPath.Length;
			directoryPath.Buffer = pCurrentEntry->Path.Buffer;

			if (::RtlEqualUnicodeString(&directoryPath, &pDosPath->Name, TRUE))
			{
				pPathToHide[nCount] = pCurrentEntry;
				nCount++;
			}

			pCurrentEntry = (PHIDE_ENTRY)pCurrentEntry->ListEntry.Flink;
		}

		if (nCount == 0)
			break;

		do
		{
			auto filename = (PWSTR)((ULONG_PTR)pDataBuffer + info.FileNameOffset);
			auto nFileNameLength = *(ULONG*)((ULONG_PTR)pDataBuffer + info.FileNameLengthOffset);
			nNextOffset = *(ULONG*)((ULONG_PTR)pDataBuffer + info.NextEntryOffset);

			for (ULONG nIndex = 0; nIndex < nCount; nIndex++)
			{
				if (nFileNameLength == 0)
					break;

				auto pNameToHide = (PWSTR)((ULONG_PTR)pPathToHide[nIndex]->Path.Buffer + pPathToHide[nIndex]->ParentPathLength);

				if (::_wcsnicmp(pNameToHide, filename, nFileNameLength / sizeof(WCHAR)) == 0)
				{
					if (pPreviousEntry == nullptr) // Top entry
					{
						params.DirectoryBuffer = (PVOID)((ULONG_PTR)pDataBuffer + nNextOffset);
						::FltSetCallbackDataDirty(Data);
					}
					else if (nNextOffset == 0) // Last entry
					{
						*(ULONG*)((ULONG_PTR)pPreviousEntry + info.NextEntryOffset) = 0;
					}
					else // Intermediate entry
					{
						*(ULONG*)((ULONG_PTR)pPreviousEntry + info.NextEntryOffset) += nNextOffset;
					}
				}
			}

			pPreviousEntry = pDataBuffer;
			pDataBuffer = (PVOID)((ULONG_PTR)pDataBuffer + nNextOffset);
		} while (nNextOffset != 0);
	} while (false);

	ExFreePool(pDosPath);

	return FLT_POSTOP_FINISHED_PROCESSING;
}


//
// Helper functions
//
PVOID AllocateNonPagedPool(_In_ SIZE_T PoolSize)
{
	PVOID pNonPagedPool = nullptr;

	// ExAllocatePool2 API was introduced from Windows 10 2004.
	// Use ExAllocatePoolWithTag API on old OSes.
	if (g_ExAllocatePool2)
	{
		pNonPagedPool = g_ExAllocatePool2(
			POOL_FLAG_NON_PAGED,
			PoolSize,
			(ULONG)DRIVER_TAG);
	}
	else if (g_ExAllocatePoolWithTag)
	{
		pNonPagedPool = g_ExAllocatePoolWithTag(
			NonPagedPool,
			PoolSize,
			(ULONG)DRIVER_TAG);

		if (pNonPagedPool)
			::memset(pNonPagedPool, 0, PoolSize);
	}

	return pNonPagedPool;
}


// Due to SDK coding failure, FILE_INFORMATION_DEFINITION struct definition 
// varies depending on the SDK version. It would cause coding failure when 
// using macro such as FileFullDirectoryInformationDefinition, so I don't 
// use it in this code.
VOID GetFileInformationDefinitionByClass(
	_In_ FILE_INFORMATION_CLASS Class,
	_Out_ PFILE_INFORMATION_DEFINITION Information)
{
	::memset(Information, 0, sizeof(FILE_INFORMATION_DEFINITION));

	// Reference:
	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/flt-parameters-for-irp-mj-directory-control
	if (Class == FileFullDirectoryInformation)
	{
		Information->Class = Class;
		Information->NextEntryOffset = FIELD_OFFSET(FILE_FULL_DIR_INFORMATION, NextEntryOffset);
		Information->FileNameOffset = FIELD_OFFSET(FILE_FULL_DIR_INFORMATION, FileName);
		Information->FileNameLengthOffset = FIELD_OFFSET(FILE_FULL_DIR_INFORMATION, FileNameLength);
	}
	else if (Class == FileBothDirectoryInformation)
	{
		Information->Class = Class;
		Information->NextEntryOffset = FIELD_OFFSET(FILE_BOTH_DIR_INFORMATION, NextEntryOffset);
		Information->FileNameOffset = FIELD_OFFSET(FILE_BOTH_DIR_INFORMATION, FileName);
		Information->FileNameLengthOffset = FIELD_OFFSET(FILE_BOTH_DIR_INFORMATION, FileNameLength);
	}
	else if (Class == FileDirectoryInformation)
	{
		Information->Class = Class;
		Information->NextEntryOffset = FIELD_OFFSET(FILE_DIRECTORY_INFORMATION, NextEntryOffset);
		Information->FileNameOffset = FIELD_OFFSET(FILE_DIRECTORY_INFORMATION, FileName);
		Information->FileNameLengthOffset = FIELD_OFFSET(FILE_DIRECTORY_INFORMATION, FileNameLength);
	}
	else if (Class == FileNamesInformation)
	{
		Information->Class = Class;
		Information->NextEntryOffset = FIELD_OFFSET(FILE_NAMES_INFORMATION, NextEntryOffset);
		Information->FileNameOffset = FIELD_OFFSET(FILE_NAMES_INFORMATION, FileName);
		Information->FileNameLengthOffset = FIELD_OFFSET(FILE_NAMES_INFORMATION, FileNameLength);
	}
	else if (Class == FileIdFullDirectoryInformation)
	{
		Information->Class = Class;
		Information->NextEntryOffset = FIELD_OFFSET(FILE_ID_FULL_DIR_INFORMATION, NextEntryOffset);
		Information->FileNameOffset = FIELD_OFFSET(FILE_ID_FULL_DIR_INFORMATION, FileName);
		Information->FileNameLengthOffset = FIELD_OFFSET(FILE_ID_FULL_DIR_INFORMATION, FileNameLength);
	}
	else if (Class == FileIdBothDirectoryInformation)
	{
		Information->Class = Class;
		Information->NextEntryOffset = FIELD_OFFSET(FILE_ID_BOTH_DIR_INFORMATION, NextEntryOffset);
		Information->FileNameOffset = FIELD_OFFSET(FILE_ID_BOTH_DIR_INFORMATION, FileName);
		Information->FileNameLengthOffset = FIELD_OFFSET(FILE_ID_BOTH_DIR_INFORMATION, FileNameLength);
	}
	else if (Class == FileIdExtdDirectoryInformation)
	{
		Information->Class = Class;
		Information->NextEntryOffset = FIELD_OFFSET(FILE_ID_EXTD_DIR_INFORMATION, NextEntryOffset);
		Information->FileNameOffset = FIELD_OFFSET(FILE_ID_EXTD_DIR_INFORMATION, FileName);
		Information->FileNameLengthOffset = FIELD_OFFSET(FILE_ID_EXTD_DIR_INFORMATION, FileNameLength);
	}
	else if (Class == FileIdGlobalTxDirectoryInformation)
	{
		Information->Class = Class;
		Information->NextEntryOffset = FIELD_OFFSET(FILE_ID_GLOBAL_TX_DIR_INFORMATION, NextEntryOffset);
		Information->FileNameOffset = FIELD_OFFSET(FILE_ID_GLOBAL_TX_DIR_INFORMATION, FileName);
		Information->FileNameLengthOffset = FIELD_OFFSET(FILE_ID_GLOBAL_TX_DIR_INFORMATION, FileNameLength);
	}
}


ULONG GetParentDirectoryPathLength(_In_ PWCHAR BasePathName)
{
	auto pFinalDelimiter = ::wcsrchr(BasePathName, L'\\');

	if (pFinalDelimiter == nullptr)
		return 0u;

	return (ULONG)(pFinalDelimiter - BasePathName + 1) * sizeof(WCHAR);
}


NTSTATUS SetMiniFilterRegistry(
	_In_ PUNICODE_STRING RegistryPath,
	_In_ PUNICODE_STRING DefaultInstanceValue,
	_In_ PUNICODE_STRING AltitudeValue)
{
	HANDLE hKey = NULL;
	HANDLE hSubKey = NULL;
	NTSTATUS ntstatus = STATUS_UNSUCCESSFUL;
	WCHAR instanceName[128] = { 0 };
	WCHAR altitude[16] = { 0 };

	if (DefaultInstanceValue->Length > (sizeof(instanceName) - sizeof(WCHAR)))
	{
		KdPrint((DRIVER_PREFIX "DefaultInstance value for registry is too long.\n"));
		return STATUS_INVALID_PARAMETER;
	}

	if (AltitudeValue->Length > (sizeof(altitude) - sizeof(WCHAR)))
	{
		KdPrint((DRIVER_PREFIX "Altitude value for registry is too long.\n"));
		return STATUS_INVALID_PARAMETER;
	}

	::memcpy(instanceName, DefaultInstanceValue->Buffer, DefaultInstanceValue->Length);
	::memcpy(altitude, AltitudeValue->Buffer, AltitudeValue->Length);

	do
	{
		HANDLE hInstanceKey = NULL;
		UNICODE_STRING instanceKeyName = { 0 };
		UNICODE_STRING subkeyName = RTL_CONSTANT_STRING(L"Instances");
		UNICODE_STRING valueName = RTL_CONSTANT_STRING(L"DefaultInstance");
		OBJECT_ATTRIBUTES keyAttributes = RTL_CONSTANT_OBJECT_ATTRIBUTES(
			RegistryPath,
			OBJ_KERNEL_HANDLE);
		OBJECT_ATTRIBUTES subkeyAttributes = { 0 };

		ntstatus = ::ZwOpenKey(&hKey, KEY_WRITE, &keyAttributes);

		if (!NT_SUCCESS(ntstatus))
		{
			hKey = NULL;
			break;
		}

		InitializeObjectAttributes(
			&subkeyAttributes,
			&subkeyName,
			OBJ_KERNEL_HANDLE,
			hKey,
			nullptr);
		ntstatus = ::ZwCreateKey(
			&hSubKey,
			KEY_WRITE,
			&subkeyAttributes,
			0,
			nullptr,
			0,
			nullptr);

		if (!NT_SUCCESS(ntstatus))
		{
			hSubKey = NULL;
			break;
		}

		ntstatus = ::ZwSetValueKey(
			hSubKey,
			&valueName,
			0,
			REG_SZ,
			instanceName,
			DefaultInstanceValue->Length + sizeof(WCHAR));

		if (!NT_SUCCESS(ntstatus))
			break;

		InitializeObjectAttributes(
			&subkeyAttributes,
			DefaultInstanceValue,
			OBJ_KERNEL_HANDLE,
			hSubKey,
			nullptr);
		ntstatus = ::ZwCreateKey(
			&hInstanceKey,
			KEY_WRITE,
			&subkeyAttributes,
			0,
			nullptr,
			0,
			nullptr);

		if (!NT_SUCCESS(ntstatus))
			break;

		do
		{
			ULONG nFlags = 0;
			UNICODE_STRING altitudeName = RTL_CONSTANT_STRING(L"Altitude");
			UNICODE_STRING flagsName = RTL_CONSTANT_STRING(L"Flags");
			ntstatus = ::ZwSetValueKey(
				hInstanceKey,
				&altitudeName,
				0,
				REG_SZ,
				altitude,
				AltitudeValue->Length + sizeof(WCHAR));

			if (!NT_SUCCESS(ntstatus))
				break;

			ntstatus = ::ZwSetValueKey(
				hInstanceKey,
				&flagsName,
				0,
				REG_DWORD,
				&nFlags,
				sizeof(nFlags));
		} while (false);

		::ZwClose(hInstanceKey);
	} while (false);

	if (hSubKey)
	{
		if (!NT_SUCCESS(ntstatus))
			::ZwDeleteKey(hSubKey);

		::ZwClose(hSubKey);
	}

	if (hKey)
		::ZwClose(hKey);

	return ntstatus;
}
