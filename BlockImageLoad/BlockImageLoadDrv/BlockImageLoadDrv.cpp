#include <ntifs.h>

#define DRIVER_PREFIX "BlockImageLoad: "
#define DEVICE_PATH L"\\Device\\BlockImageLoad"
#define SYMLINK_PATH L"\\??\\BlockImageLoad"

//
// Ioctl code definition
//
#define IOCTL_SET_MODULE_BLOCK CTL_CODE(0x8000, 0x0C00, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_UNSET_MODULE_BLOCK CTL_CODE(0x8000, 0x0C01, METHOD_BUFFERED, FILE_ANY_ACCESS)

//
// Windows definition
//
typedef struct _IMAGE_DOS_HEADER
{
	USHORT e_magic;
	USHORT e_cblp;
	USHORT e_cp;
	USHORT e_crlc;
	USHORT e_cparhdr;
	USHORT e_minalloc;
	USHORT e_maxalloc;
	USHORT e_ss;
	USHORT e_sp;
	USHORT e_csum;
	USHORT e_ip;
	USHORT e_cs;
	USHORT e_lfarlc;
	USHORT e_ovno;
	USHORT e_res[4];
	USHORT e_oemid;
	USHORT e_oeminfo;
	USHORT e_res2[10];
	LONG e_lfanew;
} IMAGE_DOS_HEADER, * PIMAGE_DOS_HEADER;

typedef struct _IMAGE_FILE_HEADER
{
	SHORT Machine;
	SHORT NumberOfSections;
	LONG TimeDateStamp;
	LONG PointerToSymbolTable;
	LONG NumberOfSymbols;
	SHORT SizeOfOptionalHeader;
	SHORT Characteristics;
} IMAGE_FILE_HEADER, * PIMAGE_FILE_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY
{
	LONG VirtualAddress;
	LONG Size;
} IMAGE_DATA_DIRECTORY, * PIMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_OPTIONAL_HEADER64
{
	SHORT Magic;
	UCHAR MajorLinkerVersion;
	UCHAR MinorLinkerVersion;
	LONG SizeOfCode;
	LONG SizeOfInitializedData;
	LONG SizeOfUninitializedData;
	LONG AddressOfEntryPoint;
	LONG BaseOfCode;
	ULONG64 ImageBase;
	LONG SectionAlignment;
	LONG FileAlignment;
	SHORT MajorOperatingSystemVersion;
	SHORT MinorOperatingSystemVersion;
	SHORT MajorImageVersion;
	SHORT MinorImageVersion;
	SHORT MajorSubsystemVersion;
	SHORT MinorSubsystemVersion;
	LONG Win32VersionValue;
	LONG SizeOfImage;
	LONG SizeOfHeaders;
	LONG CheckSum;
	SHORT Subsystem;
	SHORT DllCharacteristics;
	ULONG64 SizeOfStackReserve;
	ULONG64 SizeOfStackCommit;
	ULONG64 SizeOfHeapReserve;
	ULONG64 SizeOfHeapCommit;
	LONG LoaderFlags;
	LONG NumberOfRvaAndSizes;
	IMAGE_DATA_DIRECTORY DataDirectory[16];
} IMAGE_OPTIONAL_HEADER, * PIMAGE_OPTIONAL_HEADER;

typedef struct _IMAGE_NT_HEADERS64
{
	LONG Signature;
	IMAGE_FILE_HEADER FileHeader;
	IMAGE_OPTIONAL_HEADER OptionalHeader;
} IMAGE_NT_HEADERS, * PIMAGE_NT_HEADERS;

//
// Custom sturct definition
//
typedef struct _MODULE_NAME
{
	WCHAR ImageFileName[256];
} MODULE_NAME, *PMODULE_NAME;

//
// Global variables
//
FAST_MUTEX g_FastMutex{ 0 };
struct : UNICODE_STRING { WCHAR buf[257]; } g_ImageFileName{ };
BOOLEAN g_Registered = FALSE;

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
void LoadImageBlockRoutine(
	_In_opt_ PUNICODE_STRING FullImageName,
	_In_ HANDLE ProcessId,
	_In_ PIMAGE_INFO ImageInfo
);
BOOLEAN WriteBytesToNonWritableBuffer(PVOID Dst, PVOID Src, SIZE_T Len);

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

		g_ImageFileName.Length = 0;
		g_ImageFileName.MaximumLength = sizeof(UCHAR) * 257;
		g_ImageFileName.Buffer = (PWCH)&g_ImageFileName.buf;
		::memset(&g_ImageFileName.buf, 0, sizeof(USHORT) * 257);

		::ExInitializeFastMutex(&g_FastMutex);

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

	if (g_Registered)
	{
		::PsRemoveLoadImageNotifyRoutine(LoadImageBlockRoutine);
		g_Registered = FALSE;
	}

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
	USHORT nStrLen = 0;

	switch (dic.IoControlCode)
	{
	case IOCTL_SET_MODULE_BLOCK:
		if (dic.InputBufferLength < sizeof(MODULE_NAME))
		{
			ntstatus = STATUS_BUFFER_TOO_SMALL;
			KdPrint((DRIVER_PREFIX "Input buffer is too small.\n"));
			break;
		}

		::ExAcquireFastMutex(&g_FastMutex);
		::memset(&g_ImageFileName.buf, 0, sizeof(USHORT) * 257);

		for (auto idx = 0; idx < 256; idx++)
		{
			if (((USHORT*)Irp->AssociatedIrp.SystemBuffer)[idx] == 0)
				break;
			else
				nStrLen += 2;
		}

		g_ImageFileName.Length = nStrLen + sizeof(USHORT);
		g_ImageFileName.buf[0] = L'\\';
		::memcpy(&g_ImageFileName.buf[1], Irp->AssociatedIrp.SystemBuffer, nStrLen);

		KdPrint((DRIVER_PREFIX "Block Filter - %wZ\n", &g_ImageFileName));

		if (!g_Registered)
		{
			ntstatus = ::PsSetLoadImageNotifyRoutine(LoadImageBlockRoutine);

			if (!NT_SUCCESS(ntstatus))
			{
				KdPrint((DRIVER_PREFIX "Failed to PsSetLoadImageNotifyRoutine() API (NTSTATUS = 0x%08X).\n", ntstatus));

				g_ImageFileName.Length = 0u;
				::memset(&g_ImageFileName.buf, 0, sizeof(USHORT) * 257);
			}
			else
			{
				KdPrint((DRIVER_PREFIX "PsSetLoadImageNotifyRoutine() API is successful.\n"));
				info = g_ImageFileName.Length;
				g_Registered = TRUE;
			}
		}
		else
		{
			ntstatus = STATUS_SUCCESS;
			info = g_ImageFileName.Length;
		}

		::ExReleaseFastMutex(&g_FastMutex);
		break;

	case IOCTL_UNSET_MODULE_BLOCK:
		::ExAcquireFastMutex(&g_FastMutex);

		if (g_Registered)
		{
			::PsRemoveLoadImageNotifyRoutine(LoadImageBlockRoutine);
			g_ImageFileName.Length = 0u;
			::memset(&g_ImageFileName.buf, 0, sizeof(USHORT) * 257);
			g_Registered = FALSE;
			ntstatus = STATUS_SUCCESS;

			KdPrint((DRIVER_PREFIX "Load Image Notify Callback is unregistered successfully.\n"));
		}
		else
		{
			KdPrint((DRIVER_PREFIX "Load Image Notify Callback is not registered.\n"));
		}

		::ExReleaseFastMutex(&g_FastMutex);
	}

	Irp->IoStatus.Status = ntstatus;
	Irp->IoStatus.Information = info;
	IoCompleteRequest(Irp, 0);

	return ntstatus;
}


//
// Load Image Notify Callback routines
//
void LoadImageBlockRoutine(
	_In_opt_ PUNICODE_STRING FullImageName,
	_In_ HANDLE ProcessId,
	_In_ PIMAGE_INFO ImageInfo)
{
#ifndef DBG
	UNREFERENCED_PARAMETER(ProcessId);
#endif

	if ((g_ImageFileName.Length == 0) || (FullImageName == nullptr) || (ImageInfo == nullptr))
		return;

	KdPrint((DRIVER_PREFIX "%wZ (PID %u) is loaded at 0x%p.\n", FullImageName, HandleToULong(ProcessId), ImageInfo->ImageBase));

	if (::RtlSuffixUnicodeString(&g_ImageFileName, FullImageName, TRUE) && (ImageInfo->ImageBase != nullptr))
	{
		BOOLEAN bOverwritten = FALSE;

		__try
		{
			auto e_lfanew = ((PIMAGE_DOS_HEADER)ImageInfo->ImageBase)->e_lfanew;
			auto pNtHeaders = (PIMAGE_NT_HEADERS)((ULONG_PTR)ImageInfo->ImageBase + e_lfanew);
			auto pEntryPoint = (PVOID)((ULONG_PTR)ImageInfo->ImageBase + pNtHeaders->OptionalHeader.AddressOfEntryPoint);
			UCHAR shellcode[] = { 0xB8, 0x22, 0x00, 0x00, 0xC0, 0xC3 }; // mov eax, 0xC0000022 (STATUS_ACCESS_DENIED); ret;

			bOverwritten = WriteBytesToNonWritableBuffer(pEntryPoint, shellcode, sizeof(shellcode));
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			KdPrint((DRIVER_PREFIX "Access violation in user space.\n"));
		}

		if (bOverwritten)
			KdPrint((DRIVER_PREFIX "Shellcode is written in entry point.\n"));
		else
			KdPrint((DRIVER_PREFIX "Failed to write shellcode.\n"));
	}
}


BOOLEAN WriteBytesToNonWritableBuffer(PVOID Dst, PVOID Src, SIZE_T Len)
{
	UNREFERENCED_PARAMETER(Src);
	PVOID pWritableMap = nullptr;
	BOOLEAN bLocked = FALSE;
	BOOLEAN bSuccess = FALSE;
	PMDL pMdl = ::IoAllocateMdl(Dst, (ULONG)Len, FALSE, FALSE, nullptr);

	if (pMdl == nullptr)
	{
		KdPrint((DRIVER_PREFIX "Failed to allocate MDL.\n"));
		return FALSE;
	}

	do
	{
		__try
		{
			::MmProbeAndLockPages(pMdl, KernelMode, IoModifyAccess);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			KdPrint((DRIVER_PREFIX "Failed to lock MDL.\n"));
			break;
		}

		bLocked = TRUE;
		pWritableMap = ::MmMapLockedPagesSpecifyCache(
			pMdl,
			KernelMode,
			MmCached,
			nullptr,
			FALSE,
			HighPagePriority | MdlMappingNoExecute);

		if (pWritableMap == nullptr)
		{
			KdPrint((DRIVER_PREFIX "Failed to get writable map.\n"));
			break;
		}

		::memcpy(pWritableMap, Src, Len);
		bSuccess = TRUE;
	} while (false);

	if (pWritableMap != nullptr)
		::MmUnmapLockedPages(pWritableMap, pMdl);

	if (pMdl != nullptr)
	{
		if (bLocked)
			::MmUnlockPages(pMdl);

		::IoFreeMdl(pMdl);
	}

	return bSuccess;
}