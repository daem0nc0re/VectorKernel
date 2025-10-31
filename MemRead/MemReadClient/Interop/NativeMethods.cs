using System;
using System.Runtime.InteropServices;

namespace MemReadClient.Interop
{
    using NTSTATUS = Int32;
    using SIZE_T = UIntPtr;

    internal class NativeMethods
    {
        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtAllocateVirtualMemory(
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            SIZE_T ZeroBits,
            ref SIZE_T RegionSize,
            MEMORY_ALLOCATION_TYPE AllocationType,
            MEMORY_PROTECTION Protect);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtClose(IntPtr Handle);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtCreateFile(
            out IntPtr FileHandle,
            ACCESS_MASK DesiredAccess,
            in OBJECT_ATTRIBUTES ObjectAttributes,
            out IO_STATUS_BLOCK IoStatusBlock,
            IntPtr /* PLARGE_INTEGER */ AllocationSize,
            FILE_ATTRIBUTE_FLAGS FileAttributes,
            FILE_SHARE_ACCESS ShareAccess,
            FILE_CREATE_DISPOSITION CreateDisposition,
            FILE_CREATE_OPTIONS CreateOptions,
            IntPtr EaBuffer,
            uint EaLength);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtDeviceIoControlFile(
            IntPtr FileHandle,
            IntPtr Event,
            IntPtr /* PIO_APC_ROUTINE */ ApcRoutine,
            IntPtr /* PVOID */ ApcContext,
            out IO_STATUS_BLOCK IoStatusBlock,
            uint IoControlCode,
            IntPtr InputBuffer,
            uint InputBufferLength,
            IntPtr OutputBuffer,
            uint OutputBufferLength);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtFreeVirtualMemory(
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            ref SIZE_T RegionSize,
            MEMORY_ALLOCATION_TYPE FreeType);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtOpenSymbolicLinkObject(
            out IntPtr LinkHandle,
            ACCESS_MASK DesiredAccess,
            in OBJECT_ATTRIBUTES ObjectAttributes);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtQueryInformationProcess(
            IntPtr ProcessHandle,
            PROCESSINFOCLASS ProcessInformationClass,
            IntPtr pProcessInformation,
            uint ProcessInformationLength,
            out uint ReturnLength);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtQuerySymbolicLinkObject(
            IntPtr LinkHandle,
            IntPtr /* PUNICODE_STRING */ LinkTarget,
            out uint ReturnedLength);
    }
}
