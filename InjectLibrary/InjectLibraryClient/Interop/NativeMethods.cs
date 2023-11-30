using System;
using System.Runtime.InteropServices;

namespace InjectLibraryClient.Interop
{
    using NTSTATUS = Int32;

    internal class NativeMethods
    {
        /*
         * kernel32.dll
         */
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool CreateProcess(
            string lpApplicationName,
            string lpCommandLine,
            IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes,
            bool bInheritHandles,
            PROCESS_CREATION_FLAGS dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            in STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);

        /*
         * ntdll.dll
         */
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
        public static extern NTSTATUS NtResumeThread(IntPtr ThreadHandle, out uint SuspendCount);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtTerminateProcess(IntPtr ProcessHandle, NTSTATUS ExitStatus);
    }
}
