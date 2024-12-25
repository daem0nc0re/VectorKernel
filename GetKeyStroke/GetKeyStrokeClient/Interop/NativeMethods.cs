using System;
using System.Runtime.InteropServices;

namespace GetKeyStrokeClient.Interop
{
    using NTSTATUS = Int32;

    internal class NativeMethods
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool FileTimeToSystemTime(
            in LARGE_INTEGER lpFileTime,
            out SYSTEMTIME lpSystemTime);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtClose(IntPtr Handle);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtCreateEvent(
            out IntPtr EventHandle,
            ACCESS_MASK DesiredAccess,
            IntPtr /* in POBJECT_ATTRIBUTES */ ObjectAttributes,
            EVENT_TYPE EventType,
            BOOLEAN InitialState);

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
        public static extern NTSTATUS NtQueryInformationFile(
            IntPtr FileHandle,
            out IO_STATUS_BLOCK IoStatusBlock,
            IntPtr FileInformation,
            uint Length,
            FILE_INFORMATION_CLASS FileInformationClass);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtReadFile(
            IntPtr FileHandle,
            IntPtr Event,
            IntPtr /* PIO_APC_ROUTINE */ ApcRoutine,
            IntPtr ApcContext,
            out IO_STATUS_BLOCK IoStatusBlock,
            IntPtr Buffer,
            uint Length,
            IntPtr /* PLARGE_INTEGER */ ByteOffset,
            IntPtr /* PULONG */ Key);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtReadFile(
            IntPtr FileHandle,
            IntPtr Event,
            IntPtr /* PIO_APC_ROUTINE */ ApcRoutine,
            IntPtr ApcContext,
            out IO_STATUS_BLOCK IoStatusBlock,
            IntPtr Buffer,
            uint Length,
            in LARGE_INTEGER ByteOffset,
            IntPtr /* PULONG */ Key);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtNotifyChangeDirectoryFile(
            IntPtr FileHandle,
            IntPtr Event,
            IntPtr /* PIO_APC_ROUTINE */ ApcRoutine,
            IntPtr ApcContext,
            out IO_STATUS_BLOCK IoStatusBlock,
            IntPtr Buffer, // FILE_NOTIFY_INFORMATION
            uint Length,
            FILE_NOTIFY_CHANGE_FLAGS CompletionFilter,
            BOOLEAN WatchTree);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtSetEvent(
            IntPtr EventHandle,
            out uint PreviousState);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtWaitForSingleObject(
            IntPtr Handle,
            BOOLEAN Alertable,
            IntPtr Timeout);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtWaitForSingleObject(
            IntPtr Handle,
            BOOLEAN Alertable,
            in LARGE_INTEGER Timeout);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool SetConsoleCtrlHandler(
            IntPtr /* PHANDLER_ROUTINE */ HandlerRoutine,
            bool Add);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool SystemTimeToTzSpecificLocalTime(
            IntPtr lpTimeZoneInformation,
            in SYSTEMTIME lpUniversalTime,
            out SYSTEMTIME lpLocalTime);
    }
}
