using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using InjectLibraryClient.Interop;

namespace InjectLibraryClient.Library
{
    using NTSTATUS = Int32;

    internal class Modules
    {
        public static bool InjectDllWithCommand(string command, string dllPath)
        {
            bool bSuccess;
            var startupInfo = new STARTUPINFO { cb = Marshal.SizeOf(typeof(STARTUPINFO)) };

            Console.WriteLine("[>] Trying to create test process.");
            Console.WriteLine("    [*] Command : {0}", command);

            bSuccess = NativeMethods.CreateProcess(
                null,
                command,
                IntPtr.Zero,
                IntPtr.Zero,
                false,
                PROCESS_CREATION_FLAGS.CREATE_NEW_CONSOLE | PROCESS_CREATION_FLAGS.CREATE_SUSPENDED,
                IntPtr.Zero,
                Environment.CurrentDirectory,
                in startupInfo,
                out PROCESS_INFORMATION processInfo);

            if (!bSuccess)
            {
                Console.WriteLine("[-] Failed to CreateProcess() API (Error = 0x{0}).", Marshal.GetLastWin32Error().ToString("X8"));
            }
            else
            {
                Console.WriteLine("[+] Got process for testing DLL injection (PID: {0}).", processInfo.dwProcessId);

                bSuccess = InjectDll(processInfo.dwThreadId, dllPath);

                if (bSuccess)
                    NativeMethods.NtResumeThread(processInfo.hThread, out uint _);
                else
                    NativeMethods.NtTerminateProcess(processInfo.hProcess, Win32Consts.STATUS_SUCCESS);
            }

            return bSuccess;
        }


        public static bool InjectDll(int threadId, string dllPath)
        {
            NTSTATUS ntstatus;
            IntPtr pInBuffer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(INJECT_CONTEXT)));
            var context = new INJECT_CONTEXT(threadId, Path.GetFullPath(dllPath));

            Console.WriteLine("[*] Injection target information:");
            Console.WriteLine("    [*] Thread ID    : {0}", context.ThreadId);
            Console.WriteLine("    [*] Library Path : {0}", Encoding.Unicode.GetString(context.LibraryPath).TrimEnd('\0'));

            Marshal.StructureToPtr(context, pInBuffer, true);

            Console.WriteLine("[>] Sending a query to {0}.", Globals.SYMLINK_PATH);

            do
            {
                IntPtr hDevice;

                using (var objectAttributes = new OBJECT_ATTRIBUTES(
                    Globals.SYMLINK_PATH,
                    OBJECT_ATTRIBUTES_FLAGS.CaseInsensitive))
                {
                    ntstatus = NativeMethods.NtCreateFile(
                        out hDevice,
                        ACCESS_MASK.GENERIC_READ | ACCESS_MASK.GENERIC_WRITE,
                        in objectAttributes,
                        out IO_STATUS_BLOCK _,
                        IntPtr.Zero,
                        FILE_ATTRIBUTE_FLAGS.NORMAL,
                        FILE_SHARE_ACCESS.NONE,
                        FILE_CREATE_DISPOSITION.OPEN,
                        FILE_CREATE_OPTIONS.NON_DIRECTORY_FILE,
                        IntPtr.Zero,
                        0u);
                }

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                {
                    Console.WriteLine("[-] Failed to open {0} (NTSTATUS = 0x{1}).", Globals.SYMLINK_PATH, ntstatus.ToString("X8"));
                    break;
                }
                else
                {
                    Console.WriteLine("[+] Got a handle to {0} (Handle = 0x{1}).", Globals.SYMLINK_PATH, hDevice.ToString("X"));
                }

                ntstatus = NativeMethods.NtDeviceIoControlFile(
                    hDevice,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    out IO_STATUS_BLOCK _,
                    Globals.IOCTL_INJECT_LIBRARY,
                    pInBuffer,
                    (uint)Marshal.SizeOf(typeof(INJECT_CONTEXT)),
                    IntPtr.Zero,
                    0u);
                NativeMethods.NtClose(hDevice);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                    Console.WriteLine("[-] Failed to NtDeviceIoControlFile() (NTSTATUS = 0x{0}).", ntstatus.ToString("X8"));
                else
                    Console.WriteLine("[+] DLL injection would be successful.");
            } while (false);

            Marshal.FreeHGlobal(pInBuffer);

            Console.WriteLine("[*] Done.");

            return (ntstatus == Win32Consts.STATUS_SUCCESS);
        }
    }
}
