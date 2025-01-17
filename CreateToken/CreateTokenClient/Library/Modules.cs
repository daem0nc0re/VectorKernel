using System;
using System.Runtime.InteropServices;
using CreateTokenClient.Interop;

namespace CreateTokenClient.Library
{
    using NTSTATUS = Int32;

    internal class Modules
    {
        public static bool GetPrivilegedTokenProcess(string command)
        {
            IntPtr hToken;
            IntPtr pOutBuffer = Marshal.AllocHGlobal(IntPtr.Size);
            var bSuccess = false;

            Console.WriteLine("[>] Sending a query to {0}.", Globals.SYMLINK_PATH);

            do
            {
                NTSTATUS ntstatus;
                IntPtr hDevice;
                var startupInfo = new STARTUPINFO { cb = Marshal.SizeOf(typeof(STARTUPINFO)) };

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
                    Globals.IOCTL_CREATE_SYSTEM_TOKEN,
                    IntPtr.Zero,
                    0u,
                    pOutBuffer,
                    (uint)IntPtr.Size);
                NativeMethods.NtClose(hDevice);
                hToken = Marshal.ReadIntPtr(pOutBuffer);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                {
                    Console.WriteLine("[-] Failed to NtDeviceIoControlFile() (NTSTATUS = 0x{0}).", ntstatus.ToString("X8"));
                    break;
                }
                else
                {
                    Console.WriteLine("[+] Got a privileged token (Handle = 0x{0}).", hToken.ToString("X"));
                }

                Console.WriteLine("[>] Trying to create new process.");
                Console.WriteLine("    [*] Command : {0}", command);

                bSuccess = NativeMethods.CreateProcessAsUser(
                    hToken,
                    null,
                    command,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    false,
                    PROCESS_CREATION_FLAGS.CREATE_NEW_CONSOLE | PROCESS_CREATION_FLAGS.CREATE_BREAKAWAY_FROM_JOB,
                    IntPtr.Zero,
                    Environment.CurrentDirectory,
                    in startupInfo,
                    out PROCESS_INFORMATION processInfo);

                if (!bSuccess)
                {
                    Console.WriteLine("[-] Failed to CreateProcessAsUser() (Error = 0x{0})", Marshal.GetLastWin32Error().ToString("X8"));
                    Console.WriteLine("[>] Trying to create new process with CreateProcessWithToken().");

                    bSuccess = NativeMethods.CreateProcessWithToken(
                        hToken,
                        LOGON_FLAGS.LOGON_NETCREDENTIALS_ONLY,
                        null,
                        command,
                        PROCESS_CREATION_FLAGS.CREATE_NEW_CONSOLE,
                        IntPtr.Zero,
                        Environment.CurrentDirectory,
                        in startupInfo,
                        out processInfo);
                }

                if (!bSuccess)
                {
                    Console.WriteLine("[-] Failed to CreateProcessWithToken() (Error = 0x{0})", Marshal.GetLastWin32Error().ToString("X8"));
                }
                else
                {
                    Console.WriteLine("[+] New process is created successfully.");
                    Console.WriteLine("    [*] Process ID : {0}", processInfo.dwProcessId);
                    Console.WriteLine("    [*] Thread ID  : {0}", processInfo.dwThreadId);

                    NativeMethods.NtClose(processInfo.hThread);
                    NativeMethods.NtClose(processInfo.hProcess);
                }

                NativeMethods.NtClose(hToken);
            } while (false);

            Marshal.FreeHGlobal(pOutBuffer);

            Console.WriteLine("[*] Done.");

            return bSuccess;
        }
    }
}
