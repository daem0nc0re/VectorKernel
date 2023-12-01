using System;
using System.Runtime.InteropServices;
using ProcHideClient.Interop;

namespace ProcHideClient.Library
{
    using NTSTATUS = Int32;

    internal class Modules
    {
        public static bool HideProcessByPid(int pid)
        {
            NTSTATUS ntstatus;
            IntPtr pInBuffer = Marshal.AllocHGlobal(4);
            Marshal.WriteInt32(pInBuffer, pid);

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
                    Globals.IOCTL_HIDE_PROC_BY_PID,
                    pInBuffer,
                    4u,
                    IntPtr.Zero,
                    0u);
                NativeMethods.NtClose(hDevice);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                    Console.WriteLine("[-] Failed to NtDeviceIoControlFile() (NTSTATUS = 0x{0}).", ntstatus.ToString("X8"));
                else
                    Console.WriteLine("[+] Target process is hidden successfully (PID = {0}).", pid);
            } while (false);
            
            Marshal.FreeHGlobal(pInBuffer);

            Console.WriteLine("[*] Done.");

            return (ntstatus != Win32Consts.STATUS_SUCCESS);
        }
    }
}
