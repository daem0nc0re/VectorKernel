using System;
using System.Runtime.InteropServices;
using System.Text;
using ModHideClient.Interop;

namespace ModHideClient.Library
{
    using NTSTATUS = Int32;

    internal class Modules
    {
        public static bool HideModuleByName(string imageFileName)
        {
            NTSTATUS ntstatus;
            IntPtr pInBuffer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(MODULE_NAME_INFO)));
            var moduleName = new MODULE_NAME_INFO(imageFileName);
            imageFileName = Encoding.Unicode.GetString(moduleName.ImageFileName).TrimEnd('\0');
            Marshal.StructureToPtr(moduleName, pInBuffer, false);

            Console.WriteLine("[>] Sending a query to {0}.", Globals.SYMLINK_PATH);
            Console.WriteLine("    [*] Target : {0}", imageFileName);

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
                    Globals.IOCTL_HIDE_MODULE_BY_NAME,
                    pInBuffer,
                    (uint)Marshal.SizeOf(typeof(MODULE_NAME_INFO)),
                    IntPtr.Zero,
                    0u);
                NativeMethods.NtClose(hDevice);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                    Console.WriteLine("[-] Failed to NtDeviceIoControlFile() (NTSTATUS = 0x{0}).", ntstatus.ToString("X8"));
                else
                    Console.WriteLine("[+] Target module is hidden successfully (Driver Name: {0}).", imageFileName);
            } while (false);

            Marshal.FreeHGlobal(pInBuffer);

            Console.WriteLine("[*] Done.");

            return (ntstatus != Win32Consts.STATUS_SUCCESS);
        }
    }
}
