using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using BlockImageLoadClient.Interop;

namespace BlockImageLoadClient.Library
{
    using NTSTATUS = Int32;

    internal class Modules
    {
        public static bool SetBlockImageName(string imageFileName)
        {
            NTSTATUS ntstatus;
            IntPtr pInBuffer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(BLOCK_IMAGE_INFO)));
            var moduleName = new BLOCK_IMAGE_INFO(imageFileName);

            if (string.IsNullOrEmpty(Path.GetExtension(imageFileName)))
            {
                Console.WriteLine("[!] File extension is required.");
                return false;
            }

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
                    Globals.IOCTL_SET_MODULE_BLOCK,
                    pInBuffer,
                    (uint)Marshal.SizeOf(typeof(BLOCK_IMAGE_INFO)),
                    IntPtr.Zero,
                    0u);
                NativeMethods.NtClose(hDevice);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                    Console.WriteLine("[-] Failed to NtDeviceIoControlFile() (NTSTATUS = 0x{0}).", ntstatus.ToString("X8"));
                else
                    Console.WriteLine("[+] Block image file name is registered successfully (ImageFileName: {0}).", imageFileName);
            } while (false);

            Marshal.FreeHGlobal(pInBuffer);

            Console.WriteLine("[*] Done.");

            return (ntstatus != Win32Consts.STATUS_SUCCESS);
        }


        public static bool UnregisterLoadImageBlockingCallback()
        {
            NTSTATUS ntstatus;
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
                    Globals.IOCTL_UNSET_MODULE_BLOCK,
                    IntPtr.Zero,
                    0u,
                    IntPtr.Zero,
                    0u);
                NativeMethods.NtClose(hDevice);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                    Console.WriteLine("[-] Failed to NtDeviceIoControlFile() (NTSTATUS = 0x{0}).", ntstatus.ToString("X8"));
                else
                    Console.WriteLine("[+] Load Image Notify Callback is unregistered successfully.");
            } while (false);

            Console.WriteLine("[*] Done.");

            return (ntstatus != Win32Consts.STATUS_SUCCESS);
        }
    }
}
