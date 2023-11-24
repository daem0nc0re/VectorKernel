using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using ProcProtectClient.Interop;

namespace ProcProtectClient.Library
{
    using NTSTATUS = Int32;

    internal class Modules
    {
        public static bool GetProtectionInformation(int pid)
        {
            NTSTATUS ntstatus;
            string processName;
            IntPtr pInBuffer;
            IntPtr pOutBuffer;
            var bSuccess = false;

            try
            {
                processName = Process.GetProcessById(pid).ProcessName;

                Console.WriteLine("[*] Target process information.");
                Console.WriteLine("    [*] Process ID   : {0}", pid);
                Console.WriteLine("    [*] Process Name : {0}", processName);
            }
            catch
            {
                Console.WriteLine("[-] Failed to find the specified process.");
                return false;
            }

            pInBuffer = Marshal.AllocHGlobal(4);
            pOutBuffer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(PROTECTION_INFO)));
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
                    Globals.IOCTL_GET_PROTECTION,
                    pInBuffer,
                    4u,
                    pOutBuffer,
                    (uint)Marshal.SizeOf(typeof(PROTECTION_INFO)));
                NativeMethods.NtClose(hDevice);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                {
                    Console.WriteLine("[-] Failed to NtDeviceIoControlFile() (NTSTATUS = 0x{0}).", ntstatus.ToString("X8"));
                }
                else
                {
                    var info = (PROTECTION_INFO)Marshal.PtrToStructure(
                        pOutBuffer,
                        typeof(PROTECTION_INFO));

                    Console.WriteLine("[+] Got protection info for PID {0}.", info.ProcessId);
                    Console.WriteLine("    [*] Protected Type          : {0}", info.ProtectedType.ToString());
                    Console.WriteLine("    [*] Protected Signer        : {0}", info.ProtectedSigner.ToString());
                    Console.WriteLine("    [*] Signature Level         : 0x{0}", info.SignatureLevel.ToString("X2"));
                    Console.WriteLine("    [*] Section Signature Level : 0x{0}", info.SectionSignatureLevel.ToString("X2"));
                }
            } while (false);

            Marshal.FreeHGlobal(pOutBuffer);
            Marshal.FreeHGlobal(pInBuffer);

            Console.WriteLine("[*] Done.");

            return bSuccess;
        }
    }
}
