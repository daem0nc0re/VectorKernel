using System;
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
            IntPtr pInBuffer = Marshal.AllocHGlobal(4);
            IntPtr pOutBuffer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(PROTECTION_INFO)));
            Marshal.WriteInt32(pInBuffer, pid);

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

                    Console.WriteLine("[+] Got protection information of PID {0}.", info.ProcessId);
                    Console.WriteLine("    [*] Protected Type          : {0}", info.ProtectedType.ToString());
                    Console.WriteLine("    [*] Protected Signer        : {0}", info.ProtectedSigner.ToString());
                    Console.WriteLine("    [*] Signature Level         : {0}", info.SignatureLevel);
                    Console.WriteLine("    [*] Section Signature Level : {0}", info.SectionSignatureLevel);
                }
            } while (false);

            Marshal.FreeHGlobal(pOutBuffer);
            Marshal.FreeHGlobal(pInBuffer);

            Console.WriteLine("[*] Done.");

            return (ntstatus == Win32Consts.STATUS_SUCCESS);
        }


        public static bool SetProtection(
            int pid,
            uint protectedType,
            uint protectedSigner,
            uint signatureLevel,
            uint sectionSignatureLevel)
        {
            NTSTATUS ntstatus;
            IntPtr pInBuffer;
            var info = new PROTECTION_INFO { ProcessId = (uint)pid };
            var bIsValid = false;

            do
            {
                if (protectedType >= (uint)PS_PROTECTED_TYPE.Max)
                {
                    Console.WriteLine("[-] Invalid ProtectedType is specified.");
                    break;
                }

                if (protectedSigner >= (uint)PS_PROTECTED_SIGNER.Max)
                {
                    Console.WriteLine("[-] Invalid ProtectedSigner is specified.");
                    break;
                }

                if (signatureLevel >= 255u)
                {
                    Console.WriteLine("[-] Invalid SignatureLevel value is specified.");
                    break;
                }

                if (sectionSignatureLevel >= 255u)
                {
                    Console.WriteLine("[-] Invalid SectionSignatureLevel value is specified.");
                    break;
                }

                if ((protectedType > 0) && (protectedSigner == 0))
                {
                    Console.WriteLine("[-] When ProtectedType value is set, ProtectedSigner value is must be set.");
                    break;
                }

                if ((protectedType == 0) && (protectedSigner > 0))
                {
                    Console.WriteLine("[-] When ProtectedSigner is set, ProtectedType is must be set.");
                    break;
                }

                info.ProtectedType = (PS_PROTECTED_TYPE)(protectedType & 0xFFu);
                info.ProtectedSigner = (PS_PROTECTED_SIGNER)(protectedSigner & 0xFFu);
                info.SignatureLevel = (byte)(signatureLevel & 0xFFu);
                info.SectionSignatureLevel = (byte)(sectionSignatureLevel & 0xFFu);
                bIsValid = true;
            } while (false);

            if (!bIsValid)
                return false;

            pInBuffer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(PROTECTION_INFO)));
            Marshal.StructureToPtr(info, pInBuffer, false);

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
                    Console.WriteLine("[+] Got a handle to {0} (Handle = 0x{1})", Globals.SYMLINK_PATH, hDevice.ToString("X"));
                }

                ntstatus = NativeMethods.NtDeviceIoControlFile(
                    hDevice,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    out IO_STATUS_BLOCK _,
                    Globals.IOCTL_SET_PROTECTION,
                    pInBuffer,
                    (uint)Marshal.SizeOf(typeof(PROTECTION_INFO)),
                    IntPtr.Zero,
                    0u);
                NativeMethods.NtClose(hDevice);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                {
                    Console.WriteLine("[-] Failed to NtDeviceIoControlFile() (NTSTATUS = 0x{0}).", ntstatus.ToString("X8"));
                }
                else
                {
                    Console.WriteLine("[+] Protection of PID {0} is updated.", info.ProcessId);
                    Console.WriteLine("    [*] Protected Type          : {0}", info.ProtectedType.ToString());
                    Console.WriteLine("    [*] Protected Signer        : {0}", info.ProtectedSigner.ToString());
                    Console.WriteLine("    [*] Signature Level         : {0}", info.SignatureLevel);
                    Console.WriteLine("    [*] Section Signature Level : {0}", info.SectionSignatureLevel);
                }
            } while (false);

            Marshal.FreeHGlobal(pInBuffer);

            Console.WriteLine("[*] Done.");

            return (ntstatus == Win32Consts.STATUS_SUCCESS);
        }
    }
}
