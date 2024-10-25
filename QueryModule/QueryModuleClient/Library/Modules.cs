using System;
using System.Runtime.InteropServices;
using System.Text;
using QueryModuleClient.Interop;

namespace QueryModuleClient.Library
{
    using NTSTATUS = Int32;

    internal class Modules
    {
        public static bool GetModuleList()
        {
            NTSTATUS ntstatus;
            IntPtr hDevice;
            var pOutBuffer = IntPtr.Zero;

            Console.WriteLine("[>] Sending queries to {0}.", Globals.SYMLINK_PATH);

            do
            {
                IO_STATUS_BLOCK ioStatusBlock;
                int nOutLength = 0x4000;

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
                    hDevice = IntPtr.Zero;
                    Console.WriteLine("[-] Failed to open {0} (NTSTATUS = 0x{1}).", Globals.SYMLINK_PATH, ntstatus.ToString("X8"));
                    break;
                }
                else
                {
                    Console.WriteLine("[+] Got a handle to {0} (Handle = 0x{1}).", Globals.SYMLINK_PATH, hDevice.ToString("X"));
                }

                do
                {
                    pOutBuffer = Marshal.AllocHGlobal(nOutLength);
                    ntstatus = NativeMethods.NtDeviceIoControlFile(
                        hDevice,
                        IntPtr.Zero,
                        IntPtr.Zero,
                        IntPtr.Zero,
                        out ioStatusBlock,
                        Globals.IOCTL_QUERY_MODULE_INFO,
                        IntPtr.Zero,
                        0u,
                        pOutBuffer,
                        (uint)nOutLength);

                    if (ntstatus != Win32Consts.STATUS_SUCCESS)
                    {
                        Marshal.FreeHGlobal(pOutBuffer);
                        pOutBuffer = IntPtr.Zero;
                        nOutLength *= 2;
                    }
                } while (ntstatus == Win32Consts.STATUS_BUFFER_TOO_SMALL);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                {
                    Console.WriteLine("[-] Failed to NtDeviceIoControlFile() (NTSTATUS = 0x{0}).", ntstatus.ToString("X8"));
                }
                else
                {
                    IntPtr pInfoBuffer;
                    IntPtr pNameBuffer;
                    var nInfoSize = (uint)Marshal.SizeOf(typeof(AUX_MODULE_EXTENDED_INFO));
                    var nEntries = (ioStatusBlock.Information.ToUInt32() / nInfoSize);
                    var nNameOffset = Marshal.OffsetOf(typeof(AUX_MODULE_EXTENDED_INFO), "FullPathName").ToInt32();
                    var resultBuilder = new StringBuilder();

                    if (nEntries > 0)
                    {
                        resultBuilder.AppendFormat("[+] Got {0} modules.\n", nEntries);

                        if (Environment.Is64BitProcess)
                        {
                            resultBuilder.Append("\n");
                            resultBuilder.Append("Address            Module\n");
                            resultBuilder.Append("================== ======\n");
                        }
                        else
                        {
                            resultBuilder.Append("\n");
                            resultBuilder.Append("Address    Module\n");
                            resultBuilder.Append("========== ======\n");
                        }
                    }
                    else
                    {
                        resultBuilder.Append("[*] No modules.");
                    }

                    for (var idx = 0u; idx < nEntries; idx++)
                    {
                        if (Environment.Is64BitProcess)
                        {
                            pInfoBuffer = new IntPtr(pOutBuffer.ToInt64() + ((int)nInfoSize * idx));
                            pNameBuffer = new IntPtr(pInfoBuffer.ToInt64() + nNameOffset);
                        }
                        else
                        {
                            pInfoBuffer = new IntPtr(pOutBuffer.ToInt32() + ((int)nInfoSize * idx));
                            pNameBuffer = new IntPtr(pInfoBuffer.ToInt32() + nNameOffset);
                        }

                        var entry = (AUX_MODULE_EXTENDED_INFO)Marshal.PtrToStructure(
                            pInfoBuffer,
                            typeof(AUX_MODULE_EXTENDED_INFO));
                        resultBuilder.AppendFormat(
                            "0x{0} {1}\n",
                            entry.BasicInfo.ImageBase.ToString(Environment.Is64BitProcess ? "X16" : "X8"),
                            Marshal.PtrToStringAnsi(pNameBuffer));
                    }

                    Console.WriteLine(resultBuilder.ToString());
                }
            } while (false);

            if (pOutBuffer != IntPtr.Zero)
                Marshal.FreeHGlobal(pOutBuffer);

            if (hDevice != IntPtr.Zero)
                NativeMethods.NtClose(hDevice);

            Console.WriteLine("[*] Done.");

            return (ntstatus == Win32Consts.STATUS_SUCCESS);
        }
    }
}
