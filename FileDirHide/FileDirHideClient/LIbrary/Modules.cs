using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using FileDirHideClient.Interop;

namespace FileDirHideClient.Library
{
    using NTSTATUS = Int32;

    internal class Modules
    {
        public static bool ListRegisteredFileDirectoryEntries()
        {
            var bSuccess = false;
            var pOutBuffer = IntPtr.Zero;

            Console.WriteLine("[>] Trying to list all entries.");

            do
            {
                NTSTATUS ntstatus;
                IntPtr hDevice;
                IntPtr pCurrentEntry;
                int nEntryCount;
                var nOutBufferLength = 0x100u;
                var nBaseOffset = Marshal.OffsetOf(typeof(LIST_FILEDIR_ENTRIES_OUTPUT_EX), "Entries").ToInt32();

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

                do
                {
                    pOutBuffer = Marshal.AllocHGlobal((int)nOutBufferLength);
                    ntstatus = NativeMethods.NtDeviceIoControlFile(
                        hDevice,
                        IntPtr.Zero,
                        IntPtr.Zero,
                        IntPtr.Zero,
                        out IO_STATUS_BLOCK ioStatusBlock,
                        Globals.IOCTL_LIST_REGISTERED_FILEDIR,
                        IntPtr.Zero,
                        0u,
                        pOutBuffer,
                        nOutBufferLength);

                    if (ntstatus != Win32Consts.STATUS_SUCCESS)
                    {
                        Marshal.FreeHGlobal(pOutBuffer);
                        pOutBuffer = IntPtr.Zero;
                        nOutBufferLength <<= 1;
                    }
                } while (ntstatus == Win32Consts.STATUS_BUFFER_TOO_SMALL);

                NativeMethods.NtClose(hDevice);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                {
                    Console.WriteLine("[-] Failed to NtDeviceIoControlFile() (NTSTATUS = 0x{0}).", ntstatus.ToString("X8"));
                    break;
                }
                else
                {
                    Console.WriteLine("[+] All entries are removed successfully.");
                    nEntryCount = Marshal.ReadInt32(pOutBuffer);

                    if (Environment.Is64BitProcess)
                        pCurrentEntry = new IntPtr(pOutBuffer.ToInt64() + nBaseOffset);
                    else
                        pCurrentEntry = new IntPtr(pOutBuffer.ToInt32() + nBaseOffset);
                }

                if (nEntryCount == 0)
                {
                    Console.WriteLine("[*] No entries.");
                }
                else
                {
                    var outputBUilder = new StringBuilder();
                    var columnNames = new string[] { "Index", "Registered Path" };
                    var lineFormat = "{0, 5} {1}\n";
                    var nPathOffset = Marshal.OffsetOf(typeof(LIST_FILEDIR_ENTRIES_OUTPUT), "Path").ToInt32();

                    Console.WriteLine("[*] Got {0} entries.\n", nEntryCount);

                    outputBUilder.AppendFormat(lineFormat, columnNames[0], columnNames[1]);
                    outputBUilder.AppendFormat(lineFormat,
                        new string('=', columnNames[0].Length),
                        new string('=', columnNames[1].Length));

                    for (int nIndex = 0; nIndex < nEntryCount; nIndex++)
                    {
                        IntPtr pPathBuffer;
                        var entry = (LIST_FILEDIR_ENTRIES_OUTPUT)Marshal.PtrToStructure(
                            pCurrentEntry,
                            typeof(LIST_FILEDIR_ENTRIES_OUTPUT));

                        if (Environment.Is64BitProcess)
                            pPathBuffer = new IntPtr(pCurrentEntry.ToInt64() + nPathOffset);
                        else
                            pPathBuffer = new IntPtr(pCurrentEntry.ToInt32() + nPathOffset);

                        outputBUilder.AppendFormat(lineFormat,
                            entry.Index,
                            Marshal.PtrToStringUni(pPathBuffer, (int)entry.PathBytesLength / 2));

                        if (Environment.Is64BitProcess)
                            pCurrentEntry = new IntPtr(pCurrentEntry.ToInt64() + entry.NextOffset);
                        else
                            pCurrentEntry = new IntPtr(pCurrentEntry.ToInt32() + (int)entry.NextOffset);
                    }

                    Console.WriteLine(outputBUilder.ToString());
                }
            } while (false);

            if (pOutBuffer != IntPtr.Zero)
                Marshal.FreeHGlobal(pOutBuffer);

            Console.WriteLine("[*] Done.");

            return bSuccess;
        }


        public static bool RemoveAllFileDirectoryEntries()
        {
            var bSuccess = false;

            Console.WriteLine("[>] Trying to remove all entries.");

            do
            {
                NTSTATUS ntstatus;
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
                    Globals.IOCTL_REMOVE_ALL_REGISTERED_FILEDIR,
                    IntPtr.Zero,
                    0u,
                    IntPtr.Zero,
                    0u);
                NativeMethods.NtClose(hDevice);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                    Console.WriteLine("[-] Failed to NtDeviceIoControlFile() (NTSTATUS = 0x{0}).", ntstatus.ToString("X8"));
                else
                    Console.WriteLine("[+] All entries are removed successfully.");
            } while (false);

            Console.WriteLine("[*] Done.");

            return bSuccess;
        }


        public static bool RemoveFileDirectoryEntry(uint nIndex)
        {
            var bSuccess = false;
            var ioctlInput = new REMOVE_FILEDIR_ENTRY_INPUT
            {
                Index = nIndex
            };
            var nInBufferSize = Marshal.SizeOf(typeof(REMOVE_FILEDIR_ENTRY_INPUT));
            var pInBuffer = Marshal.AllocHGlobal(nInBufferSize);
            Marshal.StructureToPtr(ioctlInput, pInBuffer, true);

            Console.WriteLine("[>] Trying to remove an entry (Index: {0}).", nIndex);

            do
            {
                NTSTATUS ntstatus;
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
                    Globals.IOCTL_REMOVE_REGISTERED_FILEDIR,
                    pInBuffer,
                    (uint)nInBufferSize,
                    IntPtr.Zero,
                    0u);
                NativeMethods.NtClose(hDevice);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                    Console.WriteLine("[-] Failed to NtDeviceIoControlFile() (NTSTATUS = 0x{0}).", ntstatus.ToString("X8"));
                else
                    Console.WriteLine("[+] The specified entry is removed successfully.");
            } while (false);

            Marshal.FreeHGlobal(pInBuffer);

            Console.WriteLine("[*] Done.");

            return bSuccess;
        }


        public static bool SetFileDirectoryEntry(string pathname)
        {
            if (string.IsNullOrEmpty(pathname))
            {
                Console.WriteLine("[!] Path is required.", pathname);
                return false;
            }

            IntPtr pPathBuffer;
            var bSuccess = false;
            var fullPathName = Path.GetFullPath(pathname).TrimEnd('\\');
            var fullPathBytes = Encoding.Unicode.GetBytes(fullPathName);
            var nPathOffset = Marshal.OffsetOf(typeof(REGISTER_FILEDIR_ENTRY_INPUT), "Path").ToInt32();
            var nInBufferSize = nPathOffset + fullPathBytes.Length;
            var nOutBufferSize = Marshal.SizeOf(typeof(REGISTER_FILEDIR_ENTRY_OUTPUT));
            var ioctlInput = new REGISTER_FILEDIR_ENTRY_INPUT
            {
                PathBytesLength = (uint)fullPathBytes.Length
            };
            var pInBuffer = Marshal.AllocHGlobal(nInBufferSize);
            var pOutBuffer = Marshal.AllocHGlobal(nOutBufferSize);

            if (Environment.Is64BitProcess)
                pPathBuffer = new IntPtr(pInBuffer.ToInt64() + nPathOffset);
            else
                pPathBuffer = new IntPtr(pInBuffer.ToInt32() + nPathOffset);

            for (var oft = 0; oft < nOutBufferSize; oft++)
                Marshal.WriteByte(pOutBuffer, oft, 0);

            Marshal.StructureToPtr(ioctlInput, pInBuffer, true);
            Marshal.Copy(fullPathBytes, 0, pPathBuffer, fullPathBytes.Length);

            Console.WriteLine("[>] Trying to register a path \"{0}\".", fullPathName);

            do
            {
                NTSTATUS ntstatus;
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
                    Globals.IOCTL_REGISTER_FILEDIR,
                    pInBuffer,
                    (uint)nInBufferSize,
                    pOutBuffer,
                    (uint)nOutBufferSize);
                NativeMethods.NtClose(hDevice);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                {
                    Console.WriteLine("[-] Failed to NtDeviceIoControlFile() (NTSTATUS = 0x{0}).", ntstatus.ToString("X8"));
                }
                else
                {
                    var ioctlOutput = (REGISTER_FILEDIR_ENTRY_OUTPUT)Marshal.PtrToStructure(
                        pOutBuffer,
                        typeof(REGISTER_FILEDIR_ENTRY_OUTPUT));
                    bSuccess = true;
                    Console.WriteLine("[+] The specified path is registered successfully (Index = {0}).", ioctlOutput.Index);
                }
            } while (false);

            Marshal.FreeHGlobal(pOutBuffer);
            Marshal.FreeHGlobal(pInBuffer);

            Console.WriteLine("[*] Done.");

            return bSuccess;
        }
    }
}
