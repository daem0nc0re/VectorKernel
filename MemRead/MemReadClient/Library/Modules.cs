using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using MemReadClient.Interop;

namespace MemReadClient.Library
{
    using NTSTATUS = Int32;
    using SIZE_T = UIntPtr;

    internal class Modules
    {
        public static bool GetMemoryMappingInformation(uint pid)
        {
            NTSTATUS ntstatus;
            string processName;
            IntPtr hDevice;
            IntPtr pInputBuffer;
            IntPtr pOutputBuffer = IntPtr.Zero;
            var nInputLength = (uint)Marshal.SizeOf(typeof(IOCTL_QUERY_INPUT));
            var nOutputLength = 0x1000u;
            var input = new IOCTL_QUERY_INPUT { ProcessId = pid };

            try
            {
                processName = Process.GetProcessById((int)pid).ProcessName;
            }
            catch
            {
                Console.WriteLine("[-] Failed to resolve process name.");
                return false;
            }

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
                return false;
            }

            pInputBuffer = Marshal.AllocHGlobal((int)nInputLength);
            Marshal.StructureToPtr(input, pInputBuffer, true);

            do
            {
                var nRegionSize = new SIZE_T(nOutputLength);
                ntstatus = NativeMethods.NtAllocateVirtualMemory(
                    new IntPtr(-1),
                    ref pOutputBuffer,
                    SIZE_T.Zero,
                    ref nRegionSize,
                    MEMORY_ALLOCATION_TYPE.Commit | MEMORY_ALLOCATION_TYPE.Reserve,
                    MEMORY_PROTECTION.ReadWrite);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                {
                    Console.WriteLine("[-] Failed to allocate output buffer (NTSTATUS = 0x{0}).", ntstatus.ToString("X8"));
                    break;
                }

                ntstatus = NativeMethods.NtDeviceIoControlFile(
                    hDevice,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    out IO_STATUS_BLOCK _,
                    Globals.IOCTL_GET_MEMORY_MAPPING,
                    pInputBuffer,
                    nInputLength,
                    pOutputBuffer,
                    nOutputLength);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                {
                    nRegionSize = SIZE_T.Zero;
                    NativeMethods.NtFreeVirtualMemory(new IntPtr(-1), ref pOutputBuffer, ref nRegionSize, MEMORY_ALLOCATION_TYPE.Release);
                    pOutputBuffer = IntPtr.Zero;
                    nOutputLength <<= 1;
                }
            } while (ntstatus == Win32Consts.STATUS_BUFFER_TOO_SMALL);

            if (ntstatus == Win32Consts.STATUS_SUCCESS)
            {
                string lineFormat;
                IntPtr pEntryBase;
                IntPtr pCurrentEntry;
                var outputBuilder = new StringBuilder();
                var columnNames = new string[]
                {
                    "Address",
                    "Size",
                    "State",
                    "Protect",
                    "Type",
                    "Mapped File"
                };
                var columnWidths = new int[columnNames.Length];
                var nFreeSize = SIZE_T.Zero;
                var nEntryOffset = Marshal.OffsetOf(typeof(IOCTL_QUERY_OUTPUT), "Entries").ToInt32();
                var header = (IOCTL_QUERY_OUTPUT_HEADER)Marshal.PtrToStructure(
                    pOutputBuffer,
                    typeof(IOCTL_QUERY_OUTPUT_HEADER));
                outputBuilder.AppendFormat("[Memory Mapping Information (Process Name: {0}, PID: {1})]\n\n", processName, pid);
                outputBuilder.AppendFormat("PEB  : 0x{0}\n", header.Peb.ToString("X16"));
                outputBuilder.AppendFormat("PEB32: {0}\n\n",
                    (header.Peb32 == IntPtr.Zero) ? "N/A" : string.Format("0x{0}", header.Peb32.ToString("X8")));

                if (header.EntryCount > 0)
                {
                    Dictionary<string, string> deviceMap = Helpers.GetDeviceMap();

                    for (var i = 0; i < columnNames.Length; i++)
                        columnWidths[i] = columnNames[i].Length;

                    if (Environment.Is64BitProcess)
                        pEntryBase = new IntPtr(pOutputBuffer.ToInt64() + nEntryOffset);
                    else
                        pEntryBase = new IntPtr(pOutputBuffer.ToInt32() + nEntryOffset);

                    pCurrentEntry = pEntryBase;
                    columnWidths[0] = 2 + (IntPtr.Size * 2);

                    for (var i = 0; i < (int)header.EntryCount; i++)
                    {
                        var entry = (MEMORY_MAPPING_INFO)Marshal.PtrToStructure(
                            pCurrentEntry,
                            typeof(MEMORY_MAPPING_INFO));

                        if (entry.Information.RegionSize.ToUInt64().ToString("X").Length + 2 > columnWidths[1])
                            columnWidths[1] = entry.Information.RegionSize.ToUInt64().ToString("X").Length + 2;

                        if (entry.Information.State.ToString().Length > columnWidths[2])
                            columnWidths[2] = entry.Information.State.ToString().Length;

                        if (entry.Information.Protect.ToString().Length > columnWidths[3])
                            columnWidths[3] = entry.Information.Protect.ToString().Length;

                        if (entry.Information.Type.ToString().Length > columnWidths[4])
                            columnWidths[4] = entry.Information.Type.ToString().Length;

                        if (Environment.Is64BitProcess)
                            pCurrentEntry = new IntPtr(pCurrentEntry.ToInt64() + entry.Size);
                        else
                            pCurrentEntry = new IntPtr(pCurrentEntry.ToInt32() + (int)entry.Size);
                    }

                    lineFormat = string.Format("{{0, {0}}} {{1, {1}}} {{2, -{2}}} {{3, -{3}}} {{4, -{4}}} {{5}}\n",
                        columnWidths[0],
                        columnWidths[1],
                        columnWidths[2],
                        columnWidths[3],
                        columnWidths[4]);
                    outputBuilder.AppendFormat(lineFormat,
                        columnNames[0],
                        columnNames[1],
                        columnNames[2],
                        columnNames[3],
                        columnNames[4],
                        columnNames[5]);
                    outputBuilder.AppendFormat(lineFormat,
                        new string('=', columnWidths[0]),
                        new string('=', columnWidths[1]),
                        new string('=', columnWidths[2]),
                        new string('=', columnWidths[3]),
                        new string('=', columnWidths[4]),
                        new string('=', columnWidths[5]));
                    pCurrentEntry = pEntryBase;

                    for (var i = 0; i < (int)header.EntryCount; i++)
                    {
                        IntPtr pStringBuffer;
                        string mappedFileName;
                        var nNameOffset = Marshal.OffsetOf(typeof(MEMORY_MAPPING_INFO), "Filename").ToInt32();
                        var entry = (MEMORY_MAPPING_INFO)Marshal.PtrToStructure(
                            pCurrentEntry,
                            typeof(MEMORY_MAPPING_INFO));

                        if (Environment.Is64BitProcess)
                            pStringBuffer = new IntPtr(pCurrentEntry.ToInt64() + nNameOffset);
                        else
                            pStringBuffer = new IntPtr(pCurrentEntry.ToInt32() + nNameOffset);

                        mappedFileName = Marshal.PtrToStringUni(pStringBuffer, (int)entry.NameLength / 2);

                        if (!string.IsNullOrEmpty(mappedFileName))
                        {
                            foreach (var dev in deviceMap)
                            {
                                if (mappedFileName.StartsWith(dev.Value))
                                {
                                    mappedFileName = mappedFileName.Replace(dev.Value, dev.Key);
                                    break;
                                }
                            }
                        }

                        outputBuilder.AppendFormat(lineFormat,
                            string.Format("0x{0}", entry.Information.BaseAddress.ToString(Environment.Is64BitProcess ? "X16" : "X8")),
                            string.Format("0x{0}", entry.Information.RegionSize.ToUInt64().ToString("X")),
                            entry.Information.State.ToString(),
                            entry.Information.Protect.ToString(),
                            entry.Information.Type.ToString(),
                            string.IsNullOrEmpty(mappedFileName) ? "N/A" : mappedFileName);

                        if (Environment.Is64BitProcess)
                            pCurrentEntry = new IntPtr(pCurrentEntry.ToInt64() + entry.Size);
                        else
                            pCurrentEntry = new IntPtr(pCurrentEntry.ToInt32() + (int)entry.Size);
                    }
                }
                else
                {
                    outputBuilder.AppendLine("No entries.");
                }

                Console.WriteLine(outputBuilder.ToString());

                NativeMethods.NtFreeVirtualMemory(new IntPtr(-1), ref pOutputBuffer, ref nFreeSize, MEMORY_ALLOCATION_TYPE.Release);
            }

            Marshal.FreeHGlobal(pInputBuffer);
            NativeMethods.NtClose(hDevice);

            return (ntstatus == Win32Consts.STATUS_SUCCESS);
        }


        public static bool ReadMemory(uint pid, IntPtr pMemoryBase, uint nNumberOfBytesToRead)
        {
            NTSTATUS ntstatus;
            string processName;
            IntPtr hDevice;
            IntPtr pInputBuffer;
            IntPtr pOutputBuffer = IntPtr.Zero;
            var outputBuilder = new StringBuilder();
            var nNameOffset = (uint)Marshal.OffsetOf(typeof(IOCTL_READ_MEMORY_OUTPUT), "Filename").ToInt32();
            var nInputLength = (uint)Marshal.SizeOf(typeof(IOCTL_READ_MEMORY_INPUT));
            var nOutputLength = nNameOffset + 0x400u + nNumberOfBytesToRead;
            var input = new IOCTL_READ_MEMORY_INPUT {
                ProcessId = pid,
                ReadBytes = nNumberOfBytesToRead,
                BaseAddress = pMemoryBase
            };

            try
            {
                processName = Process.GetProcessById((int)pid).ProcessName;
            }
            catch
            {
                Console.WriteLine("[-] Failed to resolve process name.");
                return false;
            }

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
                return false;
            }

            pInputBuffer = Marshal.AllocHGlobal((int)nInputLength);
            Marshal.StructureToPtr(input, pInputBuffer, true);

            do
            {
                pOutputBuffer = Marshal.AllocHGlobal((int)nOutputLength);
                ntstatus = NativeMethods.NtDeviceIoControlFile(
                    hDevice,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    out IO_STATUS_BLOCK _,
                    Globals.IOCTL_READ_MEMORY,
                    pInputBuffer,
                    nInputLength,
                    pOutputBuffer,
                    nOutputLength);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                {
                    Marshal.FreeHGlobal(pOutputBuffer);
                    nOutputLength <<= 1;
                }
            } while (ntstatus == Win32Consts.STATUS_BUFFER_TOO_SMALL);

            if (ntstatus == Win32Consts.STATUS_SUCCESS)
            {
                IntPtr pDataBuffer;
                string mappedFileName = null;
                var info = (IOCTL_READ_MEMORY_OUTPUT)Marshal.PtrToStructure(
                    pOutputBuffer,
                    typeof(IOCTL_READ_MEMORY_OUTPUT));

                if (Environment.Is64BitProcess)
                    pDataBuffer = new IntPtr(pOutputBuffer.ToInt64() + info.DataOffset);
                else
                    pDataBuffer = new IntPtr(pOutputBuffer.ToInt32() + (int)info.DataOffset);

                if (info.NameLength > 0)
                {
                    IntPtr pNameBuffer;
                    Dictionary<string, string> deviceMap = Helpers.GetDeviceMap();

                    if (Environment.Is64BitProcess)
                        pNameBuffer = new IntPtr(pOutputBuffer.ToInt64() + nNameOffset);
                    else
                        pNameBuffer = new IntPtr(pOutputBuffer.ToInt32() + (int)nNameOffset);

                    mappedFileName = Marshal.PtrToStringUni(pNameBuffer, (int)info.NameLength / 2);

                    foreach (var dev in deviceMap)
                    {
                        if (mappedFileName.StartsWith(dev.Value))
                        {
                            mappedFileName = mappedFileName.Replace(dev.Value, dev.Key);
                            break;
                        }
                    }
                }

                outputBuilder.AppendFormat("Process ID       : {0}\n", pid);
                outputBuilder.AppendFormat("Process Name     : {0}\n", processName);
                outputBuilder.AppendFormat("Base Address     : 0x{0}\n",
                    info.Information.BaseAddress.ToString(Environment.Is64BitProcess ? "X16" : "X8"));
                outputBuilder.AppendFormat("Read Size        : 0x{0}\n", info.ReadBytes.ToString("X"));
                outputBuilder.AppendFormat("Memory State     : {0}\n", info.Information.State.ToString());
                outputBuilder.AppendFormat("Memory Protection: {0}\n", info.Information.Protect.ToString());
                outputBuilder.AppendFormat("Memory Type      : {0}\n", info.Information.Type.ToString());
                outputBuilder.AppendFormat("Mapped File      : {0}\n", mappedFileName ?? "N/A");
                outputBuilder.AppendFormat("Memory Content   :\n\n{0}\n",
                    HexDump.Dump(pDataBuffer, pMemoryBase, info.ReadBytes, 0));

                if (info.ReadBytes < nNumberOfBytesToRead)
                    outputBuilder.AppendLine("[*] Read region exceeded allocation boundary, so size was shrunken by kernel driver.");

                Marshal.FreeHGlobal(pOutputBuffer);
            }
            else
            {
                outputBuilder.AppendFormat("Failed to read memory (NTSTATUS = 0x{0}).\n", ntstatus.ToString("X8"));
            }

            Console.WriteLine(outputBuilder.ToString());

            Marshal.FreeHGlobal(pInputBuffer);
            NativeMethods.NtClose(hDevice);

            return (ntstatus == Win32Consts.STATUS_SUCCESS);
        }
    }
}
