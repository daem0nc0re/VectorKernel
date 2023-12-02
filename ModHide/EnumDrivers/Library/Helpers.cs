using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using EnumDrivers.Interop;

namespace EnumDrivers.Library
{
    using NTSTATUS = Int32;

    internal class Helpers
    {
        public static bool GetModuleList(out List<RTL_PROCESS_MODULE_INFORMATION> modules)
        {
            NTSTATUS ntstatus;
            IntPtr pInfoBuffer;
            uint nInfoLength = 0x1000u;
            modules = new List<RTL_PROCESS_MODULE_INFORMATION>();

            do
            {
                pInfoBuffer = Marshal.AllocHGlobal((int)nInfoLength);
                ntstatus = NativeMethods.NtQuerySystemInformation(
                    SYSTEM_INFORMATION_CLASS.SystemModuleInformation,
                    pInfoBuffer,
                    nInfoLength,
                    out nInfoLength);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                    Marshal.FreeHGlobal(pInfoBuffer);
            } while (ntstatus == Win32Consts.STATUS_INFO_LENGTH_MISMATCH);

            if (ntstatus == Win32Consts.STATUS_SUCCESS)
            {
                IntPtr pEntry;
                var nEntryOffset = Marshal.OffsetOf(typeof(RTL_PROCESS_MODULES), "Modules").ToInt32();
                var nUnitSize = Marshal.SizeOf(typeof(RTL_PROCESS_MODULE_INFORMATION));
                var nEntryCount = Marshal.ReadInt32(pInfoBuffer);

                for (var idx = 0; idx < nEntryCount; idx++)
                {
                    if (Environment.Is64BitProcess)
                        pEntry = new IntPtr(pInfoBuffer.ToInt64() + nEntryOffset + (idx * nUnitSize));
                    else
                        pEntry = new IntPtr(pInfoBuffer.ToInt32() + nEntryOffset + (idx * nUnitSize));

                    var entry = (RTL_PROCESS_MODULE_INFORMATION)Marshal.PtrToStructure(
                        pEntry,
                        typeof(RTL_PROCESS_MODULE_INFORMATION));

                    modules.Add(entry);
                }

                Marshal.FreeHGlobal(pInfoBuffer);
            }

            return (ntstatus == Win32Consts.STATUS_SUCCESS);
        }
    }
}
