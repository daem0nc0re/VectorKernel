using System;
using System.Runtime.InteropServices;

namespace EnumDrivers.Interop
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct RTL_PROCESS_MODULES
    {
        public uint NumberOfModules;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
        public RTL_PROCESS_MODULE_INFORMATION[] Modules;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct RTL_PROCESS_MODULE_INFORMATION
    {
        public IntPtr Section;
        public IntPtr MappedBase;
        public IntPtr ImageBase;
        public uint ImageSize;
        public uint Flags;
        public ushort LoadOrderIndex;
        public ushort InitOrderIndex;
        public ushort LoadCount;
        public ushort OffsetToFileName;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 256)]
        public byte[] FullPathName;
    }
}
