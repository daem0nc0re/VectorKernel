using MemReadClient.Interop;
using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace MemReadClient.Library
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct IOCTL_QUERY_OUTPUT
    {
        public IOCTL_QUERY_OUTPUT_HEADER Header;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
        public MEMORY_MAPPING_INFO[] Entries;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct IOCTL_QUERY_INPUT
    {
        public uint ProcessId;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct IOCTL_QUERY_OUTPUT_HEADER
    {
        public uint EntryCount;
        public uint DataLength;
        public IntPtr Peb;
        public IntPtr Peb32;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct IOCTL_READ_MEMORY_INPUT
    {
        public uint ProcessId;
        public uint ReadBytes;
        public IntPtr BaseAddress;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct IOCTL_READ_MEMORY_OUTPUT
    {
        public uint Size;
        public uint ReadBytes;
        public uint NameLength;
        public uint DataOffset;
        public MEMORY_BASIC_INFORMATION Information;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
        public ushort[] Filename;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
        public byte[] Data;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MEMORY_MAPPING_INFO
    {
        public uint Size;
        public uint NameLength;
        public MEMORY_BASIC_INFORMATION Information;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
        public ushort[] Filename; // Mapped filename is stored here
    }
}
