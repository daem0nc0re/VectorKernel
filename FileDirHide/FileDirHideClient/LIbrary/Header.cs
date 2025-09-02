using System.Runtime.InteropServices;

namespace FileDirHideClient.Library
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct LIST_FILEDIR_ENTRIES_OUTPUT
    {
        public uint Index;
        public uint PathBytesLength;
        public uint NextOffset;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
        public ushort[] Path;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct LIST_FILEDIR_ENTRIES_OUTPUT_EX
    {
        public uint Count;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
        public LIST_FILEDIR_ENTRIES_OUTPUT[] Entries;
    }


    [StructLayout(LayoutKind.Sequential)]
    internal struct REGISTER_FILEDIR_ENTRY_INPUT
    {
        public uint PathBytesLength;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
        public ushort[] Path;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct REGISTER_FILEDIR_ENTRY_OUTPUT
    {
        public uint Index;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct REMOVE_FILEDIR_ENTRY_INPUT
    {
        public uint Index;
    }
}
