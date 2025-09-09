using System.Runtime.InteropServices;

namespace BlockNewProcClient.Library
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct BLOCK_IMAGE_INFO
    {
        public uint NameBytesLength;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
        public ushort[] ImageFileName;
    }
}
