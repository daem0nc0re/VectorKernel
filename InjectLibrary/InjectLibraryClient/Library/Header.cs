using System;
using System.Runtime.InteropServices;
using System.Text;

namespace InjectLibraryClient.Library
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct INJECT_CONTEXT
    {
        public uint ThreadId;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 512)]
        public byte[] LibraryPath;

        public INJECT_CONTEXT(int threadId, string libraryPath)
        {
            ThreadId = (uint)threadId;
            LibraryPath = new byte[512];

            if (!string.IsNullOrEmpty(libraryPath))
            {
                var pathBytes = Encoding.Unicode.GetBytes(libraryPath);
                var nCopyLength = (pathBytes.Length < 512) ? pathBytes.Length : 512;
                Buffer.BlockCopy(pathBytes, 0, LibraryPath, 0, nCopyLength);
            }
        }
    }
}
