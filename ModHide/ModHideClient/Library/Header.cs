using System;
using System.Runtime.InteropServices;
using System.Text;

namespace ModHideClient.Library
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct MODULE_NAME_INFO
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 512)]
        public byte[] ImageFileName;

        public MODULE_NAME_INFO(string imageFileName)
        {
            ImageFileName = new byte[512];

            if (!string.IsNullOrEmpty(imageFileName))
            {
                var pathBytes = Encoding.Unicode.GetBytes(imageFileName);
                var nCopyLength = (pathBytes.Length < 512) ? pathBytes.Length : 512;
                Buffer.BlockCopy(pathBytes, 0, ImageFileName, 0, nCopyLength);
            }
        }
    }
}
