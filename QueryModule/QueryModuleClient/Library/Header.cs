using System.Runtime.InteropServices;
using QueryModuleClient.Interop;

namespace QueryModuleClient.Library
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct SYSTEM_MODULE_INFO
    {
        public uint ReturnedLength;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
        public AUX_MODULE_EXTENDED_INFO[] Information;
    }
}
