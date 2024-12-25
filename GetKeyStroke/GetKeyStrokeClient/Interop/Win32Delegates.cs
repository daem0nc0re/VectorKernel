using System.Runtime.InteropServices;

namespace GetKeyStrokeClient.Interop
{
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate bool PHANDLER_ROUTINE(CTRL_TYPES dwCtrlType);
}
