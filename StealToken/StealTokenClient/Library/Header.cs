using System.Runtime.InteropServices;

namespace StealTokenClient.Library
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct STEAL_TOKEN_INPUT
    {
        public uint SourcePid;
        public uint DestinationPid;
    }
}
