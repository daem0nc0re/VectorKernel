using System.Runtime.InteropServices;
using ProcProtectClient.Interop;

namespace ProcProtectClient.Library
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct PROTECTION_INFO
    {
        public uint ProcessId;
        public PS_PROTECTED_TYPE ProtectedType;
        public PS_PROTECTED_SIGNER ProtectedSigner;
        public byte SignatureLevel;
        public byte SectionSignatureLevel;
    }
}
