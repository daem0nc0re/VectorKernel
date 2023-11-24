using System;
using System.Runtime.InteropServices;
using System.Security.Principal;
using GetFullPrivsClient.Interop;

namespace GetFullPrivsClient.Library
{
    using NTSTATUS = Int32;

    internal class Utilities
    {
        public static IntPtr DuplicateCurrentToken(
            TOKEN_TYPE type,
            SECURITY_IMPERSONATION_LEVEL level)
        {
            NTSTATUS ntstatus;
            IntPtr pSecurityQualityOfService = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(SECURITY_QUALITY_OF_SERVICE)));
            var securityQualityOfService = new SECURITY_QUALITY_OF_SERVICE
            {
                Length = Marshal.SizeOf(typeof(SECURITY_QUALITY_OF_SERVICE)),
                ImpersonationLevel = (type == TOKEN_TYPE.Primary) ? SECURITY_IMPERSONATION_LEVEL.Anonymous : level
            };
            var objectAttributes = new OBJECT_ATTRIBUTES
            {
                Length = Marshal.SizeOf(typeof(OBJECT_ATTRIBUTES)),
                SecurityQualityOfService = pSecurityQualityOfService
            };
            Marshal.StructureToPtr(securityQualityOfService, pSecurityQualityOfService, true);

            ntstatus = NativeMethods.NtDuplicateToken(
                WindowsIdentity.GetCurrent().Token,
                ACCESS_MASK.MAXIMUM_ALLOWED,
                in objectAttributes,
                BOOLEAN.FALSE,
                type,
                out IntPtr hToken);
            Marshal.FreeHGlobal(pSecurityQualityOfService);

            if (ntstatus != Win32Consts.STATUS_SUCCESS)
                hToken = IntPtr.Zero;

            return hToken;
        }
    }
}
