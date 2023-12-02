using System;
using System.Runtime.InteropServices;

namespace EnumDrivers.Interop
{
    using NTSTATUS = Int32;

    internal class NativeMethods
    {
        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtQuerySystemInformation(
            SYSTEM_INFORMATION_CLASS SystemInformationClass,
            IntPtr SystemInformation,
            uint SystemInformationLength,
            out uint ReturnLength);
    }
}
