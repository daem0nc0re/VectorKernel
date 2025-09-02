using System;

namespace FileDirHideClient.Interop
{
    using NTSTATUS = Int32;

    internal class Win32Consts
    {
        public const NTSTATUS STATUS_SUCCESS = 0;
        public const NTSTATUS STATUS_BUFFER_TOO_SMALL = unchecked((NTSTATUS)0xC0000023);
    }
}
