﻿using System;

namespace GetKeyStrokeClient.Interop
{
    using NTSTATUS = Int32;

    internal class Win32Consts
    {
        public const NTSTATUS STATUS_SUCCESS = 0;
        public const NTSTATUS STATUS_NOTIFY_ENUM_DIR = 0x0000010C;
        public const NTSTATUS STATUS_TIMEOUT = 0x00000102;
    }
}
