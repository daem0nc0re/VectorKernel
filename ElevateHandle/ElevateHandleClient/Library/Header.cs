using System;
using System.Runtime.InteropServices;
using ElevateHandleClient.Interop;

namespace ElevateHandleClient.Library
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct ELEVATE_HANDLE_INPUT
    {
        public IntPtr UniqueProcessId;
        public IntPtr HandleValue;
        public ACCESS_MASK AccessMask;
    }
}
