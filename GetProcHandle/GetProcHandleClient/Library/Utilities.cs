using System;
using System.Runtime.InteropServices;
using GetProcHandleClient.Interop;

namespace GetProcHandleClient.Library
{
    using SIZE_T = UIntPtr;

    internal class Utilities
    {
        public static bool CreateChildProcessByHandle(
            IntPtr hParentProcess,
            string command,
            out int newProcessId,
            out int newThreadId)
        {
            var bSuccess = false;
            var startupInfoEx = new STARTUPINFOEX
            {
                StartupInfo = new STARTUPINFO
                {
                    cb = Marshal.SizeOf(typeof(STARTUPINFOEX))
                },
                lpAttributeList = IntPtr.Zero
            };
            newProcessId = 0;
            newThreadId = 0;

            do
            {
                IntPtr pValue;
                SIZE_T nInfoLength = SIZE_T.Zero;

                NativeMethods.InitializeProcThreadAttributeList(
                    IntPtr.Zero,
                    1,
                    0,
                    ref nInfoLength);

                if (Marshal.GetLastWin32Error() != Win32Consts.ERROR_INSUFFICIENT_BUFFER)
                    break;

                startupInfoEx.lpAttributeList = Marshal.AllocHGlobal((int)nInfoLength.ToUInt32());

                bSuccess = NativeMethods.InitializeProcThreadAttributeList(
                    startupInfoEx.lpAttributeList,
                    1,
                    0,
                    ref nInfoLength);

                if (!bSuccess)
                    break;

                pValue = Marshal.AllocHGlobal(IntPtr.Size);
                Marshal.WriteIntPtr(pValue, hParentProcess);

                bSuccess = NativeMethods.UpdateProcThreadAttribute(
                    startupInfoEx.lpAttributeList,
                    0u,
                    new IntPtr((int)PROC_THREAD_ATTRIBUTES.PARENT_PROCESS),
                    pValue,
                    new SIZE_T((uint)IntPtr.Size),
                    IntPtr.Zero,
                    IntPtr.Zero);
                Marshal.FreeHGlobal(pValue);

                if (!bSuccess)
                    break;

                bSuccess = NativeMethods.CreateProcess(
                    null,
                    command,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    false,
                    ProcessCreationFlags.EXTENDED_STARTUPINFO_PRESENT | ProcessCreationFlags.CREATE_NEW_CONSOLE,
                    IntPtr.Zero,
                    Environment.CurrentDirectory,
                    in startupInfoEx,
                    out PROCESS_INFORMATION processInfo);

                if (bSuccess)
                {
                    newProcessId = processInfo.dwProcessId;
                    newThreadId = processInfo.dwThreadId;

                    NativeMethods.NtClose(processInfo.hThread);
                    NativeMethods.NtClose(processInfo.hProcess);
                }
            } while (false);

            if (startupInfoEx.lpAttributeList != IntPtr.Zero)
                Marshal.FreeHGlobal(startupInfoEx.lpAttributeList);

            return bSuccess;
        }
    }
}
