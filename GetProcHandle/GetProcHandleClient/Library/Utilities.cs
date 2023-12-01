using System;
using System.IO;
using System.Runtime.InteropServices;
using GetProcHandleClient.Interop;

namespace GetProcHandleClient.Library
{
    using NTSTATUS = Int32;
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
                    PROCESS_CREATION_FLAGS.EXTENDED_STARTUPINFO_PRESENT | PROCESS_CREATION_FLAGS.CREATE_NEW_CONSOLE,
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


        public static string GetImageFileNameByProcessHandle(IntPtr hProcess)
        {
            NTSTATUS ntstatus;
            IntPtr pInfoBuffer;
            string imageFileName = null;
            var nInfoLength = (uint)(Marshal.SizeOf(typeof(UNICODE_STRING)) + 512);

            do
            {
                pInfoBuffer = Marshal.AllocHGlobal((int)nInfoLength);
                ntstatus = NativeMethods.NtQueryInformationProcess(
                    hProcess,
                    PROCESSINFOCLASS.ProcessImageFileName,
                    pInfoBuffer,
                    nInfoLength,
                    out nInfoLength);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                    Marshal.FreeHGlobal(pInfoBuffer);
            } while (ntstatus == Win32Consts.STATUS_INFO_LENGTH_MISMATCH);

            if (ntstatus == Win32Consts.STATUS_SUCCESS)
            {
                var info = (UNICODE_STRING)Marshal.PtrToStructure(
                    pInfoBuffer,
                    typeof(UNICODE_STRING));
                imageFileName = info.ToString();

                if (!string.IsNullOrEmpty(imageFileName))
                    imageFileName = Path.GetFileName(imageFileName);
                else
                    imageFileName = null;

                Marshal.FreeHGlobal(pInfoBuffer);
            }

            return imageFileName;
        }
    }
}
