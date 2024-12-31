using System;
using System.Runtime.InteropServices;
using System.Text;
using ElevateHandleClient.Interop;

namespace ElevateHandleClient.Library
{
    using NTSTATUS = Int32;

    internal class Utilities
    {
        public static bool GetObjectAccessMask(IntPtr hObject, out ACCESS_MASK accessMask)
        {
            NTSTATUS ntstatus;
            IntPtr pInfoBuffer;
            uint nInfoLength = (uint)Marshal.SizeOf(typeof(OBJECT_BASIC_INFORMATION));
            accessMask = ACCESS_MASK.NO_ACCESS;

            do
            {
                pInfoBuffer = Marshal.AllocHGlobal((int)nInfoLength);
                ntstatus = NativeMethods.NtQueryObject(
                    hObject,
                    OBJECT_INFORMATION_CLASS.ObjectBasicInformation,
                    pInfoBuffer,
                    nInfoLength,
                    out nInfoLength);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                    Marshal.FreeHGlobal(pInfoBuffer);
            } while (ntstatus == Win32Consts.STATUS_INFO_LENGTH_MISMATCH);

            if (ntstatus == Win32Consts.STATUS_SUCCESS)
            {
                var info = (OBJECT_BASIC_INFORMATION)Marshal.PtrToStructure(
                    pInfoBuffer,
                    typeof(OBJECT_BASIC_INFORMATION));
                accessMask = info.GrantedAccess;
                Marshal.FreeHGlobal(pInfoBuffer);
            }

            return (ntstatus == Win32Consts.STATUS_SUCCESS);
        }


        public static IntPtr GetServiceKeyHandle(string serviceName, out string keyName)
        {
            IntPtr hKey;
            keyName = string.Format(@"\REGISTRY\MACHINE\SYSTEM\CurrentControlSet\Services\{0}", serviceName);

            using (var objectAttributes = new OBJECT_ATTRIBUTES(
                   keyName,
                   OBJECT_ATTRIBUTES_FLAGS.CaseInsensitive))
            {
                NTSTATUS ntstatus = NativeMethods.NtOpenKey(
                    out hKey,
                    ACCESS_MASK.KEY_QUERY_VALUE,
                    in objectAttributes);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                    hKey = IntPtr.Zero;
            }

            return hKey;
        }


        public static bool ReadServiceImagePath(IntPtr hKey, out string imagePath)
        {
            var bSuccess = false;
            imagePath = null;

            using (var valueName = new UNICODE_STRING("ImagePath"))
            {
                NTSTATUS ntstatus;
                IntPtr pInfoBuffer;
                var nInfoLength = (uint)Marshal.SizeOf(typeof(KEY_VALUE_FULL_INFORMATION));

                do
                {
                    pInfoBuffer = Marshal.AllocHGlobal((int)nInfoLength);
                    ntstatus = NativeMethods.NtQueryValueKey(
                        hKey,
                        in valueName,
                        KEY_VALUE_INFORMATION_CLASS.KeyValueFullInformation,
                        pInfoBuffer,
                        nInfoLength,
                        out nInfoLength);

                    if (ntstatus != Win32Consts.STATUS_SUCCESS)
                        Marshal.FreeHGlobal(pInfoBuffer);
                } while (ntstatus == Win32Consts.STATUS_BUFFER_OVERFLOW);

                if (ntstatus == Win32Consts.STATUS_SUCCESS)
                {
                    var info = (KEY_VALUE_FULL_INFORMATION)Marshal.PtrToStructure(
                        pInfoBuffer,
                        typeof(KEY_VALUE_FULL_INFORMATION));
                    bSuccess = true;

                    if (Environment.Is64BitProcess)
                        imagePath = Marshal.PtrToStringUni(new IntPtr(pInfoBuffer.ToInt64() + info.DataOffset));
                    else
                        imagePath = Marshal.PtrToStringUni(new IntPtr(pInfoBuffer.ToInt32() + (int)info.DataOffset));

                    Marshal.FreeHGlobal(pInfoBuffer);
                }
            }

            return bSuccess;
        }


        public static bool WriteServiceImagePath(IntPtr hKey, string imagePath)
        {
            var bSuccess = false;
            byte[] imagePathBytes = Encoding.Unicode.GetBytes(imagePath);

            using (var valueName = new UNICODE_STRING("ImagePath"))
            {
                NTSTATUS ntstatus;
                var nInfoLength = (uint)((imagePathBytes.Length > 1024) ? imagePathBytes.Length : 1024);
                IntPtr pInfoBuffer = Marshal.AllocHGlobal((int)nInfoLength);

                do
                {
                    KEY_VALUE_BASIC_INFORMATION info;
                    ntstatus = NativeMethods.NtQueryValueKey(
                        hKey,
                        in valueName,
                        KEY_VALUE_INFORMATION_CLASS.KeyValueBasicInformation,
                        pInfoBuffer,
                        nInfoLength,
                        out _);

                    if (ntstatus != Win32Consts.STATUS_SUCCESS)
                        break;

                    info = (KEY_VALUE_BASIC_INFORMATION)Marshal.PtrToStructure(
                        pInfoBuffer,
                        typeof(KEY_VALUE_BASIC_INFORMATION));
                    Marshal.Copy(imagePathBytes, 0, pInfoBuffer, imagePathBytes.Length);
                    nInfoLength = (uint)imagePathBytes.Length;

                    ntstatus = NativeMethods.NtSetValueKey(
                        hKey,
                        in valueName,
                        IntPtr.Zero,
                        info.Type,
                        pInfoBuffer,
                        nInfoLength);
                    bSuccess = (ntstatus == Win32Consts.STATUS_SUCCESS);
                } while (false);

                Marshal.FreeHGlobal(pInfoBuffer);
            }

            return bSuccess;
        }
    }
}
