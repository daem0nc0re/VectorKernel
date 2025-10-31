using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using MemReadClient.Interop;

namespace MemReadClient.Library
{
    using NTSTATUS = Int32;

    internal class Helpers
    {
        public static Dictionary<string, string> GetDeviceMap()
        {
            var driveLetters = new List<string>();
            var deviceMap = new Dictionary<string, string>();
            var nInfoLength = (uint)Marshal.SizeOf(typeof(PROCESS_DEVICEMAP_INFORMATION));
            var pInfoBuffer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UNICODE_STRING)) + 512);
            NTSTATUS ntstatus = NativeMethods.NtQueryInformationProcess(
                new IntPtr(-1),
                PROCESSINFOCLASS.ProcessDeviceMap,
                pInfoBuffer,
                nInfoLength,
                out uint _);
            int nDeviceMap = Marshal.ReadInt32(pInfoBuffer);

            if (ntstatus == Win32Consts.STATUS_SUCCESS)
            {
                for (int idx = 0; idx < 0x1A; idx++)
                {
                    var nTestBit = (1 << idx);
                    var driveLetterBytes = new byte[] { (byte)(0x41 + idx), 0x3A };

                    if ((nDeviceMap & nTestBit) == nTestBit)
                        driveLetters.Add(Encoding.ASCII.GetString(driveLetterBytes));
                }
            }

            foreach (var letter in driveLetters)
            {
                IntPtr hSymlink;
                var unicodeString = new UNICODE_STRING { MaximumLength = 512 };

                using (var objectAttributes = new OBJECT_ATTRIBUTES(
                    string.Format(@"\GLOBAL??\{0}", letter),
                    OBJECT_ATTRIBUTES_FLAGS.CaseInsensitive))
                {
                    ntstatus = NativeMethods.NtOpenSymbolicLinkObject(
                        out hSymlink,
                        ACCESS_MASK.SYMBOLIC_LINK_QUERY,
                        in objectAttributes);
                }

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                    continue;

                if (Environment.Is64BitProcess)
                    unicodeString.SetBuffer(new IntPtr(pInfoBuffer.ToInt64() + Marshal.SizeOf(typeof(UNICODE_STRING))));
                else
                    unicodeString.SetBuffer(new IntPtr(pInfoBuffer.ToInt32() + Marshal.SizeOf(typeof(UNICODE_STRING))));

                Marshal.StructureToPtr(unicodeString, pInfoBuffer, true);

                ntstatus = NativeMethods.NtQuerySymbolicLinkObject(hSymlink, pInfoBuffer, out uint _);
                NativeMethods.NtClose(hSymlink);

                if (ntstatus == Win32Consts.STATUS_SUCCESS)
                {
                    var target = (UNICODE_STRING)Marshal.PtrToStructure(pInfoBuffer, typeof(UNICODE_STRING));

                    if (target.Length != 0)
                        deviceMap.Add(letter, target.ToString());
                }
            }

            Marshal.FreeHGlobal(pInfoBuffer);

            return deviceMap;
        }
    }
}
