using System;
using System.IO;
using System.Runtime.InteropServices;
using GetKeyStrokeClient.Interop;

namespace GetKeyStrokeClient.Library
{
    using NTSTATUS = Int32;

    internal class Helpers
    {
        public static string ConvertLargeIntegerToLocalTimeString(LARGE_INTEGER fileTime)
        {
            string output = "N/A";

            if (NativeMethods.FileTimeToSystemTime(in fileTime, out SYSTEMTIME systemTime))
            {
                if (NativeMethods.SystemTimeToTzSpecificLocalTime(
                    IntPtr.Zero,
                    in systemTime,
                    out SYSTEMTIME localTime))
                {
                    output = string.Format("{0}/{1}/{2} {3}:{4}:{5}",
                        localTime.wYear.ToString("D4"),
                        localTime.wMonth.ToString("D2"),
                        localTime.wDay.ToString("D2"),
                        localTime.wHour.ToString("D2"),
                        localTime.wMinute.ToString("D2"),
                        localTime.wSecond.ToString("D2"));
                }
                else
                {
                    output = string.Format("{0}/{1}/{2} {3}:{4}:{5}",
                        systemTime.wYear.ToString("D4"),
                        systemTime.wMonth.ToString("D2"),
                        systemTime.wDay.ToString("D2"),
                        systemTime.wHour.ToString("D2"),
                        systemTime.wMinute.ToString("D2"),
                        systemTime.wSecond.ToString("D2"));
                }
            }

            return output;
        }


        public static uint GetFileSize(IntPtr hFile)
        {
            var nFileSize = 0u;
            var nInfoLength = (uint)Marshal.SizeOf(typeof(FILE_STANDARD_INFORMATION));
            var pInfoBuffer = Marshal.AllocHGlobal((int)nInfoLength);
            NTSTATUS ntstatus = NativeMethods.NtQueryInformationFile(
                hFile,
                out IO_STATUS_BLOCK _,
                pInfoBuffer,
                nInfoLength,
                FILE_INFORMATION_CLASS.FileStandardInformation);

            if (ntstatus == Win32Consts.STATUS_SUCCESS)
            {
                var info = (FILE_STANDARD_INFORMATION)Marshal.PtrToStructure(
                    pInfoBuffer,
                    typeof(FILE_STANDARD_INFORMATION));
                nFileSize = (uint)info.EndOfFile.Low;
            }

            Marshal.FreeHGlobal(pInfoBuffer);

            return nFileSize;
        }


        public static string GetFileDirectoryName(IntPtr hFile)
        {
            string nameString = null;
            var nInfoLength = (uint)Marshal.SizeOf(typeof(FILE_NAME_INFORMATION)) + 512u;
            var pInfoBuffer = Marshal.AllocHGlobal((int)nInfoLength);
            NTSTATUS ntstatus = NativeMethods.NtQueryInformationFile(
                hFile,
                out IO_STATUS_BLOCK _,
                pInfoBuffer,
                nInfoLength,
                FILE_INFORMATION_CLASS.FileNameInformation);

            if (ntstatus == Win32Consts.STATUS_SUCCESS)
            {
                IntPtr pNameString;
                var nNameOffset = Marshal.OffsetOf(typeof(FILE_NAME_INFORMATION), "FileName").ToInt32();
                var info = (FILE_NAME_INFORMATION)Marshal.PtrToStructure(
                    pInfoBuffer,
                    typeof(FILE_NAME_INFORMATION));

                if (Environment.Is64BitProcess)
                    pNameString = new IntPtr(pInfoBuffer.ToInt64() + nNameOffset);
                else
                    pNameString = new IntPtr(pInfoBuffer.ToInt32() + nNameOffset);

                if (info.FileNameLength > 0)
                {
                    nameString = string.Format("{0}{1}",
                        Environment.GetEnvironmentVariable("SystemDrive"),
                        Marshal.PtrToStringUni(pNameString, (int)info.FileNameLength / 2));
                }
            }

            Marshal.FreeHGlobal(pInfoBuffer);

            return nameString;
        }


        public static bool IsDirectoryHandle(IntPtr hFile)
        {
            var bIsDirectory = false;
            var nInfoLength = (uint)Marshal.SizeOf(typeof(FILE_BASIC_INFORMATION));
            var pInfoBuffer = Marshal.AllocHGlobal((int)nInfoLength);
            NTSTATUS ntstatus = NativeMethods.NtQueryInformationFile(
                hFile,
                out IO_STATUS_BLOCK _,
                pInfoBuffer,
                nInfoLength,
                FILE_INFORMATION_CLASS.FileBasicInformation);

            if (ntstatus == Win32Consts.STATUS_SUCCESS)
            {
                var info = (FILE_BASIC_INFORMATION)Marshal.PtrToStructure(
                    pInfoBuffer,
                    typeof(FILE_BASIC_INFORMATION));
                bIsDirectory = ((info.FileAttributes & FILE_ATTRIBUTE_FLAGS.Directory) == FILE_ATTRIBUTE_FLAGS.Directory);
            }

            Marshal.FreeHGlobal(pInfoBuffer);

            return bIsDirectory;
        }


        public static IntPtr ReadFileContents(IntPtr hFile, int nOffset, int nSize)
        {
            var pInfoBuffer = Marshal.AllocHGlobal(nSize);
            var bytesOffset = new LARGE_INTEGER {  High = 0, Low = nOffset };
            NTSTATUS ntstatus = NativeMethods.NtReadFile(
                hFile,
                IntPtr.Zero,
                IntPtr.Zero,
                IntPtr.Zero,
                out IO_STATUS_BLOCK ioStatusBlock,
                pInfoBuffer,
                (uint)nSize,
                in bytesOffset,
                IntPtr.Zero);

            if ((ntstatus != Win32Consts.STATUS_SUCCESS) ||
                ((int)ioStatusBlock.Information.ToUInt32() != nSize))
            {
                Marshal.FreeHGlobal(pInfoBuffer);
                pInfoBuffer = IntPtr.Zero;
            }

            return pInfoBuffer;
        }


        public static bool WaitFileCreation(IntPtr hDirectory, string fileName)
        {
            string directoryPath;
            string fullFileName;
            var bSuccess = false;

            if (!IsDirectoryHandle(hDirectory))
                return false;

            directoryPath = GetFileDirectoryName(hDirectory);

            if (string.IsNullOrEmpty(directoryPath))
                return false;

            fileName = Path.GetFileName(fileName);
            fullFileName = string.Format(@"{0}\{1}",
                directoryPath.TrimEnd('\\'),
                fileName);

            if (!File.Exists(fullFileName))
            {
                NTSTATUS ntstatus;

                do
                {
                    ntstatus = NativeMethods.NtNotifyChangeDirectoryFile(
                        hDirectory,
                        IntPtr.Zero,
                        IntPtr.Zero,
                        IntPtr.Zero,
                        out IO_STATUS_BLOCK _,
                        IntPtr.Zero,
                        0u,
                        FILE_NOTIFY_CHANGE_FLAGS.FileName | FILE_NOTIFY_CHANGE_FLAGS.Creation,
                        BOOLEAN.FALSE);

                    if (File.Exists(fullFileName))
                    {
                        bSuccess = true;
                        break;
                    }
                } while (ntstatus == Win32Consts.STATUS_NOTIFY_ENUM_DIR);
            }
            else
            {
                bSuccess = true;
            }

            return bSuccess;
        }
    }
}
