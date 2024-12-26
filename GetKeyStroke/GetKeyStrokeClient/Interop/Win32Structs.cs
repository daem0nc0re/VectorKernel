using System;
using System.Runtime.InteropServices;
using System.Text;

namespace GetKeyStrokeClient.Interop
{
    using NTSTATUS = Int32;

    [StructLayout(LayoutKind.Sequential, Size = 0x28)]
    internal struct FILE_BASIC_INFORMATION
    {
        public LARGE_INTEGER CreationTime;
        public LARGE_INTEGER LastAccessTime;
        public LARGE_INTEGER LastWriteTime;
        public LARGE_INTEGER ChangeTime;
        public FILE_ATTRIBUTE_FLAGS FileAttributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct FILE_NAME_INFORMATION
    {
        public uint FileNameLength;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
        public ushort[] FileName;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct FILE_STANDARD_INFORMATION
    {
        public LARGE_INTEGER AllocationSize;
        public LARGE_INTEGER EndOfFile;
        public uint NumberOfLinks;
        public BOOLEAN DeletePending;
        public BOOLEAN Directory;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct IO_STATUS_BLOCK
    {
        public NTSTATUS Status;
        public UIntPtr Information;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct KEYBOARD_INPUT_DATA
    {
        public ushort UnitId;
        public ushort MakeCode;
        public KEY_ACTION_FLAGS Flags;
        public ushort Reserved;
        public uint ExtraInformation;
    }

    [StructLayout(LayoutKind.Explicit, Pack = 4)]
    internal struct LARGE_INTEGER
    {
        [FieldOffset(0)]
        public int Low;
        [FieldOffset(4)]
        public int High;
        [FieldOffset(0)]
        public long QuadPart;

        public LARGE_INTEGER(int _low, int _high)
        {
            QuadPart = 0L;
            Low = _low;
            High = _high;
        }

        public LARGE_INTEGER(long _quad)
        {
            Low = 0;
            High = 0;
            QuadPart = _quad;
        }

        public long ToInt64()
        {
            return ((long)High << 32) | (uint)Low;
        }

        public static LARGE_INTEGER FromInt64(long value)
        {
            return new LARGE_INTEGER
            {
                Low = (int)(value),
                High = (int)((value >> 32))
            };
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct OBJECT_ATTRIBUTES : IDisposable
    {
        public int Length;
        public IntPtr RootDirectory;
        private IntPtr objectName;
        public OBJECT_ATTRIBUTES_FLAGS Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;

        public OBJECT_ATTRIBUTES(
            string name,
            OBJECT_ATTRIBUTES_FLAGS attrs)
        {
            Length = 0;
            RootDirectory = IntPtr.Zero;
            objectName = IntPtr.Zero;
            Attributes = attrs;
            SecurityDescriptor = IntPtr.Zero;
            SecurityQualityOfService = IntPtr.Zero;

            Length = Marshal.SizeOf(this);
            ObjectName = new UNICODE_STRING(name);
        }

        public UNICODE_STRING ObjectName
        {
            get
            {
                return (UNICODE_STRING)Marshal.PtrToStructure(
                 objectName, typeof(UNICODE_STRING));
            }

            set
            {
                bool fDeleteOld = objectName != IntPtr.Zero;
                if (!fDeleteOld)
                    objectName = Marshal.AllocHGlobal(Marshal.SizeOf(value));
                Marshal.StructureToPtr(value, objectName, fDeleteOld);
            }
        }

        public void Dispose()
        {
            if (objectName != IntPtr.Zero)
            {
                Marshal.DestroyStructure(objectName, typeof(UNICODE_STRING));
                Marshal.FreeHGlobal(objectName);
                objectName = IntPtr.Zero;
            }
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SYSTEMTIME
    {
        public short wYear;
        public short wMonth;
        public DAY_OF_WEEK wDayOfWeek;
        public short wDay;
        public short wHour;
        public short wMinute;
        public short wSecond;
        public short wMilliseconds;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct UNICODE_STRING : IDisposable
    {
        public ushort Length;
        public ushort MaximumLength;
        private IntPtr buffer;

        public UNICODE_STRING(string s)
        {
            byte[] bytes;

            if (string.IsNullOrEmpty(s))
            {
                Length = 0;
                bytes = new byte[2];
            }
            else
            {
                Length = (ushort)(s.Length * 2);
                bytes = Encoding.Unicode.GetBytes(s);
            }

            MaximumLength = (ushort)(Length + 2);
            buffer = Marshal.AllocHGlobal(MaximumLength);

            Marshal.Copy(new byte[MaximumLength], 0, buffer, MaximumLength);
            Marshal.Copy(bytes, 0, buffer, bytes.Length);
        }

        public void Dispose()
        {
            Marshal.FreeHGlobal(buffer);
            buffer = IntPtr.Zero;
        }

        public override string ToString()
        {
            return Marshal.PtrToStringUni(buffer, Length / 2);
        }

        public IntPtr GetBuffer()
        {
            return buffer;
        }

        public void SetBuffer(IntPtr _buffer)
        {
            buffer = _buffer;
        }
    }
}
