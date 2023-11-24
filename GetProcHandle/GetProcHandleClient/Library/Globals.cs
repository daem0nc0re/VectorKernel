namespace GetProcHandleClient.Library
{
    internal class Globals
    {
        public static uint IOCTL_GET_PROC_HANDLE { get; } = 0x80000400u;
        public static string SYMLINK_PATH { get; } = @"\??\GetProcHandle";
    }
}
