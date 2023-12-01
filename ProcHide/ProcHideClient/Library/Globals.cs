namespace ProcHideClient.Library
{
    internal class Globals
    {
        public static uint IOCTL_HIDE_PROC_BY_PID { get; } = 0x80001C00u;
        public static string SYMLINK_PATH { get; } = @"\??\ProcHide";
    }
}
