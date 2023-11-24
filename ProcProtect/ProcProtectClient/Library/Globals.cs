namespace ProcProtectClient.Library
{
    internal class Globals
    {
        public static uint IOCTL_SET_PROTECTION { get; } = 0x80000C00u;
        public static uint IOCTL_GET_PROTECTION { get; } = 0x80000C04u;
        public static string SYMLINK_PATH { get; } = @"\??\ProcProtect";
    }
}
