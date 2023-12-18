namespace DropProcAccessClient.Library
{
    internal class Globals
    {
        public static uint IOCTL_SET_PROCESS_GUARD { get; } = 0x80002C00u;
        public static uint IOCTL_REMOVE_PROCESS_GUARD { get; } = 0x80002C04u;
        public static string SYMLINK_PATH { get; } = @"\??\DropProcAccess";
    }
}
