namespace ElevateHandleClient.Library
{
    internal class Globals
    {
        public static uint IOCTL_ELEVATE_HANDLE { get; } = 0x80003400u;
        public static string SYMLINK_PATH { get; } = @"\??\ElevateHandle";
    }
}
