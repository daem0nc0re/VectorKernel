namespace BlockImageLoadClient.Library
{
    internal class Globals
    {
        public static uint IOCTL_SET_MODULE_BLOCK { get; } = 0x80003000u;
        public static uint IOCTL_UNSET_MODULE_BLOCK { get; } = 0x80003004u;
        public static string SYMLINK_PATH { get; } = @"\??\BlockImageLoad";
    }
}
