namespace ModHideClient.Library
{
    internal class Globals
    {
        public static uint IOCTL_HIDE_MODULE_BY_NAME { get; } = 0x80002000u;
        public static string SYMLINK_PATH { get; } = @"\??\ModHide";
    }
}
