namespace GetFullPrivsClient.Library
{
    internal class Globals
    {
        public static uint IOCTL_GET_ALL_PRIVS { get; } = 0x80000800u;
        public static string SYMLINK_PATH { get; } = @"\??\GetFullPrivs";
    }
}
