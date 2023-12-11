namespace CreateTokenClient.Library
{
    internal class Globals
    {
        public static uint IOCTL_CREATE_SYSTEM_TOKEN { get; } = 0x80002800u;
        public static string SYMLINK_PATH { get; } = @"\??\CreateToken";
    }
}
