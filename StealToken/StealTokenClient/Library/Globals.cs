namespace StealTokenClient.Library
{
    internal class Globals
    {
        public static uint IOCTL_STEAL_TOKEN { get; } = 0x80001000u;
        public static string SYMLINK_PATH { get; } = @"\??\StealToken";
    }
}
