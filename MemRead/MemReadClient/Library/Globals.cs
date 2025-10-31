namespace MemReadClient.Library
{
    internal class Globals
    {
        public static uint IOCTL_GET_MEMORY_MAPPING { get; } = 0x80003C00;
        public static uint IOCTL_READ_MEMORY { get; } = 0x80003C04;
        public static string SYMLINK_PATH { get; } = @"\??\MemRead";
    }
}
