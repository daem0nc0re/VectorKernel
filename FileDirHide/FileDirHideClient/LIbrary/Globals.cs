namespace FileDirHideClient.Library
{
    internal class Globals
    {
        public static uint IOCTL_LIST_REGISTERED_FILEDIR { get; } = 0x80003800u;
        public static uint IOCTL_REGISTER_FILEDIR { get; } = 0x80003804u;
        public static uint IOCTL_REMOVE_ALL_REGISTERED_FILEDIR { get; } = 0x80003808u;
        public static uint IOCTL_REMOVE_REGISTERED_FILEDIR { get; } = 0x8000380Cu;
        public static string SYMLINK_PATH { get; } = @"\??\FileDirHide";
    }
}
