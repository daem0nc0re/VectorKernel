namespace BlockNewProcClient.Library
{
    internal class Globals
    {
        public static uint IOCTL_SET_PROCESS_FILENAME { get; } = 0x80002400u;
        public static uint IOCTL_UNREGISTER_CALLBACK { get; } = 0x80002404u;
        public static string SYMLINK_PATH { get; } = @"\??\BlockNewProc";
    }
}
