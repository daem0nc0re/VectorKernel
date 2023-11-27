namespace QueryModuleClient.Library
{
    internal class Globals
    {
        public static uint IOCTL_QUERY_MODULE_INFO { get; } = 0x80001400u;
        public static string SYMLINK_PATH { get; } = @"\??\QueryModule";
    }
}
