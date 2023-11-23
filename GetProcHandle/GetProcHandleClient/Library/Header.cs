namespace GetProcHandleClient.Library
{
    internal class Header
    {
        public const uint IOCTL_GET_PROC_HANDLE = 0x80000400u;
        public const string SYMLINK_PATH = @"\??\GetProcHandle";
    }
}
