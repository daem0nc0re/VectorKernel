namespace InjectLibraryClient.Library
{
    internal class Globals
    {
        public static uint IOCTL_INJECT_LIBRARY { get; } = 0x80001800u;
        public static string SYMLINK_PATH { get; } = @"\??\InjectLibrary";

    }
}
