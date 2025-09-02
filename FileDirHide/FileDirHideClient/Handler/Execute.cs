using System;
using FileDirHideClient.Library;

namespace FileDirHideClient.Handler
{
    internal class Execute
    {
        public static void Run(CommandLineParser options)
        {
            if (options.GetFlag("help"))
            {
                options.GetHelp();
                return;
            }

            Console.WriteLine();

            if (!string.IsNullOrEmpty(options.GetValue("path")))
            {
                Modules.SetFileDirectoryEntry(options.GetValue("path"));
            }
            else if (options.GetFlag("flush"))
            {
                Modules.RemoveAllFileDirectoryEntries();
            }
            else if (!string.IsNullOrEmpty(options.GetValue("remove")))
            {
                uint nIndex;

                try
                {
                    nIndex = (uint)Convert.ToInt32(options.GetValue("remove"), 10);
                    Modules.RemoveFileDirectoryEntry(nIndex);
                }
                catch
                {
                    Console.WriteLine("[-] Failed to parse index to remove.");
                }
            }
            else if (options.GetFlag("list"))
            {
                Modules.ListRegisteredFileDirectoryEntries();
            }
            else
            {
                Console.WriteLine("[-] No options. Check -h option.");
            }

            Console.WriteLine();
        }
    }
}
