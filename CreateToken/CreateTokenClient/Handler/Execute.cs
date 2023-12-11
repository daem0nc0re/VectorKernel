using System;
using CreateTokenClient.Library;

namespace CreateTokenClient.Handler
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

            if (!string.IsNullOrEmpty(options.GetValue("command")))
                Modules.GetPrivilegedTokenProcess(options.GetValue("command"));
            else
                Console.WriteLine("[-] No options. Check -h option.");

            Console.WriteLine();
        }
    }
}
