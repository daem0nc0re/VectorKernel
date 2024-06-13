using System;
using ElevateHandleClient.Library;

namespace ElevateHandleClient.Handler
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

            if (string.IsNullOrEmpty(options.GetValue("name")))
            {
                Console.WriteLine("\n[-] Service name is not specified.\n");
                return;
            }

            if (string.IsNullOrEmpty(options.GetValue("command")))
            {
                Console.WriteLine("\n[-] ImagePath value is not specified.\n");
                return;
            }

            Console.WriteLine();
            Modules.ModifyServiceBinaryPath(options.GetValue("name"), options.GetValue("command"));
            Console.WriteLine();
        }
    }
}
