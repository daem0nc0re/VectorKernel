using System;
using BlockNewProcClient.Library;

namespace BlockNewProcClient.Handler
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

            if (!string.IsNullOrEmpty(options.GetValue("name")))
                Modules.SetBlockProcessName(options.GetValue("name"));
            else if (options.GetFlag("unregister"))
                Modules.UnregisterProcessBlockingCallback();
            else
                Console.WriteLine("[-] No options. Check -h option.");

            Console.WriteLine();
        }
    }
}
