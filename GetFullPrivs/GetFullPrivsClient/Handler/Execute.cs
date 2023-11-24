using System;
using GetFullPrivsClient.Library;

namespace GetFullPrivsClient.Handler
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

            Modules.CreateFullPrivilegedProcess(options.GetValue("command"));

            Console.WriteLine();
        }
    }
}
