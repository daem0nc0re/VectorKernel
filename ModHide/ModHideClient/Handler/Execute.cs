using System;
using ModHideClient.Library;

namespace ModHideClient.Handler
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

            Modules.HideModuleByName(options.GetValue("name"));

            Console.WriteLine();
        }
    }
}
