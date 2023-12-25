using System;
using BlockImageLoadClient.Library;

namespace BlockImageLoadClient.Handler
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
                Modules.SetBlockImageName(options.GetValue("name"));
            else if (options.GetFlag("unregister"))
                Modules.UnregisterLoadImageBlockingCallback();
            else
                Console.WriteLine("[-] No options. Check -h option.");

            Console.WriteLine();
        }
    }
}
