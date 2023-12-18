using System;
using DropProcAccessClient.Library;

namespace DropProcAccessClient.Handler
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

            if (!string.IsNullOrEmpty(options.GetValue("pid")))
            {
                int pid;

                try
                {
                    pid = Convert.ToInt32(options.GetValue("pid"), 10);
                }
                catch
                {
                    Console.WriteLine("[!] Failed to parse PID.");
                    return;
                }

                Modules.SetProcessGuard(pid);
            }
            else if (options.GetFlag("remove"))
            {
                Modules.RemoveProcessGuard();
            }
            else
            {
                Console.WriteLine("[!] -p option or -r flag must be specified.");
            }

            Console.WriteLine();
        }
    }
}
