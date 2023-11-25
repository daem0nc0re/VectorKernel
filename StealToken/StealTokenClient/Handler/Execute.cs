using System;
using StealTokenClient.Library;

namespace StealTokenClient.Handler
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

            int pid;

            if (string.IsNullOrEmpty(options.GetValue("pid")))
            {
                Console.WriteLine("\n[-] PID is not specified.\n");
                return;
            }
            else
            {
                try
                {
                    pid = Convert.ToInt32(options.GetValue("pid"), 10);
                }
                catch
                {
                    Console.WriteLine("\n[!] Failed to parse PID.\n");
                    return;
                }
            }

            Console.WriteLine();

            Modules.CreateTokenStealedProcess(pid, options.GetValue("command"));

            Console.WriteLine();
        }
    }
}
