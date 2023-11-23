using System;
using GetProcHandleClient.Library;

namespace GetProcHandleClient.Handler
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

            if (string.IsNullOrEmpty("pid"))
            {
                Console.WriteLine("\n[-] PID is not specified.\n");
                return;
            }

            Console.WriteLine();

            try
            {
                int pid = Convert.ToInt32(options.GetValue("pid"), 10);

                if (pid < 0)
                    Console.WriteLine("\n[!] PID must be positive integer.\n");
                else
                    Modules.SpawnChildProcess(pid, options.GetValue("command"));
            }
            catch
            {
                Console.WriteLine("\n[!] Failed to parse PID.\n");
            }

            Console.WriteLine();
        }
    }
}
