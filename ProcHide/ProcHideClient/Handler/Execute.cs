using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using ProcHideClient.Library;

namespace ProcHideClient.Handler
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

            Modules.HideProcessByPid(pid);

            Console.WriteLine();
        }
    }
}
