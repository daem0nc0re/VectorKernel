using System;
using InjectLibraryClient.Library;

namespace InjectLibraryClient.Handler
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

            if (string.IsNullOrEmpty(options.GetValue("library")))
            {
                Console.WriteLine("[-] DLL is not specified.");
            }
            else
            {
                if (string.IsNullOrEmpty(options.GetValue("tid")) &&
                    string.IsNullOrEmpty(options.GetValue("command")))
                {
                    Console.WriteLine("[-] Thread ID or command must be specified.");
                }
                else if (!string.IsNullOrEmpty(options.GetValue("tid")))
                {
                    int threadId;

                    try
                    {
                        threadId = Convert.ToInt32(options.GetValue("tid"), 10);
                    }
                    catch
                    {
                        threadId = -1;
                        Console.WriteLine("[-] Failed to parse thread ID.");
                    }

                    if (threadId > 0)
                        Modules.InjectDll(threadId, options.GetValue("library"));
                }
                else
                {
                    Modules.InjectDllWithCommand(options.GetValue("command"), options.GetValue("library"));
                }
            }

            Console.WriteLine();
        }
    }
}
