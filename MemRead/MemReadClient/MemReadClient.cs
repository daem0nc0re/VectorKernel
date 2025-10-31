using System;
using System.Collections.Generic;
using MemReadClient.Handler;

namespace MemReadClient
{
    internal class MemReadClient
    {
        static void Main(string[] args)
        {
            var options = new CommandLineParser();
            var exclusive = new List<string> { "list", "read" };

            try
            {
                options.SetTitle("MemReadClient - Client for MemReadDrv.");
                options.AddFlag(false, "h", "help", "Displays this help message.");
                options.AddFlag(false, "l", "list", "Flag to list memory mapping information.");
                options.AddFlag(false, "r", "read", "Flag to read memory content.");
                options.AddParameter(false, "p", "pid", null, "Specifies a target PID.");
                options.AddParameter(false, "b", "base", null, "Specifies base address to read. Use with -r flag.");
                options.AddParameter(false, "s", "size", null, "Specifies size to read. Use with -r flag.");
                options.AddExclusive(exclusive);
                options.Parse(args);

                Execute.Run(options);
            }
            catch (InvalidOperationException ex)
            {
                Console.WriteLine(ex.Message);
            }
            catch (ArgumentException ex)
            {
                options.GetHelp();
                Console.WriteLine(ex.Message);
            }
        }
    }
}
