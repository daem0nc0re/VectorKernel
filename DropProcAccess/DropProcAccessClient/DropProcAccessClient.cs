using System;
using System.Collections.Generic;
using DropProcAccessClient.Handler;

namespace DropProcAccessClient
{
    internal class DropProcAccessClient
    {
        static void Main(string[] args)
        {
            var options = new CommandLineParser();

            try
            {
                options.SetTitle("DropProcAccessClient - Client for DropProcAccessDrv.");
                options.AddFlag(false, "h", "help", "Displays this help message.");
                options.AddFlag(false, "r", "remove", "Flag to Object Notify Callback to drop process handle access.");
                options.AddParameter(false, "p", "pid", null, "Specifies a target PID to protect in decimal format.");
                options.AddExclusive(new List<string> { "pid", "remove" });
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
