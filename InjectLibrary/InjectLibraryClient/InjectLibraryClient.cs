using System;
using System.Collections.Generic;
using InjectLibraryClient.Handler;

namespace InjectLibraryClient
{
    internal class InjectLibraryClient
    {
        static void Main(string[] args)
        {
            var options = new CommandLineParser();

            try
            {
                options.SetTitle("InjectLibraryClient - Client for InjectLibraryDrv.");
                options.AddFlag(false, "h", "help", "Displays this help message.");
                options.AddParameter(true, "l", "library", null, "Specifies a DLL file to inject.");
                options.AddParameter(false, "c", "command", null, "Specifies a command to create injection testing process.");
                options.AddParameter(false, "t", "tid", null, "Specifies a target thread ID in decimal format.");
                options.AddExclusive(new List<string> { "command", "tid" });
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
