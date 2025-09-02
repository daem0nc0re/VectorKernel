using System;
using System.Collections.Generic;
using FileDirHideClient.Handler;

namespace FileDirHideClient
{
    internal class FileDirHideClient
    {
        static void Main(string[] args)
        {
            var options = new CommandLineParser();
            var exclusive = new List<string> { "path", "remove", "flush" };

            try
            {
                options.SetTitle("FileDirHideClient - Client for FileDirHideDrv.");
                options.AddFlag(false, "h", "help", "Displays this help message.");
                options.AddParameter(false, "p", "path", string.Empty, "Specifies file/directory path to hide.");
                options.AddParameter(false, "r", "remove", string.Empty, "Specifies index of file/directory path to remove from hiding entries.");
                options.AddFlag(false, "f", "flush", "Flag to remove all hiding entries.");
                options.AddFlag(false, "l", "list", "Flag to list all hiding entries.");
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
