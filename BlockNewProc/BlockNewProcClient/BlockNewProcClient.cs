using System;
using System.Collections.Generic;
using BlockNewProcClient.Handler;

namespace BlockNewProcClient
{
    internal class BlockNewProcClient
    {
        static void Main(string[] args)
        {
            var options = new CommandLineParser();

            try
            {
                options.SetTitle("BlockNewProcClient - Client for BlockNewProcDrv.");
                options.AddFlag(false, "h", "help", "Displays this help message.");
                options.AddFlag(false, "u", "unregister", "Flag to unregister callback.");
                options.AddParameter(false, "n", "name", null, "Specifies a image file name to block.");
                options.AddExclusive(new List<string> { "unregister", "name" });
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
