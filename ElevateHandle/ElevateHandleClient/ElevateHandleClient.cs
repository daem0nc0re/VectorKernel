using System;
using ElevateHandleClient.Handler;

namespace ElevateHandleClient
{
    internal class ElevateHandleClient
    {
        static void Main(string[] args)
        {
            var options = new CommandLineParser();

            try
            {
                options.SetTitle("ElevateHandleClient - Client for ElevateHandleDrv.");
                options.AddFlag(false, "h", "help", "Displays this help message.");
                options.AddParameter(true, "n", "name", null, "Specifies a service name to overwrite ImagePath value.");
                options.AddParameter(true, "c", "command", null, "Specifies a command to set ImagePath value.");
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
