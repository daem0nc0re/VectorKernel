using System;
using StealTokenClient.Handler;

namespace StealTokenClient
{
    internal class StealTokenClient
    {
        static void Main(string[] args)
        {
            var options = new CommandLineParser();

            try
            {
                options.SetTitle("StealTokenClient - Client for StealTokenDrv.");
                options.AddFlag(false, "h", "help", "Displays this help message.");
                options.AddParameter(true, "p", "pid", null, "Specifies a target PID in decimal format. Use with -s flag, or -e and -H flag.");
                options.AddParameter(false, "c", "command", "cmd.exe", "Specifies command to execute. Default is \"cmd.exe\".");
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
