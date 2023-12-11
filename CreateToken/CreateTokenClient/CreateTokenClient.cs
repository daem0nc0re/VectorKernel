using System;
using CreateTokenClient.Handler;

namespace CreateTokenClient
{
    internal class CreateTokenClient
    {
        static void Main(string[] args)
        {
            var options = new CommandLineParser();

            try
            {
                options.SetTitle("CreateTokenClient - Client for CreateTokenDrv.");
                options.AddFlag(false, "h", "help", "Displays this help message.");
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
