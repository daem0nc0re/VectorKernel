using System;
using ProcHideClient.Handler;

namespace ProcHideClient
{
    internal class ProcHideClient
    {
        static void Main(string[] args)
        {
            var options = new CommandLineParser();

            try
            {
                options.SetTitle("ProcHideClient - Client for ProcHideDrv.");
                options.AddFlag(false, "h", "help", "Displays this help message.");
                options.AddParameter(true, "p", "pid", null, "Specifies a target PID in decimal format.");
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
