using System;
using GetProcHandleClient.Handler;

namespace GetProcHandleClient
{
    internal class GetProcHandleClient
    {
        static void Main(string[] args)
        {
            var options = new CommandLineParser();

            try
            {
                options.SetTitle("GetProcHandleClient - Client for GetProcHandleDrv.");
                options.AddFlag(false, "h", "help", "Displays this help message.");
                options.AddParameter(false, "c", "command", "cmd.exe", "Specifies command to execute. Default is \"cmd.exe\".");
                options.AddParameter(true, "p", "pid", null, "Specifies PID of parent process.");
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
