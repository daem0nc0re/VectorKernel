using System;
using ModHideClient.Handler;

namespace ModHideClient
{
    internal class ModHideClient
    {
        static void Main(string[] args)
        {
            var options = new CommandLineParser();

            try
            {
                options.SetTitle("ModHideClient - Client for ModHideDrv.");
                options.AddFlag(false, "h", "help", "Displays this help message.");
                options.AddParameter(true, "n", "name", null, "Specifies a complete file name of kernel driver to hide from NtQuerySystemInformation() API.");
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
