using System;
using System.Collections.Generic;
using ProcProtectClient.Handler;

namespace ProcProtectClient
{
    internal class ProcProtectClient
    {
        static void Main(string[] args)
        {
            var options = new CommandLineParser();

            try
            {
                options.SetTitle("ProcProtectClient - Client for ProcProtectDrv.");
                options.AddFlag(false, "h", "help", "Displays this help message.");
                options.AddFlag(false, "g", "get", "Flag to get protection information from process.");
                options.AddFlag(false, "u", "update", "Flag to update process protection.");
                options.AddParameter(true, "p", "pid", null, "Specifies a target PID in decimal format. Use with -s flag, or -e and -H flag.");
                options.AddParameter(false, "t", "type", null, "Specifies a ProtectedType in decimal format. Default is 0 (None).");
                options.AddParameter(false, "s", "signer", null, "Specifies a ProtectedSigner in decimal format. Default is 0 (None).");
                options.AddParameter(false, "l", "level", null, "Specifies a SignatureLevel in decimal format. Default is 0.");
                options.AddParameter(false, "S", "section", null, "Specifies a SectionSignatureLevel in decimal format. Default is 0.");
                options.AddExclusive(new List<string> { "get", "update" });
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
