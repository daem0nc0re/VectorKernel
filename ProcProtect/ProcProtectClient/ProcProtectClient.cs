using System;
using ProcProtectClient.Library;

namespace ProcProtectClient
{
    internal class ProcProtectClient
    {
        static void Main(string[] args)
        {
            if (args.Length == 0)
            {
                Console.WriteLine("Usage: ProcProtectClient.exe <PID>");
                return;
            }

            int pid;

            try
            {
                pid = Convert.ToInt32(args[0], 10);
                Modules.GetProtectionInformation(pid);
            }
            catch
            {
                Console.WriteLine("[-] Failed to parse PID.");
            }
        }
    }
}
