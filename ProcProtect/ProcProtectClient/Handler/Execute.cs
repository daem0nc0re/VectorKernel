using System;
using ProcProtectClient.Library;

namespace ProcProtectClient.Handler
{
    internal class Execute
    {
        public static void Run(CommandLineParser options)
        {
            if (options.GetFlag("help"))
            {
                options.GetHelp();
                return;
            }

            int pid;
            uint protectedType = 0u;
            uint protectedSigner = 0u;
            uint signatureLevel = 0u;
            uint sectionSignatureLevel = 0u;

            if (string.IsNullOrEmpty(options.GetValue("pid")))
            {
                Console.WriteLine("\n[-] PID is not specified.\n");
                return;
            }
            else
            {
                try
                {
                    pid = Convert.ToInt32(options.GetValue("pid"), 10);
                }
                catch
                {
                    Console.WriteLine("\n[!] Failed to parse PID.\n");
                    return;
                }
            }

            if (!string.IsNullOrEmpty(options.GetValue("type")))
            {
                try
                {
                    protectedType = (uint)Convert.ToInt32(options.GetValue("type"), 10);
                }
                catch
                {
                    Console.WriteLine("\n[!] Failed to parse ProtectedType.\n");
                    return;
                }
            }

            if (!string.IsNullOrEmpty(options.GetValue("signer")))
            {
                try
                {
                    protectedSigner = (uint)Convert.ToInt32(options.GetValue("signer"), 10);
                }
                catch
                {
                    Console.WriteLine("\n[!] Failed to parse ProtectedSigner.\n");
                    return;
                }
            }

            if (!string.IsNullOrEmpty(options.GetValue("level")))
            {
                try
                {
                    signatureLevel = (uint)Convert.ToInt32(options.GetValue("level"), 10);
                }
                catch
                {
                    Console.WriteLine("\n[!] Failed to parse SignatureLevel.\n");
                    return;
                }
            }

            if (!string.IsNullOrEmpty(options.GetValue("section")))
            {
                try
                {
                    sectionSignatureLevel = (uint)Convert.ToInt32(options.GetValue("section"), 10);
                }
                catch
                {
                    Console.WriteLine("\n[!] Failed to parse SectionSignatureLevel.\n");
                    return;
                }
            }

            Console.WriteLine();

            if (options.GetFlag("get"))
            {
                Modules.GetProtectionInformation(pid);
            }
            else if (options.GetFlag("update"))
            {
                Modules.SetProtection(
                    pid,
                    protectedType,
                    protectedSigner,
                    signatureLevel,
                    sectionSignatureLevel);
            }
            else
            {
                Console.WriteLine("[!] -g or -u flag must be specified.");
            }

            Console.WriteLine();
        }
    }
}
