using System;
using System.Text.RegularExpressions;
using MemReadClient.Library;

namespace MemReadClient.Handler
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

            Console.WriteLine();

            do
            {
                uint pid = 0u;
                uint nSize = 0u;
                IntPtr pBaseAddress = new IntPtr(-1);
                var hexPattern = new Regex(@"^0x[0-9A-Fa-f]{1,16}$");

                if (string.IsNullOrEmpty(options.GetValue("pid")))
                {
                    pid = 0;
                }
                else
                {
                    try
                    {
                        if (hexPattern.IsMatch(options.GetValue("pid")))
                            pid = (uint)Convert.ToInt32(options.GetValue("pid"), 16);
                        else
                            pid = (uint)Convert.ToInt32(options.GetValue("pid"), 10);
                    }
                    catch
                    {
                        Console.WriteLine("[-] Failed to parse PID.");
                        break;
                    }
                }

                if (string.IsNullOrEmpty(options.GetValue("base")))
                {
                    pBaseAddress = IntPtr.Zero;
                }
                else
                {
                    try
                    {
                        if (Environment.Is64BitProcess)
                        {
                            if (hexPattern.IsMatch(options.GetValue("base")))
                                pBaseAddress = new IntPtr(Convert.ToInt64(options.GetValue("base"), 16));
                            else
                                pBaseAddress = new IntPtr(Convert.ToInt64(options.GetValue("base"), 10));
                        }
                        else
                        {
                            if (hexPattern.IsMatch(options.GetValue("base")))
                                pBaseAddress = new IntPtr(Convert.ToInt32(options.GetValue("base"), 16));
                            else
                                pBaseAddress = new IntPtr(Convert.ToInt32(options.GetValue("base"), 10));
                        }
                    }
                    catch
                    {
                        Console.WriteLine("[-] Failed to parse base address.");
                        break;
                    }
                }

                if (string.IsNullOrEmpty(options.GetValue("size")))
                {
                    nSize = 0;
                }
                else
                {
                    try
                    {
                        if (hexPattern.IsMatch(options.GetValue("size")))
                            nSize = (uint)Convert.ToInt32(options.GetValue("size"), 16);
                        else
                            nSize = (uint)Convert.ToInt32(options.GetValue("size"), 10);
                    }
                    catch
                    {
                        Console.WriteLine("[-] Failed to parse memory size.");
                        break;
                    }
                }

                if (options.GetFlag("list") && (pid != 0))
                {
                    if (pid == 0)
                        Console.WriteLine("[-] Invalid PID.");
                    else
                        Modules.GetMemoryMappingInformation(pid);
                }
                else if (options.GetFlag("read") && (pid != 0))
                {
                    if (pid == 0)
                        Console.WriteLine("[-] Invalid PID.");
                    else if (pBaseAddress == new IntPtr(-1))
                        Console.WriteLine("[-] Invalid base address.");
                    else if (nSize == 0)
                        Console.WriteLine("[-] Invalid memory range.");
                    else
                        Modules.ReadMemory(pid, pBaseAddress, nSize);
                }
                else
                {
                    Console.WriteLine("[-] No options. Try -h flag.");
                }
            } while (false);

            Console.WriteLine();
        }
    }
}
