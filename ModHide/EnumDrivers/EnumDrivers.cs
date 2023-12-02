using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using EnumDrivers.Interop;
using EnumDrivers.Library;

namespace EnumDrivers
{
    internal class EnumDrivers
    {
        static void Main()
        {
            bool bSuccess;
            var resultBuilder = new StringBuilder();
            resultBuilder.AppendLine();
            resultBuilder.AppendLine("[>] Trying to enumerate kernel drivers.");

            bSuccess = Helpers.GetModuleList(out List<RTL_PROCESS_MODULE_INFORMATION> modules);

            if (!bSuccess)
            {
                resultBuilder.AppendLine("[-] Failed to get module information.");
            }
            else
            {
                if (modules.Count > 0)
                {
                    resultBuilder.AppendFormat("[+] Got {0} modules.\n\n", modules.Count);

                    if (Environment.Is64BitProcess)
                    {
                        resultBuilder.AppendLine("Address            Module Name");
                        resultBuilder.AppendLine("================== ===========");
                    }
                    else
                    {
                        resultBuilder.AppendLine("Address    Module Name");
                        resultBuilder.AppendLine("========== ===========");
                    }

                    foreach (RTL_PROCESS_MODULE_INFORMATION mod in modules)
                    {
                        int nStrLen = 0;

                        for (int idx = 0; idx < 256; idx++)
                        {
                            if (mod.FullPathName[idx] == 0)
                                break;
                            else
                                nStrLen++;
                        }

                        resultBuilder.AppendFormat(
                            "0x{0} {1}\n",
                            mod.ImageBase.ToString(Environment.Is64BitProcess ? "X16" : "X8"),
                            Path.GetFileName(Encoding.ASCII.GetString(mod.FullPathName, 0, nStrLen)));
                    }

                    resultBuilder.AppendLine();
                }
                else
                {
                    resultBuilder.AppendLine("[*] No entries.");
                }
            }

            resultBuilder.AppendLine("[*] Done.");
            Console.WriteLine(resultBuilder.ToString());
        }
    }
}
