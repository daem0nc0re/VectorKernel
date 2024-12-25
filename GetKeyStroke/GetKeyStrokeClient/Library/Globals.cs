using System;

namespace GetKeyStrokeClient.Library
{
    internal class Globals
    {
        public static IntPtr StopEvent { get; set; } = IntPtr.Zero;
        public static int Timeout { get; set; } = 300; // miliseconds
    }
}
