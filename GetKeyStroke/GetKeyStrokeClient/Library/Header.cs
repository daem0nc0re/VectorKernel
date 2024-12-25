using System.Runtime.InteropServices;
using GetKeyStrokeClient.Interop;

namespace GetKeyStrokeClient.Library
{
    [StructLayout(LayoutKind.Sequential, Size = 24)]
    internal struct KEYSTROKE_INFORMATION
    {
        public LARGE_INTEGER TimeStamp;
        public KEYBOARD_INPUT_DATA KeyboardInput;
    }
}
