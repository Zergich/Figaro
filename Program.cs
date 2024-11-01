using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Figaro
{
    internal class Program
    {
        static byte[] ParseHexString(string hex)
        {
            byte[] bytes = new byte[hex.Length / 2];
            int shift = 4; int offset = 0;
            foreach (char c in hex)
            {
                int b = (c - '0') % 32;
                if (b > 9) b -= 7;
                bytes[offset] |= (byte)(b << shift);
                shift ^= 4;
                if (shift != 0) offset++;
            }
            return bytes;
        }
        static string GetHEX(string FileName)
        {
            byte[] File1 = File.ReadAllBytes(FileName.Trim('"'));
            string ResutlHEX = BitConverter.ToString(File1).Replace("-", "");

            return ResutlHEX;
        }
        static void Main(string[] args)// Переделать метод под 16 ричные кода
        {
            //byte[] text = Convert.FromBase64String("U2FsdGVkX1/BPVdL8izz+oJjntyHGMkM93qHTkFmsH3EDp2oZGrJoSegg/ZttJ4E9qAQ4qrpzpQZt6zI8srmNg==");
            //Console.WriteLine($"{text.Length * 8}");

            //string originalText = "Гончарук сука";
            //string key = "mysecretkey";

            //string encryptedText = XorEncrypt(originalText);
            //Console.WriteLine($"Зашифрованный текст: {encryptedText} {Encoding.UTF8.GetByteCount(encryptedText)}");

            //string decryptedText = XorDecrypt(encryptedText);
            //Console.WriteLine($"Расшифрованный текст: {decryptedText}");

            if (args.Length == 0)
            {
                Console.WriteLine("-ef - Шифрует файл.\n-t - Шифрует строку.\n-td - Дешифрует файл.\n-df - Дешифрует файл.");
                return;
            }
            try
            {
                switch (args[1])
                {
                    case "-ef": File.WriteAllText(args[0], XorEncrypt(GetHEX(args[0]))); break;
                    case "-t": Console.WriteLine(XorEncrypt(args[0])); break; // шифровать строку 
                    case "-td": Console.WriteLine(XorDecrypt(args[0])); ; break; // дешифрует файл
                    case "-df": File.WriteAllBytes(args[0], XorDecrypt(GetHEX(args[0]))); break;

                    default: Console.WriteLine("Файл не обнаружен или неверный аргумент."); break;
                }
            }
            catch { Console.WriteLine("Не удалось найти файл"); }

            //errpass:
            //    Console.Write("Пароль: ");

            //    Console.ForegroundColor = ConsoleColor.Black;
            //    Console.BackgroundColor = ConsoleColor.Black;

            //    string password = Console.ReadLine();
            //    if (password.Length < 8)
            //    {
            //        Console.ForegroundColor = ConsoleColor.Gray;
            //        Console.WriteLine("Длина пароля меньше 8 знаков!");
            //        goto errpass;
            //    }
            //    Console.ForegroundColor = ConsoleColor.Gray;


            //    string strKey = Hash(password);
        }
        static string Hash(string input)
        {
            using (SHA512Managed sha1 = new SHA512Managed())
            {
                var hash = sha1.ComputeHash(Encoding.UTF8.GetBytes(input));
                var sb = new StringBuilder(hash.Length * 2);
                foreach (byte b in hash)
                {
                    // can be "x2" if you want lowercase
                    sb.Append(b.ToString("X2"));
                }
                return sb.ToString();
            }
        }
        public static string XorEncrypt(string input)
        {
        errpass:
            Console.Write("Пароль: ");

            Console.ForegroundColor = ConsoleColor.Black;
            Console.BackgroundColor = ConsoleColor.Black;

            string password = Console.ReadLine();
            if (password.Length < 8)
            {
                Console.ForegroundColor = ConsoleColor.Gray;
                Console.WriteLine("Длина пароля меньше 8 знаков!");
                goto errpass;
            }
            Console.ForegroundColor = ConsoleColor.Gray;


            char[] data = input.ToCharArray();
            char[] keyData = Hash(password).ToCharArray();
            char[] result = new char[data.Length];

            int countargs = 0;
            foreach (char i in keyData) if (i == 'H' || i == 'A' || i == '7') countargs++;

            for (int i = 0; i < data.Length; i++)
            {
                result[i] = (char)(data[i] ^ keyData[i % keyData.Length ^ countargs * 8 >> keyData[keyData.Length - 4] ^ keyData[keyData.Length - 9]]);
            }
            string dobavit = new string(result);
            for (int i = 0; i < keyData.Length; i++)
            {
                if (Encoding.UTF8.GetByteCount(dobavit) >= 256) break;
                dobavit += (char)(keyData[i] ^ keyData[i % keyData.Length ^ countargs * 8 >> keyData[keyData.Length - 4] ^ keyData[keyData.Length - 9]]);
            }

            return Convert.ToBase64String(Encoding.UTF8.GetBytes(dobavit));
        }
        public static byte[] XorDecrypt(string input)
        {
        errpass:
            Console.Write("Пароль: ");

            Console.ForegroundColor = ConsoleColor.Black;
            Console.BackgroundColor = ConsoleColor.Black;

            string password = Console.ReadLine();
            if (password.Length < 8)
            {
                Console.ForegroundColor = ConsoleColor.Gray;
                Console.WriteLine("Длина пароля меньше 8 знаков!");
                goto errpass;
            }
            Console.ForegroundColor = ConsoleColor.Gray;

            input = Encoding.UTF8.GetString(ParseHexString(input));
            //Console.WriteLine(input);

            // Дешифрование очень похоже на шифрование, поскольку XOR - это обратимая операция.
            char[] data = Encoding.UTF8.GetString(Convert.FromBase64String(input)).ToCharArray();
            char[] keyData = Hash(password).ToCharArray();
            char[] result = new char[data.Length];

            //Regex getLength = new Regex("`~(.*)}");
            //MatchCollection match = getLength.Matches(new string(data));


            char[] notmaldata = new char[data.Length - keyData.Length];
            for (int i = 0; i < data.Length - keyData.Length; i++)
                notmaldata[i] = data[i];
            int getbyte = Encoding.UTF8.GetByteCount(new string(notmaldata));

            int countargs = 0;
            foreach (char i in keyData) if (i == 'H' || i == 'A' || i == '7') countargs++;

            if (getbyte <= 256)
            {
                for (int i = 0; i < notmaldata.Length; i++)
                {
                    result[i] = (char)(notmaldata[i] ^ keyData[i % keyData.Length ^ countargs * 8 >> keyData[keyData.Length - 4] ^ keyData[keyData.Length - 9]]);
                }
            }
            else
            {
                for (int i = 0; i < data.Length; i++)
                {
                    result[i] = (char)(data[i] ^ keyData[i % keyData.Length ^ countargs * 8 >> keyData[keyData.Length - 4] ^ keyData[keyData.Length - 9]]);
                }
            }


            return ParseHexString(new string(result));
        }
    }
}
