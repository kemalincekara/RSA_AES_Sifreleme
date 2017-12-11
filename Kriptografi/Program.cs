﻿using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Kemalincekara.Kriptografi
{
    public class Program
    {
        private static string testSourceFileName = "Kriptografi.exe";

        [STAThread]
        private static void Main(string[] args)
        {
            PerformansProfile("RSA-AES Hibrit Şifreleme | HybridTestFromMemoryAsync()", 1,
                  () => HybridTestFromMemoryAsync().Wait());


            PerformansProfile("AES-256 Bit Şifreleme | AesTestMemoryAsync()", 1,
                  () => AesTestMemoryAsync().Wait());


            if (File.Exists(testSourceFileName))
            {
                PerformansProfile("RSA-AES Hibrit Şifreleme | HybridTestFromFileAsync()", 1,
                     () => HybridTestFromFileAsync().Wait());

                PerformansProfile("AES-256 Bit Şifreleme | AesTestFromFileAsync()", 1,
                      () => AesTestFromFileAsync().Wait());
            }

            Console.ReadLine();
        }

        #region " Test Methods "
        private static async Task HybridTestFromMemoryAsync()
        {
            string publicKey = RsaAesHybrit.Instance.ToXmlString(false);
            string privateKey = RsaAesHybrit.Instance.ToXmlString(true);

            string metin = "{ KeMaL; }";

            byte[] orijinal = Encoding.UTF8.GetBytes(metin);
            byte[] sifrele = await RsaAesHybrit.Instance.EncryptAsync(orijinal);
            byte[] cozuldu = await RsaAesHybrit.Instance.DecryptAsync(sifrele);
            string cozumMetin = Encoding.UTF8.GetString(cozuldu);

            Console.WriteLine("Public Key\t: {0}\r\n", publicKey);
            Console.WriteLine("Private Key\t:{0}\r\n", privateKey);

            Console.WriteLine("Orijinal\t: {0}\r\n", metin);
            Console.WriteLine("Sifrelenmiş\t: {0}\r\n", Convert.ToBase64String(sifrele));
            Console.WriteLine("Çözüm\t\t: {0}\r\n", cozumMetin);
            LogAppend(ConsoleColor.White, "Hash\t\t: ");
            if (BitConverter.ToString(MD5.Create().ComputeHash(orijinal)) == BitConverter.ToString(MD5.Create().ComputeHash(cozuldu)))
                LogLine(ConsoleColor.Green, "Doğrulandı.");
            else
                LogLine(ConsoleColor.Red, "Yanlış.");
        }

        private static async Task HybridTestFromFileAsync()
        {
            Console.WriteLine("Lütfen bekleyiniz...");

            string targetFileNameEnc = Path.GetFileNameWithoutExtension(testSourceFileName) + "_encrypted.enc";
            string targetFileNameDec = Path.GetFileNameWithoutExtension(testSourceFileName) + "_decrypted.exe";

            if (File.Exists(targetFileNameEnc)) File.Delete(targetFileNameEnc);
            if (File.Exists(targetFileNameDec)) File.Delete(targetFileNameDec);

            await RsaAesHybrit.Instance.EncryptAsync(testSourceFileName, targetFileNameEnc);
            await RsaAesHybrit.Instance.DecryptAsync(targetFileNameEnc, targetFileNameDec);

            LogAppend(ConsoleColor.White, "Hash\t\t: ");
            if (MD5Hash(testSourceFileName) == MD5Hash(targetFileNameDec))
                LogLine(ConsoleColor.Green, "Doğrulandı.");
            else
                LogLine(ConsoleColor.Red, "Yanlış.");
        }

        private static async Task AesTestMemoryAsync()
        {
            string metin = "{ KeMaL; }";

            AES aes = new AES();
            byte[] orijinal = Encoding.UTF8.GetBytes(metin);
            byte[] sifrele = await aes.ProcessAsync(orijinal, AES.Cryptor.Encrypt);
            byte[] cozuldu = await aes.ProcessAsync(sifrele, AES.Cryptor.Decrypt);
            string cozumMetin = Encoding.UTF8.GetString(cozuldu);

            Console.WriteLine("Key Anahtarı\t: {0}\r\n", Convert.ToBase64String(aes.Key));
            Console.WriteLine("IV Anahtarı\t: {0}\r\n", Convert.ToBase64String(aes.IV));

            Console.WriteLine("AES-256 Bit Şifreleme");
            Console.WriteLine("Orijinal\t: {0}\r\n", metin);
            Console.WriteLine("Sifrelenmiş\t: {0}\r\n", Convert.ToBase64String(sifrele));
            Console.WriteLine("Çözüm\t\t: {0}\r\n", cozumMetin);
            LogAppend(ConsoleColor.White, "Hash\t\t: ");
            if (BitConverter.ToString(MD5.Create().ComputeHash(orijinal)) == BitConverter.ToString(MD5.Create().ComputeHash(cozuldu)))
                LogLine(ConsoleColor.Green, "Doğrulandı.");
            else
                LogLine(ConsoleColor.Red, "Yanlış.");
        }

        private static async Task AesTestFromFileAsync()
        {
            Console.WriteLine("Lütfen bekleyiniz...");

            string targetFileNameEnc = Path.GetFileNameWithoutExtension(testSourceFileName) + "_AES_encrypted.enc";
            string targetFileNameDec = Path.GetFileNameWithoutExtension(testSourceFileName) + "_AES_decrypted.exe";

            if (File.Exists(targetFileNameEnc)) File.Delete(targetFileNameEnc);
            if (File.Exists(targetFileNameDec)) File.Delete(targetFileNameDec);

            AES aes = new AES();
            await aes.ProcessAsync(testSourceFileName, targetFileNameEnc, AES.Cryptor.Encrypt);
            await aes.ProcessAsync(targetFileNameEnc, targetFileNameDec, AES.Cryptor.Decrypt);

            LogAppend(ConsoleColor.White, "Hash\t\t: ");

            if (MD5Hash(testSourceFileName) == MD5Hash(targetFileNameDec))
                LogLine(ConsoleColor.Green, "Doğrulandı.");
            else
                LogLine(ConsoleColor.Red, "Yanlış.");
        }
        #endregion

        #region " Helper Methods "
        public static string MD5Hash(string fileName)
        {
            using (var stream = new BufferedStream(File.OpenRead(fileName), 32768))
            {
                MD5 md5 = new MD5CryptoServiceProvider();
                byte[] hash = md5.ComputeHash(stream);
                StringBuilder stringBuilder = new StringBuilder();
                foreach (byte b in hash)
                    stringBuilder.AppendFormat("{0:x2}", b);
                return stringBuilder.ToString();
            }
        }
        public static void PerformansProfile(string description, int iterations, Action method)
        {
            LogLine(ConsoleColor.Yellow, new string('-', 67));
            LogLine(ConsoleColor.Blue, string.Format("[Profil: {0}]", description));

            GC.Collect();
            GC.WaitForPendingFinalizers();
            GC.Collect();

            var watch = Stopwatch.StartNew();
            for (int i = 0; i < iterations; i++)
                method();
            watch.Stop();
            LogLine(ConsoleColor.Green, string.Format("Geçen Zaman\t: {0:00}:{1:00}:{2:00}.{3:00}", watch.Elapsed.TotalHours, watch.Elapsed.TotalMinutes, watch.Elapsed.TotalSeconds, watch.Elapsed.TotalMilliseconds));
            LogLine(ConsoleColor.Yellow, new string('-', 67));
            Console.WriteLine(Environment.NewLine);
        }
        public static void LogLine(ConsoleColor color, string format, params object[] arg)
        {
            Console.BackgroundColor = ConsoleColor.Black;
            Console.ForegroundColor = color;
            Console.WriteLine(format, arg);
            Console.ForegroundColor = ConsoleColor.White;
        }
        public static void LogAppend(ConsoleColor color, string format, params object[] arg)
        {
            Console.ForegroundColor = color;
            Console.Write(format, arg);
            Console.ForegroundColor = ConsoleColor.White;
        }
        #endregion
    }
}