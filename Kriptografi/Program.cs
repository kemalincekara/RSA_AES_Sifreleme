using Kemalincekara.Kriptografi;
using System;
using System.Security.Cryptography;
using System.Text;

namespace Kriptografi
{
    public class Program
    {
        [STAThread]
        private static void Main(string[] args)
        {
            try
            {
                string publicKey = RSA_AES.Instance.ToXmlString(false);
                string privateKey = RSA_AES.Instance.ToXmlString(true);

                Console.WriteLine("Public Key\t: {0}\r\n", publicKey);
                Console.WriteLine("Private Key\t:{0}\r\n", privateKey);

                string metin = "{ KeMaL; }";

                byte[] orijinal = Encoding.UTF8.GetBytes(metin);
                byte[] sifrele = RSA_AES.Instance.SifreleHibrit(orijinal);
                byte[] cozuldu = RSA_AES.Instance.CozumleHibrit(sifrele);

                string cozumMetin = Encoding.UTF8.GetString(cozuldu);

                Console.WriteLine("Orijinal\t: {0}\r\n", metin);
                Console.WriteLine("Sifrelenmiş\t: {0}\r\n", Convert.ToBase64String(sifrele));
                Console.WriteLine("Çözüm\t\t: {0}\r\n", cozumMetin);
                Console.Write("MD5\t\t: ");

                if (BitConverter.ToString(MD5.Create().ComputeHash(orijinal)) == BitConverter.ToString(MD5.Create().ComputeHash(cozuldu)))
                    Console.WriteLine("Doğrulandı.");
                else
                    Console.WriteLine("Yanlış.");

            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());
            }
            finally
            {
                Console.WriteLine("\r\n\nBir tuşa bas...");
                Console.ReadKey();
            }
        }
    }
}