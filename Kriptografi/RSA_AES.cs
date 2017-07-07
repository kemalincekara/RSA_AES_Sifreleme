#define NETFX40

using System;
using System.IO;
using System.Security.Cryptography;

namespace Kemalincekara.Kriptografi
{
    /// <summary>
    /// DEVELOPER KEMAL İNCEKARA
    /// </summary>
    internal sealed class RSA_AES : IDisposable
    {
        #region " Instance "
        private static RSA_AES _Instance;
        internal static RSA_AES Instance
        {
            get { return (_Instance = _Instance ?? new RSA_AES()); }
            set { _Instance = value; }
        }
        #endregion

        #region " Consts (Sabitler) "
        /// <summary>
        /// Benzersiz bir GUID giriniz.
        /// Her program için değiştirmeniz daha güvenli hâle getirecektir.
        /// </summary>
        private const string ID = "67144E3E-0201-458D-9DF1-907169846A42";

        /// <summary>
        /// RSA AYARLARI
        /// </summary>
        private const bool rsaPersistKeyInCsp = false;
        private const bool rsaOptimalAsymmetricEncryptionPadding = true;

        /// <summary>
        /// AES AYARLARI
        /// </summary>
        private const int aesKeySize = 256;
        private const int aesBlockSize = 128;
        private const CipherMode aesMode = CipherMode.CBC;
        private const PaddingMode aesPadding = PaddingMode.ISO10126;
        #endregion

        #region " Private Degiskenler "
        private RSACryptoServiceProvider rsa;
        #endregion

        #region " Constructor "
        internal RSA_AES(int KeySizeRSA = 1024)
        {
            if (!IsKeySizeRSADogrulama(KeySizeRSA))
                throw new ArgumentException("KeySize doğrulanamadı", "KeySizeRSA");

            rsa = new RSACryptoServiceProvider(KeySizeRSA);
            rsa.PersistKeyInCsp = rsaPersistKeyInCsp;
        }

        internal RSA_AES(string rsaKeyContainerName, int KeySizeRSA = 1024)
        {
            if (!IsKeySizeRSADogrulama(KeySizeRSA))
                throw new ArgumentException("RSA KeySize doğrulanamadı", "KeySizeRSA");

            CspParameters csp = new CspParameters();
            csp.KeyContainerName = rsaKeyContainerName;
            rsa = new RSACryptoServiceProvider(KeySizeRSA, csp);
            rsa.PersistKeyInCsp = rsaPersistKeyInCsp;
        }

        #endregion

        #region " Hibrit "
        /// <summary>
        /// RSA ve AES Karışımı Hibrit Kriptografi
        /// </summary>
        /// <param name="veri">Byte[] değerinden şifrelenecek veri</param>
        /// <returns>Kriptolanmış veriyi döndürür</returns>
        internal byte[] SifreleHibrit(byte[] veri)
        {
            if (veri == null || veri.Length == 0)
                throw new ArgumentException("Veri boş olamaz", "veri");

            byte[] Key = RastgeleByte(aesKeySize / 8);
            byte[] IV = RastgeleByte(aesBlockSize / 8);

            byte[] veriCrypt = SifreleAES(veri, Key, IV);
            byte[] KeyCrypt = SifreleRSA(Key);
            byte[] IVCrypt = SifreleRSA(IV);
            byte[] birlestir = new byte[veriCrypt.Length + KeyCrypt.Length + IVCrypt.Length];

            Buffer.BlockCopy(KeyCrypt, 0, birlestir, 0, KeyCrypt.Length);
            Buffer.BlockCopy(IVCrypt, 0, birlestir, KeyCrypt.Length, IVCrypt.Length);
            Buffer.BlockCopy(veriCrypt, 0, birlestir, KeyCrypt.Length + IVCrypt.Length, veriCrypt.Length);

            return birlestir;
        }

        /// <summary>
        /// RSA ve AES Karışımı Hibrit Kriptografi Çözümü
        /// </summary>
        /// <param name="veri">Byte[] değerinden şifrelenmiş veri</param>
        /// <returns>Kripto çözülmüş orijinal veriyi döndürür</returns>
        internal byte[] CozumleHibrit(byte[] veri)
        {
            if (veri == null || veri.Length == 0)
            {
                throw new ArgumentException("Veri boş olamaz", "veri");
            }

            byte[] KeyCrypt = new byte[rsa.KeySize >> 3];
            byte[] IVCrypt = new byte[rsa.KeySize >> 3];
            byte[] veriCrypt = new byte[veri.Length - KeyCrypt.Length - IVCrypt.Length];
            Buffer.BlockCopy(veri, 0, KeyCrypt, 0, KeyCrypt.Length);
            Buffer.BlockCopy(veri, KeyCrypt.Length, IVCrypt, 0, IVCrypt.Length);
            Buffer.BlockCopy(veri, KeyCrypt.Length + IVCrypt.Length, veriCrypt, 0, veriCrypt.Length);

            byte[] Key = CozumleRSA(KeyCrypt);
            byte[] IV = CozumleRSA(IVCrypt);

            return CozumleAES(veriCrypt, Key, IV);
        }
        #endregion

        #region " RSA "

        /// <summary>
        /// RSA Şifreleme
        /// </summary>
        /// <param name="veri">RSA ile şifrelenecek veri</param>
        /// <returns>RSA ile şifrelenmiş veriyi döndürür</returns>
        internal byte[] SifreleRSA(byte[] veri)
        {
            return rsa.Encrypt(veri, rsaOptimalAsymmetricEncryptionPadding);
        }

        /// <summary>
        /// RSA Şifrelenmiş veriyi çözümleme
        /// </summary>
        /// <param name="sifreliVeri">RSA ile şifrelenmiş veri</param>
        /// <returns>Orijinal veriyi döndürür</returns>
        internal byte[] CozumleRSA(byte[] sifreliVeri)
        {
            return rsa.Decrypt(sifreliVeri, rsaOptimalAsymmetricEncryptionPadding);
        }

        /// <summary>
        /// RSA Private veya Public kodu
        /// </summary>
        /// <param name="PrivateKodOlsunMu">Private kod dahil edilsin mi?</param>
        /// <returns>RSA Private veya Public kodunu döndürür</returns>
        internal string ToXmlString(bool PrivateKodOlsunMu)
        {
            return rsa.ToXmlString(PrivateKodOlsunMu);
        }

        /// <summary>
        /// RSA Private veya Public kodu
        /// </summary>
        /// <param name="XML">RSA Private veya Public kodu</param>
        internal void FromXmlString(string XML)
        {
            rsa.FromXmlString(XML);
        }

        /// <summary>  
        /// RSA Şifrelenecek maksimum veri uzunluğunu belirtir
        /// </summary>         
        /// <param name="keySize">RSA Key Size
        /// <returns>İzin verilen maksimum veri uzunluğu</returns>  
        private int MaxVeriUzunluguRSA(int keySize)
        {
            return rsaOptimalAsymmetricEncryptionPadding ? ((keySize - 384) / 8) + 7 : ((keySize - 384) / 8) + 37;
        }

        /// <summary>  
        /// RSA Key Size Doğrulaması
        /// </summary>         
        /// <param name="keySize">RSA Key Size
        /// <returns>Doğru ise true, aksi durumda false</returns>  
        private bool IsKeySizeRSADogrulama(int keySize)
        {
            return keySize >= 384 &&
                   keySize <= 16384 &&
                   keySize % 8 == 0;
        }
        #endregion

        #region " AES "

        /// <summary>
        /// AES Rijndael ile Şifreleme
        /// </summary>
        /// <param name="veri">AES ile şifrelenecek veri</param>
        /// <param name="Key">Anahtar</param>
        /// <param name="IV">Initialization vector (Başlatma Vektörü)</param>
        /// <returns>AES ile şifrelenmiş veriyi döndürür</returns>
        internal static byte[] SifreleAES(byte[] veri, byte[] Key, byte[] IV)
        {
            byte[] cikti;
            using (MemoryStream ms = new MemoryStream())
            using (Rijndael aes = Rijndael.Create()) // new RijndaelManaged
            {
                aes.BlockSize = aesBlockSize;
                aes.KeySize = aesKeySize;
                aes.Mode = aesMode;
                aes.Padding = aesPadding;
                aes.Key = Key;  // GetBytes(aes.KeySize / 8)
                aes.IV = IV;    // GetBytes(aes.BlockSize / 8)

                using (CryptoStream cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    cs.Write(veri, 0, veri.Length);
                    cs.FlushFinalBlock();
                }
                cikti = ms.ToArray();
            }
            return cikti;
        }

        /// <summary>
        /// AES Rijndael ile şifrelenmiş veriyi çözümleme
        /// </summary>
        /// <param name="sifreliVeri">Şifrelenmiş veri</param>
        /// <param name="Key">Anahtar</param>
        /// <param name="IV">Initialization vector (Başlatma Vektörü)</param>
        /// <returns>Orijinal veriyi döndürür</returns>
        internal static byte[] CozumleAES(byte[] sifreliVeri, byte[] Key, byte[] IV)
        {
            byte[] cikti;
            using (MemoryStream ms = new MemoryStream())
            using (var aes = Rijndael.Create()) //new RijndaelManaged
            {
                aes.BlockSize = aesBlockSize;
                aes.KeySize = aesKeySize;
                aes.Mode = aesMode;
                aes.Padding = aesPadding;
                aes.Key = Key;  // GetBytes(aes.KeySize / 8)
                aes.IV = IV;    // GetBytes(aes.BlockSize / 8)

                using (CryptoStream cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Write))
                {
                    cs.Write(sifreliVeri, 0, sifreliVeri.Length);
                    cs.FlushFinalBlock();
                }
                cikti = ms.ToArray();
            }
            return cikti;
        }

        #endregion

        #region " Metot "
        private byte[] RastgeleByte(int uzunluk)
        {
            byte[] cikti;
#if (NETFX20 || NETFX30 || NETFX35)
            RNGCryptoServiceProvider rastgeleSayiOlustur = new RNGCryptoServiceProvider();
#else
            using (RNGCryptoServiceProvider rastgeleSayiOlustur = new RNGCryptoServiceProvider())
#endif
            {
                cikti = new byte[uzunluk];
                rastgeleSayiOlustur.GetBytes(cikti);
            }
            return cikti;
        }

        public void Dispose()
        {

#if (NETFX20 || NETFX30 || NETFX35)
#else
            rsa.Dispose();
#endif
        }

        #endregion

    }
}
