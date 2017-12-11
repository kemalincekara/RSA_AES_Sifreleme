using System;
using System.Security.Cryptography;

namespace Kemalincekara.Kriptografi
{
    public class RSA : IDisposable
    {
        #region " Properties "
        public bool PersistKeyInCsp { get => provider.PersistKeyInCsp; set => provider.PersistKeyInCsp = value; }
        public bool OptimalAsymmetricEncryptionPadding { get; set; }
        public int KeySize => provider.KeySize;
        #endregion
        #region " Fields "
        private RSACryptoServiceProvider provider;
        #endregion
        #region " Constructor "
        public RSA(int KeySize = 1024, string KeyContainerName = default(string))
        {
            if (!IsKeySizeValidated(KeySize))
                throw new ArgumentException("KeySize doğrulanamadı", "KeySize");

            OptimalAsymmetricEncryptionPadding = true;

            if (string.IsNullOrEmpty(KeyContainerName))
            {
                provider = new RSACryptoServiceProvider(KeySize)
                {
                    PersistKeyInCsp = false
                };
            }
            else
            {
                CspParameters csp = new CspParameters();
                csp.KeyContainerName = KeyContainerName;
                provider = new RSACryptoServiceProvider(KeySize, csp)
                {
                    PersistKeyInCsp = false
                };
            }
        }
        #endregion
        #region " Methods "

        /// <summary>
        /// RSA Şifreleme
        /// </summary>
        /// <param name="data">RSA ile şifrelenecek veri</param>
        /// <returns>RSA ile şifrelenmiş veriyi döndürür</returns>
        public byte[] Encrypt(byte[] data) => provider.Encrypt(data, OptimalAsymmetricEncryptionPadding);

        /// <summary>
        /// RSA Şifrelenmiş veriyi çözümleme
        /// </summary>
        /// <param name="data">RSA ile şifrelenmiş veri</param>
        /// <returns>Orijinal veriyi döndürür</returns>
        public byte[] Decrypt(byte[] data) => provider.Decrypt(data, OptimalAsymmetricEncryptionPadding);

        /// <summary>
        /// RSA Private veya Public kodu
        /// </summary>
        /// <param name="PrivateKodOlsunMu">Private kod dahil edilsin mi?</param>
        /// <returns>RSA Private veya Public kodunu döndürür</returns>
        public string ToXmlString(bool PrivateKodOlsunMu) => provider.ToXmlString(PrivateKodOlsunMu);

        /// <summary>
        /// RSA Private veya Public kodu
        /// </summary>
        /// <param name="XML">RSA Private veya Public kodu</param>
        public void FromXmlString(string XML) => provider.FromXmlString(XML);

        /// <summary>  
        /// RSA Şifrelenecek maksimum veri uzunluğunu belirtir
        /// </summary>         
        /// <param name="keySize">RSA Key Size</param>
        /// <returns>İzin verilen maksimum veri uzunluğu</returns>  
        public int MaxVeriUzunlugu(int keySize) => OptimalAsymmetricEncryptionPadding ? ((keySize - 384) / 8) + 7 : ((keySize - 384) / 8) + 37;

        /// <summary>  
        /// RSA Key Size Doğrulaması
        /// </summary>         
        /// <param name="keySize">RSA Key Size</param>
        /// <returns>Doğru ise true, aksi durumda false</returns>  
        private bool IsKeySizeValidated(int keySize) => keySize >= 384 && keySize <= 16384 && keySize % 8 == 0;

        public void Dispose()
        {
            provider.Dispose();
            provider = null;
            GC.SuppressFinalize(this);
        }
        #endregion
    }
}
