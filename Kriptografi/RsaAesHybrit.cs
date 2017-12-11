using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;

namespace Kemalincekara.Kriptografi
{
    public sealed class RsaAesHybrit : IDisposable
    {
        #region " Single Instance "
        private static RsaAesHybrit _Instance;
        public static RsaAesHybrit Instance
        {
            get { return (_Instance = _Instance ?? new RsaAesHybrit()); }
            set { _Instance = value; }
        }
        #endregion
        #region " Private Fields "
        private AES AES;
        private RSA RSA;
        #endregion
        #region " Constructor "
        public RsaAesHybrit()
        {
            AES = new AES();
            RSA = new RSA();
        }
        public RsaAesHybrit(AES aes, RSA rsa)
        {
            AES = aes;
            RSA = rsa;
        }
        #endregion
        #region " Methods "
        /// <summary>
        /// RSA ve AES Karışımı Hibrit Kriptografi
        /// </summary>
        /// <param name="data">string değerinden şifrelenecek veri</param>
        /// <returns>Kriptolanmış veriyi string değerinde döndürür</returns>
        public async Task<string> EncryptAsync(string data) => Convert.ToBase64String(await EncryptAsync(Encoding.UTF8.GetBytes(data)));
        /// <summary>
        /// RSA ve AES Karışımı Hibrit Kriptografi Çözümü
        /// </summary>
        /// <param name="data">string değerinden şifrelenmiş veri</param>
        /// <returns>Kripto çözülmüş orijinal veriyi string olarak döndürür</returns>
        public async Task<string> DecryptAsync(string data) => Encoding.UTF8.GetString(await DecryptAsync(Convert.FromBase64String(data)));

        /// <summary>
        /// RSA ve AES Karışımı Hibrit Kriptografi
        /// </summary>
        /// <param name="data">Byte[] değerinden şifrelenecek veri</param>
        /// <returns>Kriptolanmış veriyi döndürür</returns>
        public async Task<byte[]> EncryptAsync(byte[] data)
        {
            if (data == null || data.Length == 0)
                throw new ArgumentException("Veri boş olamaz", "veri");

            byte[] veriCrypt = await AES.ProcessAsync(data, AES.Cryptor.Encrypt);
            byte[] KeyCrypt = RSA.Encrypt(AES.Key);
            byte[] IVCrypt = RSA.Encrypt(AES.IV);
            byte[] birlestir = new byte[veriCrypt.Length + KeyCrypt.Length + IVCrypt.Length];

            Buffer.BlockCopy(KeyCrypt, 0, birlestir, 0, KeyCrypt.Length);
            Buffer.BlockCopy(IVCrypt, 0, birlestir, KeyCrypt.Length, IVCrypt.Length);
            Buffer.BlockCopy(veriCrypt, 0, birlestir, KeyCrypt.Length + IVCrypt.Length, veriCrypt.Length);

            return birlestir;
        }

        /// <summary>
        /// RSA ve AES Karışımı Hibrit Kriptografi Çözümü
        /// </summary>
        /// <param name="data">Byte[] değerinden şifrelenmiş veri</param>
        /// <returns>Kripto çözülmüş orijinal veriyi döndürür</returns>
        public async Task<byte[]> DecryptAsync(byte[] data)
        {
            if (data == null || data.Length == 0)
                throw new ArgumentException("Veri boş olamaz", "veri");

            byte[] KeyCrypt = new byte[RSA.KeySize >> 3];
            byte[] IVCrypt = new byte[RSA.KeySize >> 3];
            byte[] veriCrypt = new byte[data.Length - KeyCrypt.Length - IVCrypt.Length];
            Buffer.BlockCopy(data, 0, KeyCrypt, 0, KeyCrypt.Length);
            Buffer.BlockCopy(data, KeyCrypt.Length, IVCrypt, 0, IVCrypt.Length);
            Buffer.BlockCopy(data, KeyCrypt.Length + IVCrypt.Length, veriCrypt, 0, veriCrypt.Length);

            byte[] Key = RSA.Decrypt(KeyCrypt);
            byte[] IV = RSA.Decrypt(IVCrypt);

            return await AES.ProcessAsync(veriCrypt, AES.Cryptor.Decrypt);
        }

        /// <summary>
        /// RSA ve AES Karışımı Hibrit Kriptografi
        /// </summary>
        /// <param name="sourceFileName">Şifrelemek istediğiniz dosyanın tam adresi</param>
        /// <param name="targetFileName">Yeni kaydetmek istediğiniz dosyanın tam adresi</param>
        /// <returns></returns>
        public async Task EncryptAsync(string sourceFileName, string targetFileName)
        {
            if (!File.Exists(sourceFileName))
                throw new FileNotFoundException("Dosya bulunamadı!", sourceFileName);
            using (BufferedStream input = new BufferedStream(File.OpenRead(sourceFileName), AES.FileReadChunkSize))
            using (FileStream output = File.OpenWrite(targetFileName))
            {
                byte[] KeyCrypt = RSA.Encrypt(AES.Key);
                byte[] IVCrypt = RSA.Encrypt(AES.IV);
                await output.WriteAsync(KeyCrypt, 0, KeyCrypt.Length);
                await output.WriteAsync(IVCrypt, 0, IVCrypt.Length);
                await AES.ProcessAsync(input, output, AES.Cryptor.Encrypt);
            }
        }

        /// <summary>
        /// RSA ve AES Karışımı Hibrit Kriptografi Çözümü
        /// </summary>
        /// <param name="sourceFileName">Çözümlemek istediğiniz dosyanın tam adresi</param>
        /// <param name="targetFileName">Yeni kaydetmek istediğiniz dosyanın tam adresi</param>
        /// <returns></returns>
        public async Task DecryptAsync(string sourceFileName, string targetFileName)
        {
            if (!File.Exists(sourceFileName))
                throw new FileNotFoundException("Dosya bulunamadı!", sourceFileName);
            using (BufferedStream input = new BufferedStream(File.OpenRead(sourceFileName), AES.FileReadChunkSize))
            using (FileStream output = File.OpenWrite(targetFileName))
            {
                byte[] KeyCrypt = new byte[RSA.KeySize >> 3];
                byte[] IVCrypt = new byte[RSA.KeySize >> 3];
                await input.ReadAsync(KeyCrypt, 0, KeyCrypt.Length);
                await input.ReadAsync(IVCrypt, 0, IVCrypt.Length);
                AES.Key = RSA.Decrypt(KeyCrypt);
                AES.IV = RSA.Decrypt(IVCrypt);
                await AES.ProcessAsync(input, output, AES.Cryptor.Decrypt);
            }
        }

        /// <summary>
        /// RSA Private veya Public kodu
        /// </summary>
        /// <param name="PrivateKodOlsunMu">Private kod dahil edilsin mi?</param>
        /// <returns>RSA Private veya Public kodunu döndürür</returns>
        public string ToXmlString(bool PrivateKodOlsunMu) => RSA.ToXmlString(PrivateKodOlsunMu);

        /// <summary>
        /// RSA Private veya Public kodu
        /// </summary>
        /// <param name="XML">RSA Private veya Public kodu</param>
        public void FromXmlString(string XML) => RSA.FromXmlString(XML);

        public void Dispose()
        {
            RSA.Dispose();
            AES.Dispose();
            RSA = null;
            AES = null;
            GC.SuppressFinalize(this);
        }
        #endregion
    }
}
