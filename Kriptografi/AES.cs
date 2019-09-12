using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Kemalincekara.Kriptografi
{
    public class AES : IDisposable
    {
        public enum Cryptor
        {
            Encrypt, Decrypt
        }

        #region " Properties "
        public int FileReadChunkSize { get; set; }
        public int KeySize { get => SymmetricKey.KeySize; set => SymmetricKey.KeySize = value; }
        public int BlockSize { get => SymmetricKey.BlockSize; set => SymmetricKey.BlockSize = value; }
        public CipherMode Mode { get => SymmetricKey.Mode; set => SymmetricKey.Mode = value; }
        public PaddingMode Padding { get => SymmetricKey.Padding; set => SymmetricKey.Padding = value; }
        /// <summary>
        /// Anahtar
        /// </summary>
        public byte[] Key { get => SymmetricKey.Key; set => SymmetricKey.Key = value; }
        /// <summary>
        /// Initialization vector (Başlatma Vektörü)
        /// </summary>
        public byte[] IV { get => SymmetricKey.IV; set => SymmetricKey.IV = value; }
        #endregion
        #region " Fields "
        private RijndaelManaged SymmetricKey;
        #endregion
        #region " Constructor "
        public AES()
        {
            FileReadChunkSize = 32768;
            SymmetricKey = new RijndaelManaged()
            {
                KeySize = 256,
                BlockSize = 256,
                Mode = CipherMode.CBC,
                Padding = PaddingMode.PKCS7
            };
            GenerateKeyIV();
        }
        #endregion
        #region " Methods "
        /// <summary>
        /// Key ve IV oluşturmak için
        /// </summary>
        /// <param name="password">Ana parola</param>
        /// <param name="salt">Salt anahtarı</param>
        public void GenerateKeyIV(string password, string salt)
        {
            byte[] saltBytes = Encoding.ASCII.GetBytes(salt);
            byte[] passwordBytes = Encoding.ASCII.GetBytes(password);
            using (Rfc2898DeriveBytes rfc = new Rfc2898DeriveBytes(passwordBytes, saltBytes, 10000))
            {
                Key = rfc.GetBytes(KeySize / 8);
                IV = rfc.GetBytes(BlockSize / 8);
            }
        }

        /// <summary>
        /// Rastgele Key ve IV oluşturur.
        /// </summary>
        public void GenerateKeyIV()
        {
            SymmetricKey.GenerateKey();
            SymmetricKey.GenerateIV();
        }

        /// <summary>
        /// AES Rijndael ile verileri şifreleme ve çözümleme
        /// </summary>
        /// <param name="sourceFileName">Şifrelemek|Çözümlemek istediğiniz dosyanın tam adresi</param>
        /// <param name="targetFileName">Yeni kaydetmek istediğiniz dosyanın tam adresi</param>
        /// <param name="cryptor">İşlem yönü</param>
        /// <returns></returns>
        public async Task ProcessAsync(string sourceFileName, string targetFileName, Cryptor cryptor)
        {
            if (!File.Exists(sourceFileName))
                throw new FileNotFoundException("Dosya bulunamadı!", sourceFileName);
            using (BufferedStream input = new BufferedStream(File.OpenRead(sourceFileName), FileReadChunkSize))
            using (FileStream output = File.OpenWrite(targetFileName))
                await ProcessAsync(input, output, cryptor);
        }

        /// <summary>
        /// AES Rijndael ile verileri şifreleme ve çözümleme
        /// </summary>
        /// <param name="sourceFileName">Şifrelemek|Çözümlemek istediğiniz dosya için FileStream</param>
        /// <param name="targetFileName">Yeni kaydetmek istediğiniz dosya için FileStream</param>
        /// <param name="cryptor">İşlem yönü</param>
        /// <returns></returns>
        public async Task ProcessAsync(BufferedStream sourceFile, FileStream targetFile, Cryptor cryptor)
        {
            using (var createCryptor = cryptor == Cryptor.Encrypt ? SymmetricKey.CreateEncryptor() : SymmetricKey.CreateDecryptor())
            using (CryptoStream cs = new CryptoStream(targetFile, createCryptor, CryptoStreamMode.Write))
            {
                byte[] chunkData = new byte[FileReadChunkSize];
                int read = 0;
                while ((read = await sourceFile.ReadAsync(chunkData, 0, FileReadChunkSize)) > 0)
                    await cs.WriteAsync(chunkData, 0, read);
                if (!cs.HasFlushedFinalBlock)
                    cs.FlushFinalBlock();
            }
        }

        /// <summary>
        /// AES Rijndael ile verileri şifreleme ve çözümleme
        /// </summary>
        /// <param name="data">Orijinal|Şifreli Veri girişi</param>
        /// <param name="cryptor">İşlem yönü</param>
        /// <returns>Şifreli|Çözülmüş veriyi döndürür</returns>
        public async Task<byte[]> ProcessAsync(byte[] data, Cryptor cryptor)
        {
            using (var output = new MemoryStream())
            using (var createCryptor = cryptor == Cryptor.Encrypt ? SymmetricKey.CreateEncryptor() : SymmetricKey.CreateDecryptor())
            using (CryptoStream cs = new CryptoStream(output, createCryptor, CryptoStreamMode.Write))
            {
                await cs.WriteAsync(data, 0, data.Length);
                if (!cs.HasFlushedFinalBlock)
                    cs.FlushFinalBlock();
                return output.ToArray();
            }
        }

        public void Dispose()
        {
            SymmetricKey.Dispose();
            SymmetricKey = null;
            GC.SuppressFinalize(this);
        }
        #endregion
    }
}
