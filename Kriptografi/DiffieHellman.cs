using System;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Kemalincekara.Kriptografi
{
    public class DiffieHellman : IDisposable
    {
        #region " Private Fields "
        private AES AES;
        private ECDiffieHellmanCng DiffieHellmanCng;
        private byte[] _PrivateKey;
        #endregion
        #region " Properties "
        public byte[] PublicKey => DiffieHellmanCng.PublicKey.ToByteArray();
        public byte[] PrivateKey
        {
            get => _PrivateKey ?? DiffieHellmanCng.Key.Export(CngKeyBlobFormat.EccPrivateBlob);
            set
            {
                _PrivateKey = value;
                DiffieHellmanCng = new ECDiffieHellmanCng(CngKey.Import(_PrivateKey, CngKeyBlobFormat.EccPrivateBlob, CngProvider.MicrosoftSoftwareKeyStorageProvider))
                {
                    KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash,
                };
            }
        }
        public byte[] AesIV { get => AES.IV; set => AES.IV = value; }
        #endregion
        #region " Constructor "
        public DiffieHellman()
        {
            _PrivateKey = null;
            AES = new AES();
            DiffieHellmanCng = new ECDiffieHellmanCng(CngKey.Create(CngAlgorithm.ECDiffieHellmanP256, null, new CngKeyCreationParameters
            {
                ExportPolicy = CngExportPolicies.AllowPlaintextExport,
                KeyCreationOptions = CngKeyCreationOptions.MachineKey,
                KeyUsage = CngKeyUsages.AllUsages,
                Provider = CngProvider.MicrosoftSoftwareKeyStorageProvider,
                UIPolicy = new CngUIPolicy(CngUIProtectionLevels.None)
            }))
            {
                KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash,
            };
        }
        #endregion
        #region " Methods "
        public async Task<string> EncryptAsync(string publicKey, string data) => Convert.ToBase64String(await EncryptAsync(Convert.FromBase64String(publicKey), Encoding.UTF8.GetBytes(data)));

        public async Task<string> DecryptAsync(string publicKey, string data, string IV) => Encoding.UTF8.GetString(await DecryptAsync(Convert.FromBase64String(publicKey), Convert.FromBase64String(data), Convert.FromBase64String(IV)));

        public async Task<string> EncryptAsync(byte[] publicKey, string data) => Convert.ToBase64String(await EncryptAsync(publicKey, Encoding.UTF8.GetBytes(data)));

        public async Task<string> DecryptAsync(byte[] publicKey, string data, byte[] IV) => Encoding.UTF8.GetString(await DecryptAsync(publicKey, Convert.FromBase64String(data), IV));

        public async Task<byte[]> EncryptAsync(byte[] publicKey, byte[] data)
        {
            using (var key = CngKey.Import(publicKey, CngKeyBlobFormat.EccPublicBlob))
            {
                var derivedKey = DiffieHellmanCng.DeriveKeyMaterial(key);
                AES.Key = derivedKey;
                return await AES.ProcessAsync(data, AES.Cryptor.Encrypt);
            }
        }

        public async Task<byte[]> DecryptAsync(byte[] publicKey, byte[] data, byte[] IV)
        {
            using (var key = CngKey.Import(publicKey, CngKeyBlobFormat.EccPublicBlob))
            {
                var derivedKey = DiffieHellmanCng.DeriveKeyMaterial(key);
                AES.Key = derivedKey;
                AES.IV = IV;
                return await AES.ProcessAsync(data, AES.Cryptor.Decrypt);
            }
        }

        public void Dispose()
        {
            DiffieHellmanCng.Dispose();
            AES.Dispose();
            DiffieHellmanCng = null;
            AES = null;
            GC.SuppressFinalize(this);
        }
        #endregion
    }
}
