﻿## RSA - AES HYBRID ENCRYPTION-DECRYPTION
###### RSA - AES HİBRİT ŞİFRELEME-ÇÖZME

### Build requirements
 * Visual Studio 2017
 * .NET Framework 4.5

### Features
 * Asynchronous (You can use async/await)
 * RSA-AES Hybrid Encryption-Decryption (My Algorithm)
 * RSA Encryption-Decryption `(1024 Bit, 2048 Bit, 4096 Bit)`
 * AES Encryption-Decryption `(128 Bit, 256 Bit)`
 * Diffie–Hellman Key Exchange

## Examples
#### RSA-AES Hybrid Encryption-Decryption

- string or byte[]
```C#
string publicKey = RsaAesHybrit.Instance.ToXmlString(false);
string privateKey = RsaAesHybrit.Instance.ToXmlString(true);

byte[] data = Encoding.UTF8.GetBytes("KEMAL");
byte[] encrypted = await RsaAesHybrit.Instance.EncryptAsync(data);
byte[] decrypted = await RsaAesHybrit.Instance.DecryptAsync(encrypted);
```

- File

```C#
string testSourceFileName = "Kriptografi.exe";
string targetFileNameEnc = "Kriptografi_encrypted.enc";
string targetFileNameDec = "Kriptografi_decrypted.exe";
await RsaAesHybrit.Instance.EncryptAsync(testSourceFileName, targetFileNameEnc);
await RsaAesHybrit.Instance.DecryptAsync(targetFileNameEnc, targetFileNameDec);
```

#### AES-256 Bit Encryption-Decryption
- byte[]
```C#
AES aes = new AES();
byte[] data = Encoding.UTF8.GetBytes(metin);
byte[] encrypted = await aes.ProcessAsync(data, AES.Cryptor.Encrypt);
byte[] decrypted = await aes.ProcessAsync(sifrele, AES.Cryptor.Decrypt);

Console.WriteLine("Key: {0}", Convert.ToBase64String(aes.Key));
Console.WriteLine("IV: {0}", Convert.ToBase64String(aes.IV));
```

- File
```C#
string testSourceFileName = "Kriptografi.exe";
string targetFileNameEnc = "Kriptografi_encrypted.enc";
string targetFileNameDec = "Kriptografi_decrypted.exe";
AES aes = new AES();
await aes.ProcessAsync(testSourceFileName, targetFileNameEnc, AES.Cryptor.Encrypt);
await aes.ProcessAsync(targetFileNameEnc, targetFileNameDec, AES.Cryptor.Decrypt);
```


#### Diffie–Hellman Key Exchange
```C#
using (var bob = new DiffieHellman())
using (var alice = new DiffieHellman())
{
	Console.WriteLine("Bob Private Key: {0}\n", Convert.ToBase64String(bob.PrivateKey));
	Console.WriteLine("Alice Private Key: {0}\n", Convert.ToBase64String(alice.PrivateKey));

	Console.WriteLine("Bob IV: {0}\n", Convert.ToBase64String(bob.AesIV));
	Console.WriteLine("Alice IV: {0}\n", Convert.ToBase64String(alice.AesIV));
				
	byte[] data = Encoding.UTF8.GetBytes("{ KeMaL; }");

	// Bob uses Alice's public key to encrypt his data.
	byte[] secretData = await bob.EncryptAsync(alice.PublicKey, data);

	// Alice uses Bob's public key and IV to decrypt the secret data.
	byte[] decryptedData = await alice.DecryptAsync(bob.PublicKey, secretData, bob.AesIV);
}
```