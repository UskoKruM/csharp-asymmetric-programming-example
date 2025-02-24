using System.Security.Cryptography;
using System.Text;

using (RSA rsa = RSA.Create())
{
    rsa.KeySize = 2048;

    string publicKey = Convert.ToBase64String(rsa.ExportRSAPublicKey());
    string privateKey = Convert.ToBase64String(rsa.ExportRSAPrivateKey());

    Console.WriteLine($"Public Key: {publicKey}");
    Console.WriteLine("---------------------------------------------------");
    Console.WriteLine($"Private Key: {privateKey}");

    Console.WriteLine("---------------------------------------------------");

    string message = "Hola! Suscríbete al canal!";
    byte[] encryptedMessage = Encrypt(message, publicKey);
    Console.WriteLine($"Encrypted: {Convert.ToBase64String(encryptedMessage)}");

    Console.WriteLine("---------------------------------------------------");

    string decryptedMessage = Decrypt(encryptedMessage, privateKey);
    Console.WriteLine($"Decrypted: {decryptedMessage}");
}

static byte[] Encrypt(string message, string publicKey)
{
    using RSA rsa = RSA.Create();
    rsa.ImportRSAPublicKey(Convert.FromBase64String(publicKey), out _);
    byte[] messageToEncrypt = Encoding.UTF8.GetBytes(message);

    return rsa.Encrypt(messageToEncrypt, RSAEncryptionPadding.OaepSHA256);
}

static string Decrypt(byte[] encryptedMessage, string privateKey)
{
    using RSA rsa = RSA.Create();
    rsa.ImportRSAPrivateKey(Convert.FromBase64String(privateKey), out _);
    byte[] decryptedMessage = rsa.Decrypt(encryptedMessage, RSAEncryptionPadding.OaepSHA256);

    return Encoding.UTF8.GetString(decryptedMessage);
}