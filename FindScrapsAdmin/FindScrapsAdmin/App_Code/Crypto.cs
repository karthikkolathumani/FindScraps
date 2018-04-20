using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

/// <summary>
/// Summary description for Crypto
/// </summary>
public class Crypto
{
    private byte[] _key;
    private byte[] _iv;

    public string Base64IV
    {
        get { return Convert.ToBase64String(_iv); }
    }

    public Crypto(string key)
    {
        _key = Encoding.ASCII.GetBytes(key);

        Aes myAes = Aes.Create();
        _iv = myAes.IV;
        myAes.Dispose();
    }

    public Crypto(string key, string base64_iv)
    {
        _key = Encoding.ASCII.GetBytes(key);
        _iv = Convert.FromBase64String(base64_iv);
    }

    public string EncryptString_Aes_Base64(string plainText)
    {
        string encrypted;
        // Create an Aes object 
        // with the specified key and IV. 
        using (Aes aesAlg = Aes.Create())
        {
            // Create a decrytor to perform the stream transform.
            ICryptoTransform encryptor = aesAlg.CreateEncryptor(_key, _iv);

            // Create the streams used for encryption. 
            using (MemoryStream msEncrypt = new MemoryStream())
            {
                using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                {
                    using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                    {

                        //Write all data to the stream.
                        swEncrypt.Write(plainText);
                    }

                    encrypted = Convert.ToBase64String(msEncrypt.ToArray());
                }
            }
            encryptor.Dispose();
        }

        // Return the encrypted string from the memory stream. 
        return encrypted;
    }

    public string DecryptString_Aes_Base64(string cipherText)
    {
        // Declare the string used to hold 
        // the decrypted text. 
        string plaintext = null;

        // Create an Aes object 
        // with the specified key and IV. 
        using (Aes aesAlg = Aes.Create())
        {
            // Create a decrytor to perform the stream transform.
            ICryptoTransform decryptor = aesAlg.CreateDecryptor(_key, _iv);

            // Create the streams used for decryption. 
            using (MemoryStream msDecrypt = new MemoryStream(Convert.FromBase64String(cipherText)))
            {
                using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                {
                    using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                    {

                        // Read the decrypted bytes from the decrypting stream
                        // and place them in a string.
                        plaintext = srDecrypt.ReadToEnd();
                    }
                }
            }
            decryptor.Dispose();
        }

        return plaintext;
    }
}