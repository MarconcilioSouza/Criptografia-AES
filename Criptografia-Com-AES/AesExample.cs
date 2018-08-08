using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Criptografia_Com_AES
{
    class AesExample
    {
        // Mensagem que sera criptografada.
        const string mensagem = "Tokio Marine Seguradora S.A.";
        // Senha definida da operadora.
        const String chave = "JessicaBiel";

        //public static void Main()
        //{
        //    try
        //    {
        //        byte[] pwdBytes = Encoding.UTF8.GetBytes(chave);
        //        byte[] keyBytes = new byte[0x10];
        //        int len = pwdBytes.Length;
        //        if (len > keyBytes.Length)
        //        {
        //            len = keyBytes.Length;
        //        }

        //        Array.Copy(pwdBytes, keyBytes, len);

        //        using (Aes myAes = Aes.Create("AES"))
        //        {
        //            myAes.Key = keyBytes;
        //            //myAes.IV = new byte[0x10];
        //            //myAes.Mode = CipherMode.CBC;
        //            //myAes.KeySize = 256;
        //            //myAes.BlockSize = 128;

        //            byte[] encrypted = EncryptStringToBytes_Aes(mensagem, myAes.Key, myAes.IV);
        //            string roundtrip = DecryptStringFromBytes_Aes(encrypted, myAes.Key, myAes.IV);

        //            Console.WriteLine("Original:   {0}", mensagem);
        //            Console.WriteLine("Criptografado C# : {0}", Convert.ToBase64String(encrypted));
        //            Console.WriteLine("Criptografado Java: {0}", "JGTfV+CntuSutHK0LLeZix9Teu87ynjpJN8d3OaQdWge6yN0stn7/1I5KmMJEFYk");

        //            if (encrypted.Equals("JGTfV+CntuSutHK0LLeZix9Teu87ynjpJN8d3OaQdWge6yN0stn7/1I5KmMJEFYk"))
        //                Console.WriteLine("Criptografia indentica");

        //            Console.ReadKey();
        //        }
        //    }
        //    catch (Exception e)
        //    {
        //        Console.WriteLine("Error: {0}", e.Message);
        //        Console.ReadKey();
        //    }
        //}
        static byte[] EncryptStringToBytes_Aes(string plainText, byte[] Key, byte[] IV)
        {
            // Check arguments.
            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException("plainText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");
            byte[] encrypted;
            // Create an Aes object
            // with the specified key and IV.
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                // Create a decrytor to perform the stream transform.
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

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
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }

            // Return the encrypted bytes from the memory stream.
            return encrypted;
        }

        static string DecryptStringFromBytes_Aes(byte[] cipherText, byte[] Key, byte[] IV)
        {
            // Check arguments.
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");

            // Declare the string used to hold
            // the decrypted text.
            string plaintext = null;

            // Create an Aes object
            // with the specified key and IV.
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                // Create a decrytor to perform the stream transform.
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for decryption.
                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {

                            // Read the decrypted bytes from the decrypting  stream
                            // and place them in a string.
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }
            return plaintext;
        }
    }
}
