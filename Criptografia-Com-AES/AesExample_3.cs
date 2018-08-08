using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Criptografia_Com_AES
{
    public class AesExample_3
    {
        // Mensagem que sera criptografada.
        const string mensagem = "Tokio Marine Seguradora S.A.";
        // Senha definida da operadora.
        const String chave = "JessicaBiel";


        /// Updated decrypt function
        private static string Encrypt(string PlainText, string keyStr)
        {
            RijndaelManaged aes = new RijndaelManaged();
            aes.BlockSize = 128;
            aes.KeySize = 256;

            // It is equal in java 
            /// Cipher _Cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");    
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;

            byte[] pwdBytes = Encoding.UTF8.GetBytes(chave);
            byte[] keyBytes = new byte[32];
            int len = pwdBytes.Length;
            if (len > keyBytes.Length)
            {
                len = keyBytes.Length;
            }

            Array.Copy(pwdBytes, keyBytes, len);

            var derivedPassword = new Rfc2898DeriveBytes(chave, len);
            var symmetricKey = new RijndaelManaged();
            keyBytes = derivedPassword.GetBytes(symmetricKey.KeySize / 8);
            byte[] initBytes = derivedPassword.GetBytes(symmetricKey.BlockSize / 8);


            // Initialization vector.   
            // It could be any value or generated using a random number generator.
            byte[] ivArr = { 1, 2, 3, 4, 5, 6, 6, 5, 4, 3, 2, 1, 7, 7, 7, 7 };
            byte[] IVBytes16Value = new byte[16];
            Array.Copy(ivArr, IVBytes16Value, 16);

            aes.Key = keyBytes;
            aes.IV = IVBytes16Value;

            ICryptoTransform encrypto = aes.CreateEncryptor();

            byte[] plainTextByte = ASCIIEncoding.UTF8.GetBytes(PlainText);
            byte[] CipherText = encrypto.TransformFinalBlock(plainTextByte, 0, plainTextByte.Length);
            return Convert.ToBase64String(CipherText);
        }
    }
}
