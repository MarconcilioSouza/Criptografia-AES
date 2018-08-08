using System;
using System.Security.Cryptography;
using System.Text;

namespace Criptografia_Com_AES
{
    public sealed class Criptografia
    {
        public static String criptografar(String mensagem, String chave)
        {
            try
            {
                RijndaelManaged rijndaelCipher = new RijndaelManaged();
                rijndaelCipher.Mode = CipherMode.CBC;
                rijndaelCipher.Padding = PaddingMode.PKCS7;

                rijndaelCipher.KeySize = 0x80;
                rijndaelCipher.BlockSize = 0x80;
                byte[] pwdBytes = Encoding.UTF8.GetBytes(chave);
                byte[] keyBytes = new byte[0x10];
                int len = pwdBytes.Length;
                if (len > keyBytes.Length)
                {
                    len = keyBytes.Length;
                }

                Array.Copy(pwdBytes, keyBytes, len);
                rijndaelCipher.Key = keyBytes;
                rijndaelCipher.IV = keyBytes;
                ICryptoTransform transform = rijndaelCipher.CreateEncryptor();
                byte[] plainText = Encoding.UTF8.GetBytes(mensagem);
                return Convert.ToBase64String(transform.TransformFinalBlock(plainText, 0, plainText.Length));
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }

        public static String descriptografar(String mensagem, String chave)
        {
            try
            {
                RijndaelManaged rijndaelCipher = new RijndaelManaged();
                rijndaelCipher.Mode = CipherMode.CBC;
                rijndaelCipher.Padding = PaddingMode.PKCS7;

                rijndaelCipher.KeySize = 0x80;
                rijndaelCipher.BlockSize = 0x80;
                byte[] encryptedData = Convert.FromBase64String(mensagem);
                byte[] pwdBytes = Encoding.UTF8.GetBytes(chave);
                byte[] keyBytes = new byte[0x10];
                int len = pwdBytes.Length;
                if (len > keyBytes.Length)
                {
                    len = keyBytes.Length;
                }
                Array.Copy(pwdBytes, keyBytes, len);
                rijndaelCipher.Key = keyBytes;
                rijndaelCipher.IV = keyBytes;
                byte[] plainText = rijndaelCipher.CreateDecryptor().TransformFinalBlock(encryptedData, 0, encryptedData.Length);
                return Encoding.UTF8.GetString(plainText);
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }

        public static void Main(string[] args)
        {
            // Mensagem que sera criptografada.
            const String mensagem = "Tokio Marine Seguradora S.A.";
            // Senha definida da operadora.
            const String chave = "JessicaBiel";

            // Valor criptografado.
            String criptografado = Criptografia.criptografar(mensagem, chave);
            Console.WriteLine("Valor criptografado: '{0}'", criptografado);

            // Valor original.
            String descriptografado = Criptografia.descriptografar(criptografado, chave);
            Console.WriteLine("Valor descriptografado: '{0}'", descriptografado);

            Console.ReadKey();
        }
    }
}
