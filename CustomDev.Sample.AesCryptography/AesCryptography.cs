using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace CustomDev.Sample.AesCryptography
{
    public class AesCryptography
    {
        public static byte[] GetKeyFromPassword(string password, byte[] salt)
        {            
            Rfc2898DeriveBytes derivator = new Rfc2898DeriveBytes(password, salt, 100);
            return derivator.GetBytes(32);
        }        

        public static byte[] EncryptWithAes(byte[] plainContent, byte[] key)
        {
            if (plainContent == null || plainContent.Length == 0) { throw new ArgumentNullException("plainText"); }
            if (key == null || key.Length == 0) { throw new ArgumentNullException("key"); }

            byte[] encrypted;
            using (Aes aes = Aes.Create())
            using(SHA256 sha256 = SHA256.Create())
            {
                ICryptoTransform encryptor;
                byte[] signature = sha256.ComputeHash(plainContent);

                aes.GenerateIV();
                aes.Mode = CipherMode.CBC;
                aes.Key = key;
                if (aes.IV == null || aes.IV.Length != 16)
                {
                    throw new Exception("Invalid initialization vector");
                }

                encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

                using (MemoryStream memoryStream = new MemoryStream())
                {
                    memoryStream.Write(aes.IV, 0, aes.IV.Length);
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                    {
                        cryptoStream.WriteByte(1);
                        cryptoStream.Write(signature, 0, signature.Length);
                        cryptoStream.Write(plainContent, 0, plainContent.Length);
                    }

                    encrypted = memoryStream.ToArray();
                }
            }

            return encrypted;
        }

        public static byte[] DecryptWithAes(byte[] cipherText, byte[] key)
        {
            if (cipherText == null || cipherText.Length == 0) { throw new ArgumentNullException("cipherText"); }
            if (key == null || key.Length == 0) { throw new ArgumentNullException("Key"); }

            byte[] plainContent = null;

            using (SHA256 sha256 = SHA256.Create())
            using (Aes aes = Aes.Create())
            using (MemoryStream msDecrypt = new MemoryStream(cipherText))
            {
                byte[] initializationVector = new byte[16];
                ICryptoTransform decryptor;

                msDecrypt.Read(initializationVector, 0, initializationVector.Length);
                aes.Mode = CipherMode.CBC;
                aes.Key = key;
                aes.IV = initializationVector;

                decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                using (MemoryStream outputDecrypt = new MemoryStream())
                {
                    using (CryptoStream cryptoStream = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        int hashAlgorithm = cryptoStream.ReadByte();

                        if (hashAlgorithm == 1)
                        {
                            byte[] signature = new byte[32];
                            byte[] computedSignature;

                            cryptoStream.Read(signature, 0, 32);
                            cryptoStream.CopyTo(outputDecrypt);
                            plainContent = outputDecrypt.ToArray();
                            computedSignature = sha256.ComputeHash(plainContent);

                            if (!CompareByteArray(computedSignature, signature))
                            {
                                throw new Exception("Corrupted data");
                            }
                        }
                    }
                }

            }

            return plainContent;
        }

        private static bool CompareByteArray(byte[] array1, byte[] array2)
        {
            if (array1 == array2) { return true; }
            if (array1 == null && array2 != null) { return false; }
            if (array1 != null && array2 == null) { return false; }
            if (array1.Length != array2.Length) { return false; }
            
            for(int i = 0; i < array1.Length; ++i)
            {
                if (array1[i] != array2[i]) { return false; }
            }

            return true;
        }
    }
}
