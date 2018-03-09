using System;
using System.IO;
using System.Security.Cryptography;

namespace CustomDev.Sample.AesCryptography
{
    class Program
    {
        static void Main(string[] args)
        {
            AesCryptography crypto = new AesCryptography();
            if (args.Length != 3)
            {
                DisplayHelp();
                return;
            }

            string command = args[0];
            string inputFile = args[1];
            string outputFile = args[2];

            byte[] salt = Program.KeySalt;
            string password = Program.Password;
            byte[] inputContent = GetContent(inputFile);
            byte[] outputContent = null;

            byte[] key = AesCryptography.GetKeyFromPassword(password, salt);

            switch (command)
            {
                case "encrypt":
                    {
                        outputContent = AesCryptography.EncryptWithAes(inputContent, key);
                        break;
                    }
                case "decrypt":
                    {
                        outputContent = AesCryptography.DecryptWithAes(inputContent, key);
                        break;
                    }
                default:
                    DisplayHelp();
                    return;
            }

            SaveContent(outputContent, outputFile);        
        }

        private static void DisplayHelp()
        {
            Console.WriteLine("AesCryptography");
            Console.WriteLine("===============");
            Console.WriteLine();
            Console.WriteLine("Usage:");
            Console.WriteLine("AesCryptography encrypt [input file] [output file]");
            Console.WriteLine();            
        }

        private static void SaveContent(byte[] content, string filePath)
        {
            File.WriteAllBytes(filePath, content);
        }        

        private static byte[] GetContent(string filePath)
        {
            byte[] content;
            using (FileStream file = File.OpenRead(filePath))
            using (MemoryStream memoryStream = new MemoryStream())
            {
                file.CopyTo(memoryStream);
                content = memoryStream.ToArray();
            }
            
            return content;
        }

        /// <summary>
        /// Password used to generate the key.
        /// 
        /// SECURITY NOTICE
        /// ---------------
        /// This is a SAMPLE program.
        /// 
        /// For security reasons, password MUST NOT BE :
        /// - hardcoded in program (like in this program)
        /// - passed as a argument of a command line utility 
        /// 
        /// You can use <see cref="https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.protecteddata?view=netframework-4.7.1">System.Security.ProtectedData</see>
        /// to securely store a password.
        /// </summary>
        private static string Password
        {
            get { return "1234"; }
        }

        /// <summary>
        /// Salt used to generate the key
        /// No special consideration about security (salt can be public)
        /// </summary>
        private static byte[] KeySalt
        {
            get { return new byte[] { 0, 1, 2, 3, 4, 5, 6, 7 }; }
        }       
    }
}
