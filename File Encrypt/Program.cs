using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace File_Encrypt
{
    class Program
    {
        static void Main(string[] args)
        {
            bool MODE;
            Console.WriteLine("Input \"1\" for encryption. None for decryption");
            if (Console.ReadLine() == "1")
            {
                MODE = true;
            }
            else
            {
                MODE = false;
            }
            Console.WriteLine("Input Password...");
            string passwd = Console.ReadLine();
            Walk(ref passwd, ref MODE);
            if (MODE)
            {
                Console.WriteLine("All Encrypted!");
            }
            else
            {
                Console.WriteLine("All Decrypted!");
            }
            
            Console.ReadLine();
        }

        static void Walk(ref string passwd, ref bool MODE)
        {
            string selfpath = System.Diagnostics.Process.GetCurrentProcess().MainModule.FileName;
            string root = Environment.CurrentDirectory;
            var folders = Directory.GetDirectories(root);
            foreach (var folder in folders)
            {
                var files = Directory.GetFiles(folder, "*.*");
                foreach (var file in files)
                {
                    ICryptoTransform Cryptor = AES_Init(ref passwd, ref MODE);
                    if (MODE)
                    {
                        File_ecpt(file, ref Cryptor);
                        Console.WriteLine(file);
                    }
                    else
                    {
                        if (file.EndsWith(".acb"))
                        {
                            File_dcpt(file, ref Cryptor);
                            Console.WriteLine(file);
                        }
                    }
                }
            }
            string[] rootfiles = Directory.GetFiles(root, "*.*");
            foreach (var file in rootfiles)
            {
                if (file != selfpath)
                {
                    ICryptoTransform Cryptor = AES_Init(ref passwd, ref MODE);
                    if (MODE)
                    {
                        Console.WriteLine(file);
                        File_ecpt(file, ref Cryptor);
                    }
                    else
                    {
                        if (file.EndsWith(".acb"))
                        {
                            File_dcpt(file, ref Cryptor);
                            Console.WriteLine(file);
                        }
                    }
                }

            }
        }

        static ICryptoTransform AES_Init(ref string passwd, ref bool MODE)
        {
            Aes aes = Aes.Create();
            aes.Mode = CipherMode.CFB;
            aes.Padding = PaddingMode.PKCS7;
            using (SHA256 SHAHash = SHA256.Create())
            {
                byte[] KEY = SHAHash.ComputeHash(Encoding.UTF8.GetBytes(passwd));
                aes.Key = KEY;
            }
            using (MD5 md5Hash = MD5.Create())
            {
                byte[] IV = md5Hash.ComputeHash(Encoding.UTF8.GetBytes(passwd));
                aes.IV = IV;
            }
            if (MODE)
            {
                ICryptoTransform Cryptor = aes.CreateEncryptor(aes.Key, aes.IV);
                return Cryptor;
            }
            else
            {
                ICryptoTransform Cryptor = aes.CreateDecryptor(aes.Key, aes.IV);
                return Cryptor;
            }
            
        }

        static void File_ecpt(string file, ref ICryptoTransform Encryptor)
        {
            string tmpPath = file + ".acb";
            Aes aes = Aes.Create();
            byte[] b = new byte[4096];
            int readlenth;
            using (FileStream fsw = File.Create(tmpPath))
            {
                using (FileStream fsr = File.Open(file, FileMode.Open))
                {
                    using (CryptoStream cs = new CryptoStream(fsw, Encryptor, CryptoStreamMode.Write))
                    {
                        while (true)
                        {
                            if ((readlenth = fsr.Read(b, 0, b.Length)) > 0)
                            {
                                byte[] tmp = new byte[readlenth];
                                Array.Copy(b, tmp, readlenth);
                                cs.Write(tmp, 0, tmp.Length);
                            }
                            else
                            {
                                break;
                            }
                        }
                    }
                }
            }

            File.Delete(file);
        }

        static void File_dcpt(string file, ref ICryptoTransform Decryptor)
        {
            byte[] b = new byte[4096];
            int readlenth;
            using (FileStream fsw = File.Create(file.Replace(".acb", "")))
            {
                using (FileStream fsr = File.Open(file, FileMode.Open))
                {
                    using (CryptoStream cs = new CryptoStream(fsw, Decryptor, CryptoStreamMode.Write))
                    {
                        while (true)
                        {
                            if ((readlenth = fsr.Read(b, 0, b.Length)) > 0)
                            {
                                byte[] tmp = new byte[readlenth];
                                Array.Copy(b, tmp, readlenth);
                                cs.Write(tmp, 0, tmp.Length);
                            }
                            else
                            {
                                break;
                            }
                        }
                    }
                }
            }
            File.Delete(file);
        }

    }
}
