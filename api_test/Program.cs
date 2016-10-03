using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using api;
namespace api_test
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Testing api dll...");

            //Start testing Files methods
            string[] exts = new string[] {".txt",".png"};
            string[] dirs = new string[] { "C:\\Users1\\" + Environment.UserName + "\\Documents", "C:\\Users\\Username\\Documents\\404-notfound" };
            Files files = new Files(); //Using api class
            foreach(string dir in dirs)
            {
                if (!Directory.Exists(dir)) { continue; }
                List<string> tempFiles = files.ListFiles(dir, exts);
                foreach(string ff in tempFiles)
                {
                    Console.WriteLine(ff);
                }
            }
            Console.WriteLine("FINISHED FINDING ANY FILES.");

            //Start testing networking methods
            Networking net = new Networking();
            Console.WriteLine();
            Console.WriteLine("curl() Function test:" + net.curl("http://icanhazip.com"));

            //Start testing crypto methods
            crypto cr = new crypto();
            string plain = "Hello World!";
            Console.WriteLine("Plain:     " + plain);
            string enc = cr.EncryptString(plain, "SHA256", "password", "aselrias38490a32", "ry473326e5wuejer");
            Console.WriteLine("Encrypted: " + enc);
            string dec = cr.DecryptString(enc, "SHA256", "password", "aselrias38490a32", "ry473326e5wuejer");
            Console.WriteLine("Decrypted: " + dec);
            Console.WriteLine();
            Console.WriteLine("Testing OpenPGP");
            crypto.Password = "";
            crypto.PublicKeyPath = "pub.key";
            crypto.PrivateKeyOnlyPath = "priv.key";
            crypto.EncryptPgpFile("This is a test document.txt", "This is a test document.txt.enc");
            crypto.DecryptPgpData("This is a test document.txt.enc");
            Console.WriteLine("Finished with API_TEST.EXE");
            Console.ReadLine();
        }
    }
}
