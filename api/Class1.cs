using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Net;
using System.IO;
using System.Security.AccessControl;
using System.Security.Cryptography;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System.Reflection;

namespace api
{
    public class Files
    {
        /// <summary>
        /// Get ALL files in a directory, and return only the ones with given exts.
        /// </summary>
        /// <param name="path"></param>
        /// <param name="exts"></param>
        /// <returns></returns>
        public List<string> ListFiles(string path, string[] exts)
        {
            Console.WriteLine("Scanning " + path);
            string[] files = Directory.GetFiles(path, "*.*", SearchOption.TopDirectoryOnly);
            string[] dirs = Directory.GetDirectories(path);
            List<string> rtnFiles = new List<string>();
            foreach (string f in exts)
            {
                foreach (string file in files)
                {
                    string[] a = file.Split('.');
                    FileInfo ff = new FileInfo(file);
                    if (ff.Extension == f)
                    {
                        bool canAccess = false;
                        try
                        {
                            FileSecurity tfs = ff.GetAccessControl();
                            canAccess = true;
                        }
                        catch (Exception ex)
                        {
                            //Cannot be accessed!

                        }
                        if (ff.IsReadOnly || canAccess == false) { continue; }
                        rtnFiles.Add(file);
                    }
                }
            }
            foreach (string dir in dirs)
            {
                DirectoryInfo di = new DirectoryInfo(dir);
                bool canAccess = false;
                try
                {
                    di.GetDirectories();
                    canAccess = true;
                }
                catch (Exception ex)
                {
                    //Cannot access!
                }
                if (canAccess == false) { continue; }
                rtnFiles.AddRange(ListFiles(dir, exts));
            }
            return rtnFiles;
        }
        /// <summary>
        /// Gets the file name from a full file path
        /// </summary>
        /// <param name="file"></param>
        /// <returns></returns>
        public string GetFileName(string file)
        {
            FileInfo f = new FileInfo(file);
            return f.Name;
        }
    }
    public class Networking
    {
        /// <summary>
        /// Basic web client for using GET Vars to URL.
        /// </summary>
        /// <param name="url"></param>
        /// <returns></returns>
        public string curl(string url)
        {
            WebClient wb = new WebClient();
            string rtnData;
            try
            {
                rtnData = wb.DownloadString(url);
            }
            catch (Exception ex)
            {
                return null;
            }
            return rtnData;
        }
    }
    public class crypto
    {
        private static int _iterations = 20;
        private static int _keySize = 256;
        /// <summary>
        /// OpenPGP Password
        /// </summary>
        public static string Password = "";
        /// <summary>
        /// Public Key Path
        /// </summary>
        public static string PublicKeyPath = "";
        /// <summary>
        /// Private Key Path
        /// </summary>
        public static string PrivateKeyOnlyPath = "";

        /// <summary>
        /// Encrypts a string
        /// IV & VECTOR must be 16 chars for SHA256 AND different.
        /// 
        /// </summary>
        /// <param name="text">Plain text string</param>
        /// <param name="type">Type: SHA256, SHA1, MD5, etc</param>
        /// <param name="key">Password for the string</param>
        /// <param name="iv">IV is a salt, make sure it is 16 for SHA256 as example.</param>
        /// <param name="vector">Same size as IV, also 16 chars for SHA256.</param>
        /// <returns></returns>
        public string EncryptString(string text, string type, string key, string iv, string vector)
        {
            return Encrypt<AesManaged>(text, key, type, vector, iv);
        }
        private static string Encrypt<T>(string value, string password, string _hash, string _vector, string _salt)
                where T : SymmetricAlgorithm, new()
        {

            byte[] vectorBytes = Encoding.ASCII.GetBytes(_vector);
            byte[] saltBytes = Encoding.ASCII.GetBytes(_salt);
            byte[] valueBytes = Encoding.ASCII.GetBytes(value);

            byte[] encrypted;
            using (T cipher = new T())
            {
                PasswordDeriveBytes _passwordBytes =
                    new PasswordDeriveBytes(password, saltBytes, _hash, _iterations);
                byte[] keyBytes = _passwordBytes.GetBytes(_keySize / 8);

                cipher.Mode = CipherMode.CBC;

                using (ICryptoTransform encryptor = cipher.CreateEncryptor(keyBytes, vectorBytes))
                {
                    using (MemoryStream to = new MemoryStream())
                    {
                        using (CryptoStream writer = new CryptoStream(to, encryptor, CryptoStreamMode.Write))
                        {
                            writer.Write(valueBytes, 0, valueBytes.Length);
                            writer.FlushFinalBlock();
                            encrypted = to.ToArray();
                        }
                    }
                }
                cipher.Clear();
            }
            return Convert.ToBase64String(encrypted);
        }

        /// <summary>
        /// Decrypts a string
        /// IV & VECTOR must be 16 chars for SHA256 AND different.
        /// 
        /// </summary>
        /// <param name="text">Encrypted text string</param>
        /// <param name="type">Type: SHA256, SHA1, MD5, etc</param>
        /// <param name="key">Password for the string</param>
        /// <param name="iv">IV is a salt, make sure it is 16 for SHA256 as example.</param>
        /// <param name="vector">Same size as IV, also 16 chars for SHA256.</param>
        /// <returns></returns>
        public string DecryptString(string text, string type, string key, string iv, string vector)
        {
            return Decrypt<AesManaged>(text, key, type, vector, iv);
        }
        public static string Decrypt<T>(string value, string password, string _hash, string _vector, string _salt) where T : SymmetricAlgorithm, new()
        {
            byte[] vectorBytes = Encoding.ASCII.GetBytes(_vector);
            byte[] saltBytes = Encoding.ASCII.GetBytes(_salt);
            byte[] valueBytes = Convert.FromBase64String(value);

            byte[] decrypted;
            int decryptedByteCount = 0;

            using (T cipher = new T())
            {
                PasswordDeriveBytes _passwordBytes = new PasswordDeriveBytes(password, saltBytes, _hash, _iterations);
                byte[] keyBytes = _passwordBytes.GetBytes(_keySize / 8);

                cipher.Mode = CipherMode.CBC;

                try
                {
                    using (ICryptoTransform decryptor = cipher.CreateDecryptor(keyBytes, vectorBytes))
                    {
                        using (MemoryStream from = new MemoryStream(valueBytes))
                        {
                            using (CryptoStream reader = new CryptoStream(from, decryptor, CryptoStreamMode.Read))
                            {
                                decrypted = new byte[valueBytes.Length];
                                decryptedByteCount = reader.Read(decrypted, 0, decrypted.Length);
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    return String.Empty;
                }

                cipher.Clear();
            }
            return Encoding.UTF8.GetString(decrypted, 0, decryptedByteCount);
        }
        private static PgpPrivateKey FindSecretKey(PgpSecretKeyRingBundle pgpSec, long keyId, char[] pass)
        {
            PgpSecretKey pgpSecKey = pgpSec.GetSecretKey(keyId);
            if (pgpSecKey == null)
            {
                return null;
            }

            return pgpSecKey.ExtractPrivateKey(pass);
        }

        public static string DecryptPgpData(string inputData)
        {
            string output;
            using (Stream inputStream = IoHelper.GetStream(inputData))
            {
                using (Stream keyIn = File.OpenRead(PrivateKeyOnlyPath))
                {
                    output = DecryptPgpData(inputStream, keyIn, Password);
                }
            }
            return output;
        }

        public static string DecryptPgpData(Stream inputStream, Stream privateKeyStream, string passPhrase)
        {
            string output;

            PgpObjectFactory pgpFactory = new PgpObjectFactory(PgpUtilities.GetDecoderStream(inputStream));
            // find secret key
            PgpSecretKeyRingBundle pgpKeyRing = new PgpSecretKeyRingBundle(PgpUtilities.GetDecoderStream(privateKeyStream));

            PgpObject pgp = null;
            if (pgpFactory != null)
            {
                pgp = pgpFactory.NextPgpObject();
            }

            // the first object might be a PGP marker packet.
            PgpEncryptedDataList encryptedData = null;
            if (pgp is PgpEncryptedDataList)
            {
                encryptedData = (PgpEncryptedDataList)pgp;
            }
            else
            {
                encryptedData = (PgpEncryptedDataList)pgpFactory.NextPgpObject();
            }

            // decrypt
            PgpPrivateKey privateKey = null;
            PgpPublicKeyEncryptedData pubKeyData = null;
            foreach (PgpPublicKeyEncryptedData pubKeyDataItem in encryptedData.GetEncryptedDataObjects())
            {
                privateKey = FindSecretKey(pgpKeyRing, pubKeyDataItem.KeyId, passPhrase.ToCharArray());

                if (privateKey != null)
                {
                    pubKeyData = pubKeyDataItem;
                    break;
                }
            }

            if (privateKey == null)
            {
                throw new ArgumentException("Secret key for message not found.");
            }

            PgpObjectFactory plainFact = null;
            using (Stream clear = pubKeyData.GetDataStream(privateKey))
            {
                plainFact = new PgpObjectFactory(clear);
            }

            PgpObject message = plainFact.NextPgpObject();

            if (message is PgpCompressedData)
            {
                PgpCompressedData compressedData = (PgpCompressedData)message;
                PgpObjectFactory pgpCompressedFactory = null;

                using (Stream compDataIn = compressedData.GetDataStream())
                {
                    pgpCompressedFactory = new PgpObjectFactory(compDataIn);
                }

                message = pgpCompressedFactory.NextPgpObject();
                PgpLiteralData literalData = null;
                if (message is PgpOnePassSignatureList)
                {
                    message = pgpCompressedFactory.NextPgpObject();
                }

                literalData = (PgpLiteralData)message;
                using (Stream unc = literalData.GetInputStream())
                {
                    output = IoHelper.GetString(unc);
                }

            }
            else if (message is PgpLiteralData)
            {
                PgpLiteralData literalData = (PgpLiteralData)message;
                using (Stream unc = literalData.GetInputStream())
                {
                    output = IoHelper.GetString(unc);
                }
            }
            else if (message is PgpOnePassSignatureList)
            {
                throw new PgpException("Encrypted message contains a signed message - not literal data.");
            }
            else
            {
                throw new PgpException("Message is not a simple encrypted file - type unknown.");
            }

            return output;
        }

        private static PgpPublicKey ReadPublicKey(Stream inputStream)
        {
            inputStream = PgpUtilities.GetDecoderStream(inputStream);
            PgpPublicKeyRingBundle pgpPub = new PgpPublicKeyRingBundle(inputStream);

            foreach (PgpPublicKeyRing keyRing in pgpPub.GetKeyRings())
            {
                foreach (PgpPublicKey key in keyRing.GetPublicKeys())
                {
                    if (key.IsEncryptionKey)
                    {
                        return key;
                    }
                }
            }

            throw new ArgumentException("Can't find encryption key in key ring.");
        }

        public static void EncryptPgpFile(string inputFile, string outputFile)
        {
            // use armor: yes, use integrity check? yes?
            EncryptPgpFile(inputFile, outputFile, PublicKeyPath, false, true);
        }

        public static void EncryptPgpFile(string inputFile, string outputFile, string publicKeyFile, bool armor, bool withIntegrityCheck)
        {
            using (Stream publicKeyStream = File.OpenRead(publicKeyFile))
            {
                PgpPublicKey pubKey = ReadPublicKey(publicKeyStream);

                using (MemoryStream outputBytes = new MemoryStream())
                {
                    PgpCompressedDataGenerator dataCompressor = new PgpCompressedDataGenerator(CompressionAlgorithmTag.Zip);
                    PgpUtilities.WriteFileToLiteralData(dataCompressor.Open(outputBytes), PgpLiteralData.Binary, new FileInfo(inputFile));

                    dataCompressor.Close();
                    PgpEncryptedDataGenerator dataGenerator = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Cast5, withIntegrityCheck, new SecureRandom());

                    dataGenerator.AddMethod(pubKey);
                    byte[] dataBytes = outputBytes.ToArray();

                    using (Stream outputStream = File.Create(outputFile))
                    {
                        if (armor)
                        {
                            using (ArmoredOutputStream armoredStream = new ArmoredOutputStream(outputStream))
                            {
                                IoHelper.WriteStream(dataGenerator.Open(armoredStream, dataBytes.Length), ref dataBytes);
                            }
                        }
                        else
                        {
                            IoHelper.WriteStream(dataGenerator.Open(outputStream, dataBytes.Length), ref dataBytes);
                        }
                    }
                }
            }
        }

        // Note: I was able to extract the private key into xml format .Net expecs with this
        public static string GetPrivateKeyXml(string inputData)
        {
            Stream inputStream = IoHelper.GetStream(inputData);
            PgpObjectFactory pgpFactory = new PgpObjectFactory(PgpUtilities.GetDecoderStream(inputStream));
            PgpObject pgp = null;
            if (pgpFactory != null)
            {
                pgp = pgpFactory.NextPgpObject();
            }

            PgpEncryptedDataList encryptedData = null;
            if (pgp is PgpEncryptedDataList)
            {
                encryptedData = (PgpEncryptedDataList)pgp;
            }
            else
            {
                encryptedData = (PgpEncryptedDataList)pgpFactory.NextPgpObject();
            }

            Stream privateKeyStream = File.OpenRead(PrivateKeyOnlyPath);

            // find secret key
            PgpSecretKeyRingBundle pgpKeyRing = new PgpSecretKeyRingBundle(PgpUtilities.GetDecoderStream(privateKeyStream));
            PgpPrivateKey privateKey = null;

            foreach (PgpPublicKeyEncryptedData pked in encryptedData.GetEncryptedDataObjects())
            {
                privateKey = FindSecretKey(pgpKeyRing, pked.KeyId, Password.ToCharArray());
                if (privateKey != null)
                {
                    //pubKeyData = pked;
                    break;
                }
            }

            // get xml:
            RsaPrivateCrtKeyParameters rpckp = ((RsaPrivateCrtKeyParameters)privateKey.Key);
            RSAParameters dotNetParams = DotNetUtilities.ToRSAParameters(rpckp);
            RSA rsa = RSA.Create();
            rsa.ImportParameters(dotNetParams);
            string xmlPrivate = rsa.ToXmlString(true);

            return xmlPrivate;
        }

    }
    public static class IoHelper
    {
        public static readonly string BasePath = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);

        public static Stream GetStream(string stringData)
        {
            MemoryStream stream = new MemoryStream();
            StreamWriter writer = new StreamWriter(stream);
            writer.Write(stringData);
            writer.Flush();
            stream.Position = 0;
            return stream;
        }

        public static string GetString(Stream inputStream)
        {
            string output;
            using (StreamReader reader = new StreamReader(inputStream))
            {
                output = reader.ReadToEnd();
            }
            return output;
        }

        public static void WriteStream(Stream inputStream, ref byte[] dataBytes)
        {
            using (Stream outputStream = inputStream)
            {
                outputStream.Write(dataBytes, 0, dataBytes.Length);
            }
        }
    }
}
