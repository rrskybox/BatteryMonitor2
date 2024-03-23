using System.IO;
using System.Security.Cryptography;

namespace BatteryMonitor
{
    internal class CryptoLEOld
    {
        private static readonly int _hlen = 128;
        private static readonly byte[] _IV = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
        private static readonly byte[] _KEY = { 0x6c, 0x65, 0x61, 0x67, 0x65, 0x6e, 0x64, 0xff, 0xfe, 0x31, 0x38, 0x38, 0x32, 0x34, 0x36, 0x36 };

        //public string HandleNotification(int self, int cHandle, string data)
        //{
        //    now = int(time.time())
        //    string encrypted_data = data;
        //    string decrypted_data = AES.new(KEY, AES.MODE_CBC, bytes([0] * 16)).decrypt(bytes(encrypted_data));
        //    voltage = (struct.unpack(">H", decrypted_data[1:1 + 2])[0] >> 4) / 100
        //if(logfile):
        //    payload = f'{now} {voltage}'
        //    logging.basicConfig(filename=logfile,level=logging.DEBUG,format='%(asctime)s %(message)s', datefmt='%d/%m/%Y %H:%M:%S')
        //    logging.info(payload)
        //else:
        //    if(loop==False):
        //        payload = f'{voltage}'
        //        print(payload+' V')
        //    else:
        //        payload = f'{now} {voltage}'
        //        print(payload)
        //if(loop==False):
        //    p.disconnect();
        //    exit(0)
        //    }

        public string HandleNotification(byte[] data)
        {
            return DecryptStringFromBytes_Aes(data, _KEY, _IV);
        }

        public static string DecryptLE(byte[] data)
        {
            return DecryptStringFromBytes_Aes(data, _KEY, _IV);
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

                // Create a decryptor to perform the stream transform.
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for decryption.
                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
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
            }

            return plaintext;
        }
    }
}
