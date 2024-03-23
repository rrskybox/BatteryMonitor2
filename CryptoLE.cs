using System.Runtime.InteropServices.WindowsRuntime;
using Windows.Security.Cryptography;
using Windows.Security.Cryptography.Core;
using Windows.Storage;
using Windows.Storage.Streams;

namespace BatteryMonitor
{
    public sealed class CryptoLE
    {
        private static readonly int _hlen = 128;
        private static readonly byte[] _IV = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
        private static readonly byte[] _KEY = { 0x6c, 0x65, 0x61, 0x67, 0x65, 0x6e, 0x64, 0xff, 0xfe, 0x31, 0x38, 0x38, 0x32, 0x34, 0x36, 0x36 };

        public CryptoLE()
        {

        }

        public byte[]? BM2_Decrypt(byte[] bm2)
        {
            //Decrypt string
            byte[] decrypt = DecryptAesAsync(bm2, _KEY, _IV);

            return decrypt;
        }


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

        //public string HandleNotification(byte[] data)
        //{
        //    return DecryptStringFromBytes_Aes(data, _KEY, _IV);
        //}

        //public string DecryptLE(byte[] data)
        //{
        //    return DecryptStringFromBytes_Aes(data, _KEY, _IV);
        //}

        //public string DecryptStringFromBytes_Aes(byte[] cipherText, byte[] Key, byte[] IV)
        //{
        //    // Check arguments.
        //    if (cipherText == null || cipherText.Length <= 0)
        //        rootPage.NotifyUser("Error: Cipher text exception, try again.", NotifyType.ErrorMessage);
        //    if (Key == null || Key.Length <= 0)
        //        rootPage.NotifyUser("Error: Cipher key exception, try again.", NotifyType.ErrorMessage);
        //    if (IV == null || IV.Length <= 0)
        //        rootPage.NotifyUser("Error: Cipher vector exception, try again.", NotifyType.ErrorMessage);

        //    // Declare the string used to hold
        //    // the decrypted text.
        //    string plaintext = null;

        //    // Create an Aes object
        //    // with the specified key and IV.
        //    using (Aes aesAlg = Aes.Create())
        //    {
        //        aesAlg.Key = Key;
        //        aesAlg.IV = IV;

        //        // Create a decryptor to perform the stream transform.
        //        ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

        //        // Create the streams used for decryption.
        //        using (MemoryStream msDecrypt = new MemoryStream(cipherText))
        //        {
        //            using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
        //            {
        //                using (StreamReader srDecrypt = new StreamReader(csDecrypt))
        //                {

        //                    // Read the decrypted bytes from the decrypting stream
        //                    // and place them in a string.
        //                    plaintext = srDecrypt.ReadToEnd();
        //                }
        //            }
        //        }
        //    }

        //    return plaintext;
        //}

        public async Task<bool> EncryptAesFileAsync(StorageFile fileForEncryption, string aesKey256, string iv16length)
        {

            bool success = false;
            try
            {
                //Initialize key
                IBuffer key = Convert.FromBase64String(aesKey256).AsBuffer();
                var m_iv = Convert.FromBase64String(iv16length).AsBuffer();
                SymmetricKeyAlgorithmProvider provider = SymmetricKeyAlgorithmProvider.OpenAlgorithm(SymmetricAlgorithmNames.AesCbcPkcs7);
                var m_key = provider.CreateSymmetricKey(key);

                //secured data
                IBuffer data = await FileIO.ReadBufferAsync(fileForEncryption);
                IBuffer SecuredData = CryptographicEngine.Encrypt(m_key, data, m_iv);
                await FileIO.WriteBufferAsync(fileForEncryption, SecuredData);
                success = true;
            }
            catch (Exception ex)
            {
                success = false;
            }
            return success;

        }

        public async Task<bool> DecryptAesFileAsync(StorageFile EncryptedFile, string aesKey256, string iv16length)
        {

            bool success = false;
            try
            {
                //Initialize key
                IBuffer key = Convert.FromBase64String(aesKey256).AsBuffer();
                var m_iv = Convert.FromBase64String(iv16length).AsBuffer();
                SymmetricKeyAlgorithmProvider provider = SymmetricKeyAlgorithmProvider.OpenAlgorithm(SymmetricAlgorithmNames.AesCbcPkcs7);
                var m_key = provider.CreateSymmetricKey(key);

                //Unsecured Data
                IBuffer data = await FileIO.ReadBufferAsync(EncryptedFile);
                IBuffer UnSecuredData = CryptographicEngine.Decrypt(m_key, data, m_iv);
                await FileIO.WriteBufferAsync(EncryptedFile, UnSecuredData);
                success = true;
            }
            catch (Exception ex)
            {
                success = false;
            }
            return success;
        }

        public byte[]? EncryptAesAsync(byte[] forEncryption, byte[] aesKey256, byte[] iv16length)
        {
            try
            {
                //Initialize key
                IBuffer key = aesKey256.AsBuffer(); // IBuffer key = Convert.FromBase64String(aesKey256).AsBuffer();
                var m_iv = iv16length.AsBuffer();  // var m_iv = Convert.FromBase64String(iv16length).AsBuffer();
                SymmetricKeyAlgorithmProvider provider = SymmetricKeyAlgorithmProvider.OpenAlgorithm(SymmetricAlgorithmNames.AesCbcPkcs7);
                var m_key = provider.CreateSymmetricKey(key);

                //secured data
                IBuffer data = forEncryption.AsBuffer(); // Convert.FromBase64String(forEncryption).AsBuffer();
                IBuffer SecuredData = CryptographicEngine.Encrypt(m_key, data, m_iv);
                byte[] dataOut;
                CryptographicBuffer.CopyToByteArray(SecuredData, out dataOut);
                return dataOut;
            }
            catch (Exception ex)
            {
                return null;
            }
        }

        public byte[]? DecryptAesAsync(byte[] forDecryption, byte[] aesKey256, byte[] iv16length)
        {
            byte[]? decryptData;
            try
            {
                //Initialize key
                IBuffer key = aesKey256.AsBuffer();  //IBuffer key = Convert.FromBase64String(aesKey256).AsBuffer();
                var m_iv = iv16length.AsBuffer(); // Convert.FromBase64String(iv16length).AsBuffer();
                SymmetricKeyAlgorithmProvider provider = SymmetricKeyAlgorithmProvider.OpenAlgorithm(SymmetricAlgorithmNames.AesCbc);
                var m_key = provider.CreateSymmetricKey(key);

                //Unsecured Data
                IBuffer data = forDecryption.AsBuffer(); // Convert.FromBase64String(forDecryption).AsBuffer();
                IBuffer UnSecuredData = CryptographicEngine.Decrypt(m_key, data, m_iv);
                CryptographicBuffer.CopyToByteArray(UnSecuredData, out decryptData);
                return decryptData;
            }
            catch (Exception ex)
            {
                return null;
            }
        }


    }
}
