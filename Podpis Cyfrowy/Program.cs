using System;
using System.Security.Cryptography;
using System.Text;



public class Program
{
    static void Main()
    {
        try
        {
            using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider(2048))
            {
                using (SHA256 sha256Hash = SHA256.Create())
                {
                    //Przyjecie danych i obliczenie funkcji skrotu
                    Console.WriteLine("Podaj dane do zaszyfrowania:");
                    string source = Console.ReadLine().ToString();
                    byte[] sourceBytes = Encoding.UTF8.GetBytes(source);
                    byte[] hashBytes = sha256Hash.ComputeHash(sourceBytes);
                    string hash = BitConverter.ToString(hashBytes).Replace("-", String.Empty);
                    Console.WriteLine("Funkcja skrótu tekstu " + source + " to: " + hash);

                    //Zaszyfrowanie danych przy pomocy RSA i odczytanie wartosci kluczu publicznego
                    UnicodeEncoding ByteConverter = new UnicodeEncoding();
                    byte[] dataToEncrypt = ByteConverter.GetBytes(hash);
                    byte[] encryptedData;
                    byte[] decryptedData;
                    encryptedData = RSAEncrypt(dataToEncrypt, RSA.ExportParameters(false), false);
                    string publicKey = Convert.ToBase64String(RSA.ExportRSAPublicKey());
                    Console.WriteLine("Klucz publiczny:");
                    Console.WriteLine(publicKey);

                    //Odszyfrowanie funkcji skrotu
                    decryptedData = RSADecrypt(encryptedData, RSA.ExportParameters(true), false);
                    string decryptedString = ByteConverter.GetString(decryptedData);
                    Console.WriteLine("Odszyfrowana funkcja skrótu: {0}", decryptedString);

                    //Porownanie odszyfrowanej funkcji skrotu i pierwotnej
                    if (hash == decryptedString)
                    {
                        Console.WriteLine("Odszyfrowanie udane");
                    } else
                    {
                        Console.WriteLine("Odszyfrowanie nieudane");
                    }
                }
            }
        }
        catch (ArgumentNullException)
        {
            Console.WriteLine("Blad szyfrowania");
        }
    }

    //Funkcja szyfrujaca
    public static byte[] RSAEncrypt(byte[] DataToEncrypt, RSAParameters RSAKeyInfo, bool DoOAEPPadding)
    {
        try
        {
            byte[] encryptedData;
            using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider())
            {
                RSA.ImportParameters(RSAKeyInfo);
                encryptedData = RSA.Encrypt(DataToEncrypt, DoOAEPPadding);
            }
            return encryptedData;
        }
        catch (CryptographicException e)
        {
            Console.WriteLine(e.Message);

            return null;
        }
    }

    //Funkcja odszyfrowujaca
    public static byte[] RSADecrypt(byte[] DataToDecrypt, RSAParameters RSAKeyInfo, bool DoOAEPPadding)
    {
        try
        {
            byte[] decryptedData;
            using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider())
            {
                RSA.ImportParameters(RSAKeyInfo);
                decryptedData = RSA.Decrypt(DataToDecrypt, DoOAEPPadding);
            }
            return decryptedData;
        }
        catch (CryptographicException e)
        {
            Console.WriteLine(e.ToString());

            return null;
        }
    }
}