using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;
using System;
using System.IO;
using System.Text;

namespace RSASignSHA1
{
    public class Program
    {
        [STAThread]
        private static void Main(string[] args)
        {

            var model = new Rootobject();
            var dic = ReflectionObj.ToDictionary(model);

            var ts = ReflectionObj.GetText(dic);  //46c0fc7fcf95895d5061887857AC320519588998930097129



            var cripto = new Crypto();
            var text = "cf117375f9c44d9f5061887857AC320519588998930097129";

            var md5 = cripto.MD5Hash(text); //c0697ea5f30399bdce8b6b7759bb6393


            var keys = cripto.GenerateRandomKeyPair();

            var res = cripto.Sign(md5, keys.privateKey);

            var str = cripto.getHEX(res);

            Console.WriteLine(str);
        }
    }

    public class ReflectionObj
    {
        public static Dictionary<string, object> ToDictionary(object obj)
        {
            var d = new Dictionary<string, object>();

            foreach (var prop in obj.GetType().GetProperties())
            {
                d.Add(prop.Name, prop.GetValue(obj, null));
            }

            return d;
        }

        public static string GetText(Dictionary<string, object> d)
        {
            var ls = d.Keys.OrderBy(x => x).ToArray();
            string res = "";
            foreach (var it in ls)
            {
                if (it == "signed" || it == "sign") continue;
                res += d[it].ToString();
            }

            return res;
        }
    }


    public class Crypto
    {

        public (RsaPrivateCrtKeyParameters privateKey, RsaKeyParameters publicKey) GenerateRandomKeyPair()
        {
            var rsaKeyPairGen = new RsaKeyPairGenerator();
            var sr = new SecureRandom();
            BigInteger pubExp = new BigInteger("10001", 16);
            var RSAKeyGenPara = new RsaKeyGenerationParameters(pubExp, sr, 1024, 80);

            rsaKeyPairGen.Init(RSAKeyGenPara);

            AsymmetricCipherKeyPair keyPair = rsaKeyPairGen.GenerateKeyPair();


            PrintKeys(keyPair);

            var RSAprivKey = (RsaPrivateCrtKeyParameters)keyPair.Private;
            var RSApubKey = (RsaKeyParameters)keyPair.Public;

            BigInteger RSAmod = ((RsaPrivateCrtKeyParameters)keyPair.Private).Modulus;
            BigInteger RSAprivExp = ((RsaPrivateCrtKeyParameters)keyPair.Private).Exponent;
            BigInteger RSApubExp = ((RsaPrivateCrtKeyParameters)keyPair.Private).PublicExponent;
            BigInteger RSAdp = ((RsaPrivateCrtKeyParameters)keyPair.Private).DP;
            BigInteger RSAdq = ((RsaPrivateCrtKeyParameters)keyPair.Private).DQ;
            BigInteger RSAp = ((RsaPrivateCrtKeyParameters)keyPair.Private).P;
            BigInteger RSAq = ((RsaPrivateCrtKeyParameters)keyPair.Private).Q;
            BigInteger RSAqInv = ((RsaPrivateCrtKeyParameters)keyPair.Private).QInv;


            var RSAprivKeyBOU = new RsaPrivateCrtKeyParameters(((RsaPrivateCrtKeyParameters)keyPair.Private).Modulus,
                                                               ((RsaPrivateCrtKeyParameters)keyPair.Private).PublicExponent,
                                                               ((RsaPrivateCrtKeyParameters)keyPair.Private).Exponent,
                                                               ((RsaPrivateCrtKeyParameters)keyPair.Private).P,
                                                               ((RsaPrivateCrtKeyParameters)keyPair.Private).Q,
                                                               ((RsaPrivateCrtKeyParameters)keyPair.Private).DP,
                                                               ((RsaPrivateCrtKeyParameters)keyPair.Private).DQ,
                                                               ((RsaPrivateCrtKeyParameters)keyPair.Private).QInv);

            RSApubKey = new RsaKeyParameters(false, ((RsaPrivateCrtKeyParameters)keyPair.Private).Modulus,
                                                    ((RsaPrivateCrtKeyParameters)keyPair.Private).PublicExponent);


            var publicKey = new RsaKeyParameters(false, RSAprivKey.Modulus, RSAprivKey.PublicExponent);

            var PublicKeyStr = GetPublicKey(publicKey);
            var PrivateKeyStr = GetPrivateKey(RSAprivKey);



            return (RSAprivKey, RSApubKey);
        }

        public string GetPublicKey(RsaKeyParameters publicKey)
        {
            TextWriter textWriter = new StringWriter();
            PemWriter pemWriter = new PemWriter(textWriter);
            pemWriter.WriteObject(publicKey);
            pemWriter.Writer.Flush();
            String publicKeyPEM = textWriter.ToString();

            return publicKeyPEM;
        }

        public string GetPrivateKey(RsaPrivateCrtKeyParameters key)
        {
            TextWriter textWriter = new StringWriter();
            PemWriter pemWriter = new PemWriter(textWriter);
            pemWriter.WriteObject(key);
            pemWriter.Writer.Flush();
            String publicKeyPEM = textWriter.ToString();

            return publicKeyPEM;
        }

        public AsymmetricKeyParameter ReadAsymmetricKeyParameter(string pemFilename)
        {
            var fileStream = System.IO.File.OpenText(pemFilename);
            var pemReader = new Org.BouncyCastle.OpenSsl.PemReader(fileStream);
            var KeyParameter = (Org.BouncyCastle.Crypto.AsymmetricKeyParameter)pemReader.ReadObject();
            return KeyParameter;
        }

        public void GetKeys(string publicKeyPEM)
        {
            TextReader textReader = new StringReader(publicKeyPEM);
            PemReader pemReader = new PemReader(textReader);
            RsaKeyParameters publicKeyRestored = (RsaKeyParameters)pemReader.ReadObject();
        }

        public string MD5Hash(string input)
        {
            using (System.Security.Cryptography.MD5 md5 = System.Security.Cryptography.MD5.Create())
            {
                byte[] inputBytes = System.Text.Encoding.ASCII.GetBytes(input);
                byte[] hashBytes = md5.ComputeHash(inputBytes);

                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < hashBytes.Length; i++)
                {
                    sb.Append(hashBytes[i].ToString("X2"));
                }
                return sb.ToString();
            }
        }

        public bool Verify(string sourceData, byte[] signature, RsaKeyParameters publicKey)
        {
            byte[] tmpSource = Encoding.ASCII.GetBytes(sourceData);

            ISigner signClientSide = SignerUtilities.GetSigner(PkcsObjectIdentifiers.Sha1WithRsaEncryption.Id);
            signClientSide.Init(false, publicKey);
            signClientSide.BlockUpdate(tmpSource, 0, tmpSource.Length);

            return signClientSide.VerifySignature(signature);
        }

        public byte[] Sign(string sourceData, RsaKeyParameters privateKey)
        {
            byte[] tmpSource = Encoding.ASCII.GetBytes(sourceData);

            ISigner sign = SignerUtilities.GetSigner(PkcsObjectIdentifiers.Sha1WithRsaEncryption.Id);
            sign.Init(true, privateKey);
            sign.BlockUpdate(tmpSource, 0, tmpSource.Length);
            return sign.GenerateSignature();
        }

        public void PrintKeys(AsymmetricCipherKeyPair keyPair)
        {
            using (TextWriter textWriter1 = new StringWriter())
            {
                var pemWriter1 = new PemWriter(textWriter1);
                pemWriter1.WriteObject(keyPair.Private);
                pemWriter1.Writer.Flush();

                string privateKey = textWriter1.ToString();
                Console.WriteLine(privateKey);
            }

            using (TextWriter textWriter2 = new StringWriter())
            {
                var pemWriter2 = new PemWriter(textWriter2);
                pemWriter2.WriteObject(keyPair.Public);
                pemWriter2.Writer.Flush();
                string publicKey = textWriter2.ToString();
                Console.WriteLine(publicKey);
            }
        }

        private byte[] ConvertHexString(string hexString)
        {
            byte[] data = new byte[hexString.Length / 2];
            for (int index = 0; index < data.Length; index++)
            {
                string byteValue = hexString.Substring(index * 2, 2);
                data[index] = byte.Parse(byteValue, System.Globalization.NumberStyles.HexNumber, System.Globalization.CultureInfo.InvariantCulture);
            }

            return data;
        }

        public string getHEX(byte[] keys)
        {
            return Convert.ToBase64String(keys);
        }

    }
}

//https://8gwifi.org/RSAFunctionality?rsasignverifyfunctions=rsasignverifyfunctions&keysize=1024