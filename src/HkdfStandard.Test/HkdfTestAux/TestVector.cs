using System.Security.Cryptography;

namespace HkdfStandard.Test.HkdfTestAux
{
    public class TestVector
    {
        public string Name { get; set; }
        public HashAlgorithmName Hash { get; set; }
        public byte[] Ikm { get; set; }
        public byte[] Salt { get; set; }
        public byte[] Info { get; set; }
        public int OutputLength { get; set; }
        public byte[] Prk { get; set; }
        public byte[] Okm { get; set; }
    }
}
