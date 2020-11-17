using BenchmarkDotNet.Attributes;
using NSec.Cryptography;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace HkdfStandard.Benchmark
{
    [MaxRelativeError(0.005)]
    public class KeyDerivationBenchmark
    {
        #region Parameters
        
        private byte[] ikm = new byte[32];
        private byte[] salt = new byte[32];
        private byte[] info = new byte[32];


        public IEnumerable<byte[]> Okms => new[]
        {
            new byte[16],
            new byte[512]
        };

        [ParamsSource(nameof(Okms))]
        public byte[] Okm;


        public IEnumerable<HashAlgorithmName> DotNetHashes => new[]
        {
            HashAlgorithmName.MD5,
            HashAlgorithmName.SHA1,
            HashAlgorithmName.SHA256,
            HashAlgorithmName.SHA384,
            HashAlgorithmName.SHA512
        };

        public IEnumerable<IDigest> BouncyCastleHashes => new IDigest[]
        {
            new MD5Digest(),
            new Sha1Digest(),
            new Sha256Digest(),
            new Sha384Digest(),
            new Sha512Digest()
        };

        public IEnumerable<KeyDerivationAlgorithm> NSecKdfs => new KeyDerivationAlgorithm[]
        {
            KeyDerivationAlgorithm.HkdfSha256,
            KeyDerivationAlgorithm.HkdfSha512,
        };

        #endregion


        #region Benchmark the HKDF.Standard's HKDF

        [Benchmark]
        [ArgumentsSource(nameof(DotNetHashes))]
        public void BenchmarkHkdfStandardBytes(HashAlgorithmName hash)
        {
            Hkdf.DeriveKey(hash, ikm, Okm.Length, salt, info);
        }

        [Benchmark]
        [ArgumentsSource(nameof(DotNetHashes))]
        public void BenchmarkHkdfStandardSpan(HashAlgorithmName hash)
        {
            Hkdf.DeriveKey(hash, ikm, Okm, salt, info);
        }

        #endregion


        #region Benchmark the .NET 5's HKDF

        [Benchmark]
        [ArgumentsSource(nameof(DotNetHashes))]
        public void BenchmarkDotNet5Bytes(HashAlgorithmName hash)
        {
            HKDF.DeriveKey(hash, ikm, Okm.Length, salt, info);
        }

        [Benchmark]
        [ArgumentsSource(nameof(DotNetHashes))]
        public void BenchmarkDotNet5Span(HashAlgorithmName hash)
        {
            HKDF.DeriveKey(hash, ikm, Okm, salt, info);
        }

        #endregion


        #region Benchmark the Bouncy Castle's HKDF

        [Benchmark]
        [ArgumentsSource(nameof(BouncyCastleHashes))]
        public void BenchmarkBouncyCastleBytes(IDigest hash)
        {
            var hkdf = new HkdfBytesGenerator(hash);
            hkdf.Init(new HkdfParameters(ikm, salt, info));
            hkdf.GenerateBytes(Okm, 0, Okm.Length);
        }

        #endregion


        #region Benchmark the NSec's HKDF

        [Benchmark]
        [ArgumentsSource(nameof(NSecKdfs))]
        public void BenchmarkNSecBytes(KeyDerivationAlgorithm kdf)
        {
            var sharedSecret = SharedSecret.Import(ikm);
            kdf.DeriveBytes(sharedSecret, salt, info, Okm.Length);
        }

        [Benchmark]
        [ArgumentsSource(nameof(NSecKdfs))]
        public void BenchmarkNSecSpan(KeyDerivationAlgorithm kdf)
        {
            var sharedSecret = SharedSecret.Import(ikm);
            kdf.DeriveBytes(sharedSecret, salt, info, Okm);
        }

        #endregion
    }
}
