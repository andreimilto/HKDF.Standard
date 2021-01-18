using HkdfStandard.Test.HkdfTestAux;
using System;
using System.Linq;
using System.Security.Cryptography;
using Xunit;

namespace HkdfStandard.Test
{
    public class HkdfTest
    {
        private const int maxOutputLengthCoef = 255;


        #region Extract byte[]

        [Fact]
        public void ExtractBytes_ThrowsArgumentOutOfRangeException_UnsupportedHashAlgorithm()
        {
            var hashAlgorithmName = new HashAlgorithmName("Noname");
            var ikm = new byte[50];

            var thrownException = Assert.Throws<ArgumentOutOfRangeException>(() => Hkdf.Extract(hashAlgorithmName, ikm));
            Assert.Equal(nameof(hashAlgorithmName), thrownException.ParamName);
        }

        [Fact]
        public void ExtractBytes_ThrowsArgumentNullException_NullIkm()
        {
            HashAlgorithmName hashAlgorithmName = HashAlgorithmName.SHA256;
            byte[] ikm = null;

            var thrownException = Assert.Throws<ArgumentNullException>(() => Hkdf.Extract(hashAlgorithmName, ikm));
            Assert.Equal(nameof(ikm), thrownException.ParamName);
        }

        [Theory]
        [MemberData(nameof(Rfc5869TestData.TestVectors), MemberType = typeof(Rfc5869TestData))]
        [MemberData(nameof(UnofficialTestData.TestVectors), MemberType = typeof(UnofficialTestData))]
        public void ExtractBytes_ProducesCorrectPrk_ForGivenTestVector(TestVector testVector)
        {
            byte[] actualPrk = Hkdf.Extract(testVector.Hash, testVector.Ikm, testVector.Salt);
            Assert.Equal(testVector.Prk, actualPrk);
        }

        [Theory]
        [InlineData(new byte[0], null)]
        [InlineData(new byte[0], new byte[0])]
        [InlineData(new byte[0], new byte[] { 255 })]
        [InlineData(new byte[] { 255 }, null)]
        [InlineData(new byte[] { 255 }, new byte[0])]
        [InlineData(new byte[] { 255 }, new byte[] { 255 })]
        public void ExtractBytes_DoesNotModifyInputs(byte[] ikm, byte[] salt)
        {
            byte[] originalIkm = ikm.ToArray();
            byte[] originalSalt = salt?.ToArray();

            Hkdf.Extract(HashAlgorithmName.SHA256, ikm, salt);

            Assert.Equal(originalIkm, ikm);
            Assert.Equal(originalSalt, salt);
        }

        #endregion


        #region Expand byte[]

        [Fact]
        public void ExpandBytes_ThrowsArgumentOutOfRangeException_UnsupportedHashAlgorithm()
        {
            HashAlgorithmName hashAlgorithmName = new HashAlgorithmName("Noname");
            byte[] prk = new byte[50];
            int outputLength = 50;

            var thrownException = Assert.Throws<ArgumentOutOfRangeException>(() => Hkdf.Expand(hashAlgorithmName, prk, outputLength));
            Assert.Equal(nameof(hashAlgorithmName), thrownException.ParamName);
        }

        [Fact]
        public void ExpandBytes_ThrowsArgumentNullException_NullPrk()
        {
            HashAlgorithmName hashAlgorithmName = HashAlgorithmName.SHA256;
            byte[] prk = null;
            int outputLength = 50;

            var thrownException = Assert.Throws<ArgumentNullException>(() => Hkdf.Expand(hashAlgorithmName, prk, outputLength));
            Assert.Equal(nameof(prk), thrownException.ParamName);
        }

        [Theory]
        [InlineData("SHA512", 64 - 1)]
        [InlineData("SHA384", 48 - 1)]
        [InlineData("SHA256", 32 - 1)]
        [InlineData("SHA1", 20 - 1)]
        [InlineData("MD5", 16 - 1)]
        public void ExpandBytes_ThrowsArgumentException_PrkTooShort(string algorithmName, int prkLength)
        {
            HashAlgorithmName hashAlgorithmName = new HashAlgorithmName(algorithmName);
            byte[] prk = new byte[prkLength];
            int outputLength = 50;

            var thrownException = Assert.Throws<ArgumentException>(() => Hkdf.Expand(hashAlgorithmName, prk, outputLength));
            Assert.Equal(nameof(prk), thrownException.ParamName);
        }

        [Theory]
        [InlineData(0)]
        [InlineData(-1)]
        [InlineData(int.MinValue)]
        public void ExpandBytes_ThrowsArgumentOutOfRangeException_OutputLengthTooSmall(int outputLength)
        {
            var hashAlgorithmName = HashAlgorithmName.SHA256;
            byte[] prk = new byte[50];

            var thrownException = Assert.Throws<ArgumentOutOfRangeException>(() => Hkdf.Expand(hashAlgorithmName, prk, outputLength));
            Assert.Equal(nameof(outputLength), thrownException.ParamName);
        }

        [Theory]
        [InlineData("SHA512", 64 * maxOutputLengthCoef + 1)]
        [InlineData("SHA384", 48 * maxOutputLengthCoef + 1)]
        [InlineData("SHA256", 32 * maxOutputLengthCoef + 1)]
        [InlineData("SHA1", 20 * maxOutputLengthCoef + 1)]
        [InlineData("MD5", 16 * maxOutputLengthCoef + 1)]
        public void ExpandBytes_ThrowsArgumentOutOfRangeException_OutputLengthTooLarge(string algorithmName, int outputLength)
        {
            var hashAlgorithmName = new HashAlgorithmName(algorithmName);
            byte[] prk = new byte[100];

            var thrownException = Assert.Throws<ArgumentOutOfRangeException>(() => Hkdf.Expand(hashAlgorithmName, prk, outputLength));
            Assert.Equal(nameof(outputLength), thrownException.ParamName);
        }

        [Theory]
        [MemberData(nameof(Rfc5869TestData.TestVectors), MemberType = typeof(Rfc5869TestData))]
        [MemberData(nameof(UnofficialTestData.TestVectors), MemberType = typeof(UnofficialTestData))]
        public void ExpandBytes_ProducesCorrectOkm_ForGivenTestVector(TestVector testVector)
        {
            byte[] actualOkm = Hkdf.Expand(testVector.Hash, testVector.Prk, testVector.OutputLength, testVector.Info);
            Assert.Equal(testVector.Okm, actualOkm);
        }

        [Theory]
        [InlineData(null)]
        [InlineData(new byte[0])]
        [InlineData(new byte[] { 255 })]
        public void ExpandBytes_DoesNotModifyInputs(byte[] info)
        {
            HashAlgorithmName hashAlgorithmName = HashAlgorithmName.SHA256;
            byte[] prk = Enumerable.Repeat<byte>(255, 32).ToArray();
            int outputLength = 50;

            byte[] originalPrk = prk.ToArray();
            byte[] originalInfo = info?.ToArray();

            Hkdf.Expand(hashAlgorithmName, prk, outputLength, info);

            Assert.Equal(originalPrk, prk);
            Assert.Equal(originalInfo, info);
        }

        #endregion


        #region DeriveKey byte[]

        [Fact]
        public void DeriveKeyBytes_ThrowsArgumentOutOfRangeException_UnsupportedHashAlgorithm()
        {
            HashAlgorithmName hashAlgorithmName = new HashAlgorithmName("Noname");
            byte[] ikm = new byte[50];
            int outputLength = 50;

            var thrownException = Assert.Throws<ArgumentOutOfRangeException>(() => Hkdf.DeriveKey(hashAlgorithmName, ikm, outputLength));
            Assert.Equal(nameof(hashAlgorithmName), thrownException.ParamName);
        }

        [Fact]
        public void DeriveKeyBytes_ThrowsArgumentNullException_NullIkm()
        {
            HashAlgorithmName hashAlgorithmName = HashAlgorithmName.SHA256;
            byte[] ikm = null;
            int outputLength = 50;

            var thrownException = Assert.Throws<ArgumentNullException>(() => Hkdf.DeriveKey(hashAlgorithmName, ikm, outputLength));
            Assert.Equal(nameof(ikm), thrownException.ParamName);
        }

        [Theory]
        [InlineData(0)]
        [InlineData(-1)]
        [InlineData(int.MinValue)]
        public void DeriveKeyBytes_ThrowsArgumentOutOfRangeException_OutputLengthTooSmall(int outputLength)
        {
            var hashAlgorithmName = HashAlgorithmName.SHA256;
            var ikm = new byte[50];

            var thrownException = Assert.Throws<ArgumentOutOfRangeException>(() => Hkdf.DeriveKey(hashAlgorithmName, ikm, outputLength));
            Assert.Equal(nameof(outputLength), thrownException.ParamName);
        }

        [Theory]
        [InlineData("SHA512", 64 * maxOutputLengthCoef + 1)]
        [InlineData("SHA384", 48 * maxOutputLengthCoef + 1)]
        [InlineData("SHA256", 32 * maxOutputLengthCoef + 1)]
        [InlineData("SHA1", 20 * maxOutputLengthCoef + 1)]
        [InlineData("MD5", 16 * maxOutputLengthCoef + 1)]
        public void DeriveKeyBytes_ThrowsArgumentOutOfRangeException_OutputLengthTooLarge(string algorithmName, int outputLength)
        {
            var hashAlgorithmName = new HashAlgorithmName(algorithmName);
            var ikm = new byte[100];

            var thrownException = Assert.Throws<ArgumentOutOfRangeException>(() => Hkdf.DeriveKey(hashAlgorithmName, ikm, outputLength));
            Assert.Equal(nameof(outputLength), thrownException.ParamName);
        }

        [Theory]
        [MemberData(nameof(Rfc5869TestData.TestVectors), MemberType = typeof(Rfc5869TestData))]
        [MemberData(nameof(UnofficialTestData.TestVectors), MemberType = typeof(UnofficialTestData))]
        public void DeriveKeyBytes_ProducesCorrectOkm_ForGivenTestVector(TestVector testVector)
        {
            byte[] actualOkm = Hkdf.DeriveKey(testVector.Hash, testVector.Ikm, testVector.OutputLength, testVector.Salt, testVector.Info);
            Assert.Equal(testVector.Okm, actualOkm);
        }

        [Theory]
        [InlineData(new byte[0], null, null)]
        [InlineData(new byte[0], null, new byte[0])]
        [InlineData(new byte[0], null, new byte[] { 255 })]
#pragma warning disable xUnit1025 // InlineData should be unique within the Theory it belongs to. See the xUnit bug https://github.com/xunit/xunit/issues/1877.
        [InlineData(new byte[0], new byte[0], null)]
#pragma warning restore xUnit1025 // InlineData should be unique within the Theory it belongs to
        [InlineData(new byte[0], new byte[0], new byte[0])]
        [InlineData(new byte[0], new byte[0], new byte[] { 255 })]
        [InlineData(new byte[0], new byte[] { 255 }, null)]
#pragma warning disable xUnit1025 // InlineData should be unique within the Theory it belongs to
        [InlineData(new byte[0], new byte[] { 255 }, new byte[0])]
#pragma warning restore xUnit1025 // InlineData should be unique within the Theory it belongs to
        [InlineData(new byte[0], new byte[] { 255 }, new byte[] { 255 })]
        [InlineData(new byte[] { 255 }, null, null)]
        [InlineData(new byte[] { 255 }, null, new byte[0])]
        [InlineData(new byte[] { 255 }, null, new byte[] { 255 })]
#pragma warning disable xUnit1025 // InlineData should be unique within the Theory it belongs to
        [InlineData(new byte[] { 255 }, new byte[0], null)]
#pragma warning restore xUnit1025 // InlineData should be unique within the Theory it belongs to
        [InlineData(new byte[] { 255 }, new byte[0], new byte[0])]
        [InlineData(new byte[] { 255 }, new byte[0], new byte[] { 255 })]
        [InlineData(new byte[] { 255 }, new byte[] { 255 }, null)]
#pragma warning disable xUnit1025 // InlineData should be unique within the Theory it belongs to
        [InlineData(new byte[] { 255 }, new byte[] { 255 }, new byte[0])]
#pragma warning restore xUnit1025 // InlineData should be unique within the Theory it belongs to
        [InlineData(new byte[] { 255 }, new byte[] { 255 }, new byte[] { 255 })]
        public void DeriveKeyBytes_DoesNotModifyInputs(byte[] ikm, byte[] salt, byte[] info)
        {
            HashAlgorithmName hashAlgorithmName = HashAlgorithmName.SHA256;
            int outputLength = 50;

            byte[] originalIkm = ikm.ToArray();
            byte[] originalSalt = salt?.ToArray();
            byte[] originalInfo = info?.ToArray();

            Hkdf.DeriveKey(hashAlgorithmName, ikm, outputLength, salt, info);

            Assert.Equal(originalIkm, ikm);
            Assert.Equal(originalSalt, salt);
            Assert.Equal(originalInfo, info);
        }

        #endregion


#if NETCOREAPP3_1

        #region Extract Span<byte>

        [Fact]
        public void ExtractSpan_ThrowsArgumentOutOfRangeException_UnsupportedHashAlgorithm()
        {
            var hashAlgorithmName = new HashAlgorithmName("Noname");
            var ikm = new byte[50];
            var salt = new byte[50];
            var prk = new byte[50];

            var thrownException = Assert.Throws<ArgumentOutOfRangeException>(() => Hkdf.Extract(hashAlgorithmName, ikm, salt, prk));
            Assert.Equal(nameof(hashAlgorithmName), thrownException.ParamName);
        }

        [Theory]
        [InlineData("SHA512", 64 - 1)]
        [InlineData("SHA384", 48 - 1)]
        [InlineData("SHA256", 32 - 1)]
        [InlineData("SHA1", 20 - 1)]
        [InlineData("MD5", 16 - 1)]
        public void ExtractSpan_ThrowsArgumentException_PrkTooShort(string alrogithmName, int prkLength)
        {
            var hashAlgorithmName = new HashAlgorithmName(alrogithmName);
            var ikm = new byte[50];
            var salt = new byte[50];
            var prk = new byte[prkLength];

            var thrownException = Assert.Throws<ArgumentException>(() => Hkdf.Extract(hashAlgorithmName, ikm, salt, prk));
            Assert.Equal(nameof(prk), thrownException.ParamName);
        }

        [Theory]
        [MemberData(nameof(Rfc5869TestData.TestVectors), MemberType = typeof(Rfc5869TestData))]
        [MemberData(nameof(UnofficialTestData.TestVectors), MemberType = typeof(UnofficialTestData))]
        public void ExtractSpan_ProducesCorrectPrk_ForGivenTestVector(TestVector testVector)
        {
            byte[] actualPrk = new byte[testVector.Prk.Length];

            int actualPrkLength = Hkdf.Extract(testVector.Hash, testVector.Ikm, testVector.Salt, actualPrk);

            Assert.Equal(testVector.Prk.Length, actualPrkLength);
            Assert.Equal(testVector.Prk, actualPrk);
        }

        #endregion


        #region Expand Span<byte>

        [Fact]
        public void ExpandSpan_ThrowsArgumentOutOfRangeException_UnsupportedHashAlgorithm()
        {
            var hashAlgorithmName = new HashAlgorithmName("Noname");
            byte[] prk = new byte[50];
            byte[] okm = new byte[50];
            byte[] info = new byte[50];

            var thrownException = Assert.Throws<ArgumentOutOfRangeException>(() => Hkdf.Expand(hashAlgorithmName, prk, okm, info));
            Assert.Equal(nameof(hashAlgorithmName), thrownException.ParamName);
        }

        [Theory]
        [InlineData("SHA512", 64 - 1)]
        [InlineData("SHA384", 48 - 1)]
        [InlineData("SHA256", 32 - 1)]
        [InlineData("SHA1", 20 - 1)]
        [InlineData("MD5", 16 - 1)]
        public void ExpandSpan_ThrowsArgumentException_PrkTooShort(string algorithmName, int prkLength)
        {
            var hashAlgorithmName = new HashAlgorithmName(algorithmName);
            var prk = new byte[prkLength];
            var output = new byte[50];
            var info = new byte[50];

            var thrownException = Assert.Throws<ArgumentException>(() => Hkdf.Expand(hashAlgorithmName, prk, output, info));
            Assert.Equal(nameof(prk), thrownException.ParamName);
        }

        [Fact]
        public void ExpandSpan_ThrowsArgumentException_ZeroOutputLength()
        {
            var hashAlgorithmName = HashAlgorithmName.SHA256;
            byte[] prk = new byte[50];
            byte[] output = new byte[0];
            byte[] info = new byte[50];

            var thrownException = Assert.Throws<ArgumentException>(() => Hkdf.Expand(hashAlgorithmName, prk, output, info));
            Assert.Equal(nameof(output), thrownException.ParamName);
        }

        [Theory]
        [InlineData("SHA512", 64 * maxOutputLengthCoef + 1)]
        [InlineData("SHA384", 48 * maxOutputLengthCoef + 1)]
        [InlineData("SHA256", 32 * maxOutputLengthCoef + 1)]
        [InlineData("SHA1", 20 * maxOutputLengthCoef + 1)]
        [InlineData("MD5", 16 * maxOutputLengthCoef + 1)]
        public void ExpandSpan_ThrowsArgumentException_OutputLengthTooLarge(string algorithmName, int outputLength)
        {
            var hashAlgorithmName = new HashAlgorithmName(algorithmName);
            var prk = new byte[100];
            var output = new byte[outputLength];
            var info = new byte[50];

            var thrownException = Assert.Throws<ArgumentException>(() => Hkdf.Expand(hashAlgorithmName, prk, output, info));
            Assert.Equal(nameof(output), thrownException.ParamName);
        }

        [Theory]
        [MemberData(nameof(Rfc5869TestData.TestVectors), MemberType = typeof(Rfc5869TestData))]
        [MemberData(nameof(UnofficialTestData.TestVectors), MemberType = typeof(UnofficialTestData))]
        public void ExpandSpan_ProducesCorrectOkm_ForGivenTestVector(TestVector testVector)
        {
            byte[] actualOkm = new byte[testVector.OutputLength];

            Hkdf.Expand(testVector.Hash, testVector.Prk, actualOkm, testVector.Info);

            Assert.Equal(testVector.Okm, actualOkm);
        }

        #endregion


        #region DeriveKey Span<byte>

        [Fact]
        public void DeriveKeySpan_ThrowsArgumentOutOfRangeException_UnsupportedHashAlgorithm()
        {
            var hashAlgorithmName = new HashAlgorithmName("Noname");
            var ikm = new byte[50];
            var output = new byte[50];
            var salt = new byte[50];
            var info = new byte[50];

            var thrownException = Assert.Throws<ArgumentOutOfRangeException>(() => Hkdf.DeriveKey(hashAlgorithmName, ikm, output, salt, info));
            Assert.Equal(nameof(hashAlgorithmName), thrownException.ParamName);
        }

        [Fact]
        public void DeriveKeySpan_ThrowsArgumentException_ZeroOutputLength()
        {
            var hashAlgorithmName = HashAlgorithmName.SHA256;
            byte[] ikm = new byte[50];
            byte[] output = new byte[0];
            byte[] salt = new byte[50];
            byte[] info = new byte[50];

            var thrownException = Assert.Throws<ArgumentException>(() => Hkdf.DeriveKey(hashAlgorithmName, ikm, output, salt, info));
            Assert.Equal(nameof(output), thrownException.ParamName);
        }

        [Theory]
        [InlineData("SHA512", 64 * maxOutputLengthCoef + 1)]
        [InlineData("SHA384", 48 * maxOutputLengthCoef + 1)]
        [InlineData("SHA256", 32 * maxOutputLengthCoef + 1)]
        [InlineData("SHA1", 20 * maxOutputLengthCoef + 1)]
        [InlineData("MD5", 16 * maxOutputLengthCoef + 1)]
        public void DeriveKeySpan_ThrowsArgumentException_OutputLengthTooLarge(string algorithmName, int outputLength)
        {
            var hashAlgorithmName = new HashAlgorithmName(algorithmName);
            var ikm = new byte[100];
            var output = new byte[outputLength];
            var salt = new byte[50];
            var info = new byte[50];

            var thrownException = Assert.Throws<ArgumentException>(() => Hkdf.DeriveKey(hashAlgorithmName, ikm, output, salt, info));
            Assert.Equal(nameof(output), thrownException.ParamName);
        }

        [Theory]
        [MemberData(nameof(Rfc5869TestData.TestVectors), MemberType = typeof(Rfc5869TestData))]
        [MemberData(nameof(UnofficialTestData.TestVectors), MemberType = typeof(UnofficialTestData))]
        public void DeriveKeySpan_ProducesCorrectOkm_ForGivenTestVector(TestVector testVector)
        {
            byte[] actualOkm = new byte[testVector.OutputLength];

            Hkdf.DeriveKey(testVector.Hash, testVector.Ikm, actualOkm, testVector.Salt, testVector.Info);

            Assert.Equal(testVector.Okm, actualOkm);
        }

        #endregion
    
#endif        
    }
}
