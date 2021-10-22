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


#if (NETCOREAPP3_1 || NET5_0)

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
        public void ExtractSpan_ThrowsArgumentException_PrkTooShort(string algorithmName, int prkLength)
        {
            var hashAlgorithmName = new HashAlgorithmName(algorithmName);
            var ikm = new byte[50];
            var salt = new byte[50];
            var prk = new byte[prkLength];

            var thrownException = Assert.Throws<ArgumentException>(() => Hkdf.Extract(hashAlgorithmName, ikm, salt, prk));
            Assert.Equal(nameof(prk), thrownException.ParamName);
        }

        [Theory]
        [InlineData("SHA512", 1000, 936, "a519b5386ab65d436f1aab000bebdf83a70ff531ff833d979cbfe41c05fac0cba72f8fcad989fb6734009ffe0818e7a3e8ea5f666e9f273ed359f3a602d720c2")]
        [InlineData("SHA512", 1000, 468, "a519b5386ab65d436f1aab000bebdf83a70ff531ff833d979cbfe41c05fac0cba72f8fcad989fb6734009ffe0818e7a3e8ea5f666e9f273ed359f3a602d720c2")]
        [InlineData("SHA512", 1000, 0, "a519b5386ab65d436f1aab000bebdf83a70ff531ff833d979cbfe41c05fac0cba72f8fcad989fb6734009ffe0818e7a3e8ea5f666e9f273ed359f3a602d720c2")]
        [InlineData("SHA384", 1000, 952, "572b0fd3bd01f776b44952add69910bce37d8d3122b6646d831c80bf6d2d1a600984d4429517a1ef9204244874f47540")]
        [InlineData("SHA384", 1000, 476, "572b0fd3bd01f776b44952add69910bce37d8d3122b6646d831c80bf6d2d1a600984d4429517a1ef9204244874f47540")]
        [InlineData("SHA384", 1000, 0, "572b0fd3bd01f776b44952add69910bce37d8d3122b6646d831c80bf6d2d1a600984d4429517a1ef9204244874f47540")]
        [InlineData("SHA256", 1000, 968, "68c320f92016e006f9929312284e3957d4a01ed662067b7ec080276c7919e94a")]
        [InlineData("SHA256", 1000, 484, "68c320f92016e006f9929312284e3957d4a01ed662067b7ec080276c7919e94a")]
        [InlineData("SHA256", 1000, 0, "68c320f92016e006f9929312284e3957d4a01ed662067b7ec080276c7919e94a")]
        [InlineData("SHA1", 1000, 980, "765aa961cc5ed2649c4bc97b784b56fbd2d79e54")]
        [InlineData("SHA1", 1000, 490, "765aa961cc5ed2649c4bc97b784b56fbd2d79e54")]
        [InlineData("SHA1", 1000, 0, "765aa961cc5ed2649c4bc97b784b56fbd2d79e54")]
        [InlineData("MD5", 1000, 984, "cf6ad5682bce634b994bfcda16937432")]
        [InlineData("MD5", 1000, 492, "cf6ad5682bce634b994bfcda16937432")]
        [InlineData("MD5", 1000, 0, "cf6ad5682bce634b994bfcda16937432")]
        public void ExtractSpan_ProducesCorrectPrk_PrkOverlapsIkm(string algorithmName, int ikmLength, int prkOffset, string expectedHexPrk)
        {
            var hashAlgorithmName = new HashAlgorithmName(algorithmName);
            var ikm = new byte[ikmLength];
            var salt = Span<byte>.Empty;
            var expectedPrk = HexConverter.ToBytes(expectedHexPrk);
            var actualPrk = ikm.AsSpan().Slice(prkOffset, expectedPrk.Length);

            Hkdf.Extract(hashAlgorithmName, ikm, salt, actualPrk);

            Assert.Equal(expectedPrk, actualPrk.ToArray());
        }

        [Theory]
        [InlineData("SHA512", 1000, 936, "75241fd960097d308448baa5a2ea0e9d141095792b15a4caf1709e644b4f4edf8b8b2f5e6ad1a97a8c20e09e54d254c570b7a71bc3374c7c3e1d2f1b194e8d14")]
        [InlineData("SHA512", 1000, 468, "75241fd960097d308448baa5a2ea0e9d141095792b15a4caf1709e644b4f4edf8b8b2f5e6ad1a97a8c20e09e54d254c570b7a71bc3374c7c3e1d2f1b194e8d14")]
        [InlineData("SHA512", 1000, 0, "75241fd960097d308448baa5a2ea0e9d141095792b15a4caf1709e644b4f4edf8b8b2f5e6ad1a97a8c20e09e54d254c570b7a71bc3374c7c3e1d2f1b194e8d14")]
        [InlineData("SHA512", 128, 64, "83951a25e3c623acfa94641b2065334f54706fc277d18ec5f84bc09d8c5565182d1afc711fb6b029ae6d21f1716c6b11664c88e471bfc8d3a1408a71d5a638bf")]
        [InlineData("SHA512", 128, 0, "83951a25e3c623acfa94641b2065334f54706fc277d18ec5f84bc09d8c5565182d1afc711fb6b029ae6d21f1716c6b11664c88e471bfc8d3a1408a71d5a638bf")]
        [InlineData("SHA384", 1000, 952, "9692cd60e1d3a9c3461ac43fee45360ccbcabe3ac652c68cec42301dff5feff5d7c29b54b0dfffd60978b59d0e181d78")]
        [InlineData("SHA384", 1000, 476, "9692cd60e1d3a9c3461ac43fee45360ccbcabe3ac652c68cec42301dff5feff5d7c29b54b0dfffd60978b59d0e181d78")]
        [InlineData("SHA384", 1000, 0, "9692cd60e1d3a9c3461ac43fee45360ccbcabe3ac652c68cec42301dff5feff5d7c29b54b0dfffd60978b59d0e181d78")]
        [InlineData("SHA384", 96, 48, "bd1280b85ffc69bd3c2c7da61eec835dfdb0ea7b5644df485269d86e8890b4445935167a96cbbd700776df4a0a8ab991")]
        [InlineData("SHA384", 96, 0, "bd1280b85ffc69bd3c2c7da61eec835dfdb0ea7b5644df485269d86e8890b4445935167a96cbbd700776df4a0a8ab991")]
        [InlineData("SHA256", 1000, 968, "171404a7cb5ec7f11b1201260d34a6d58e3e85e5f161effae959ed5883e13215")]
        [InlineData("SHA256", 1000, 484, "171404a7cb5ec7f11b1201260d34a6d58e3e85e5f161effae959ed5883e13215")]
        [InlineData("SHA256", 1000, 0, "171404a7cb5ec7f11b1201260d34a6d58e3e85e5f161effae959ed5883e13215")]
        [InlineData("SHA256", 64, 32, "2d7d2b3430e6a36fad72c2b870ef283800b1ac043c9d76c0e75489f18a35c22a")]
        [InlineData("SHA256", 64, 0, "2d7d2b3430e6a36fad72c2b870ef283800b1ac043c9d76c0e75489f18a35c22a")]
        [InlineData("SHA1", 1000, 980, "e3d294b14cd100c4944f2ed3510b16d54d32abb0")]
        [InlineData("SHA1", 1000, 490, "e3d294b14cd100c4944f2ed3510b16d54d32abb0")]
        [InlineData("SHA1", 1000, 0, "e3d294b14cd100c4944f2ed3510b16d54d32abb0")]
        [InlineData("SHA1", 40, 20, "0db9b1bf707cbdfa8b8c0a46d89687a48e890d7d")]
        [InlineData("SHA1", 40, 0, "0db9b1bf707cbdfa8b8c0a46d89687a48e890d7d")]
        [InlineData("MD5", 1000, 984, "7a0988af1a9252ac7c2319992be53ab8")]
        [InlineData("MD5", 1000, 492, "7a0988af1a9252ac7c2319992be53ab8")]
        [InlineData("MD5", 1000, 0, "7a0988af1a9252ac7c2319992be53ab8")]
        [InlineData("MD5", 32, 16, "93323d1aaa4e82f5adaf780e1d4568d5")]
        [InlineData("MD5", 32, 0, "93323d1aaa4e82f5adaf780e1d4568d5")]
        public void ExtractSpan_ProducesCorrectPrk_PrkOverlapsSalt(string algorithmName, int saltLength, int prkOffset, string expectedHexPrk)
        {
            var hashAlgorithmName = new HashAlgorithmName(algorithmName);
            var ikm = new byte[128];
            var salt = new byte[saltLength];
            var expectedPrk = HexConverter.ToBytes(expectedHexPrk);
            var actualPrk = salt.AsSpan().Slice(prkOffset, expectedPrk.Length);

            Hkdf.Extract(hashAlgorithmName, ikm, salt, actualPrk);

            Assert.Equal(expectedPrk, actualPrk.ToArray());
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
        [InlineData("SHA512", 1000, 872, "233aa2926c60dd8326551e18d38010036cf6d8af77e74b8784d9215db5888b1ff3cf8aa3e5bf75c0f0e21b924494427e34f6d924b2a013a3f633e1ae0645b6485d8eb023e21bf8fde79323cd5280f29029c7ec4fa7fb30da7d35fb76d25a29ad09817b2e527b1fd78fa3c6a1be9e519b375f72880a78a6c2624b89897c6aa671")]
        [InlineData("SHA512", 1000, 436, "233aa2926c60dd8326551e18d38010036cf6d8af77e74b8784d9215db5888b1ff3cf8aa3e5bf75c0f0e21b924494427e34f6d924b2a013a3f633e1ae0645b6485d8eb023e21bf8fde79323cd5280f29029c7ec4fa7fb30da7d35fb76d25a29ad09817b2e527b1fd78fa3c6a1be9e519b375f72880a78a6c2624b89897c6aa671")]
        [InlineData("SHA512", 1000, 0, "233aa2926c60dd8326551e18d38010036cf6d8af77e74b8784d9215db5888b1ff3cf8aa3e5bf75c0f0e21b924494427e34f6d924b2a013a3f633e1ae0645b6485d8eb023e21bf8fde79323cd5280f29029c7ec4fa7fb30da7d35fb76d25a29ad09817b2e527b1fd78fa3c6a1be9e519b375f72880a78a6c2624b89897c6aa671")]
        [InlineData("SHA512", 128, 0, "3d0527d886733fc5695701b5825e5c6f35367c05edefda335ace96011e89f0767b5d5db160b7906157d7a0b64b3da486c92d0f3794982c54dd85cd3050ac4010859cefb900b26293ca0d939e7fe1d696d86fa422a5fdf8f2c3ec4b0a104b337ebabe4c8787d43dbfb263269c0b2d36a94fc88bdd96370876b99abbe5373b3d5a")]
        [InlineData("SHA384", 1000, 904, "d8c9a8b1c3f6ec7b05b3f3e883bc70420a2e2c9150a35d71a792ec058f83b0b7c5f9500db7de3001a622ab18c779d90b1e4f2c324cc2c86bd2d5187faeab95e105ce910b01f9b88baf8a95739bb9101956f441d6e6e99c5305cdae73f61c1272")]
        [InlineData("SHA384", 1000, 452, "d8c9a8b1c3f6ec7b05b3f3e883bc70420a2e2c9150a35d71a792ec058f83b0b7c5f9500db7de3001a622ab18c779d90b1e4f2c324cc2c86bd2d5187faeab95e105ce910b01f9b88baf8a95739bb9101956f441d6e6e99c5305cdae73f61c1272")]
        [InlineData("SHA384", 1000, 0, "d8c9a8b1c3f6ec7b05b3f3e883bc70420a2e2c9150a35d71a792ec058f83b0b7c5f9500db7de3001a622ab18c779d90b1e4f2c324cc2c86bd2d5187faeab95e105ce910b01f9b88baf8a95739bb9101956f441d6e6e99c5305cdae73f61c1272")]
        [InlineData("SHA384", 96, 0, "874058a2c04982c953e4a5bb4fa30fb61226cf5b2fa5601741e976752a02ddb8d9138c88268fe153f39cebe70790257bcf2b36e2195e13729c0e33117f2d0109e2f79520cb50e9faf880a6cc18221be0b8661d9f46b6b9f513440cb5284ab15d")]
        [InlineData("SHA256", 1000, 936, "a4e19cd6b1a0281771aed7ff35826b4c7a9af9cbf9a66d0083327fef7ec0e55dbe023173b442deabe8f4cff6d989508a4b27c4900f0ba162ea95abdfc126beb0")]
        [InlineData("SHA256", 1000, 468, "a4e19cd6b1a0281771aed7ff35826b4c7a9af9cbf9a66d0083327fef7ec0e55dbe023173b442deabe8f4cff6d989508a4b27c4900f0ba162ea95abdfc126beb0")]
        [InlineData("SHA256", 1000, 0, "a4e19cd6b1a0281771aed7ff35826b4c7a9af9cbf9a66d0083327fef7ec0e55dbe023173b442deabe8f4cff6d989508a4b27c4900f0ba162ea95abdfc126beb0")]
        [InlineData("SHA256", 64, 0, "3d7afb663124ecbf2c953f863d4fc8796eeb2d372b64aad58697ec5264649cdb8eb20d0e5acf7134b680fd516e14798b43533b5a5d1b99b38d743eb401907405")]
        [InlineData("SHA1", 1000, 960, "96faa667f98be760894b098da7de64943172a8020aab433f587673d0f07efd0a78abda9eddaad13d")]
        [InlineData("SHA1", 1000, 480, "96faa667f98be760894b098da7de64943172a8020aab433f587673d0f07efd0a78abda9eddaad13d")]
        [InlineData("SHA1", 1000, 0, "96faa667f98be760894b098da7de64943172a8020aab433f587673d0f07efd0a78abda9eddaad13d")]
        [InlineData("SHA1", 40, 0, "6564ed6529528df3c40278b3ccd84cc59b6e9ccc41a4651921dfc404ad2df89a789f322c41981e1e")]
        [InlineData("MD5", 1000, 968, "34e0deefbf49f5c22aab393a68263a8299e5e030d30cc1e0a9d652697c02dff8")]
        [InlineData("MD5", 1000, 484, "34e0deefbf49f5c22aab393a68263a8299e5e030d30cc1e0a9d652697c02dff8")]
        [InlineData("MD5", 1000, 0, "34e0deefbf49f5c22aab393a68263a8299e5e030d30cc1e0a9d652697c02dff8")]
        [InlineData("MD5", 32, 0, "b41153dc48510aeee089ee50d9574434d74d7b3febe99cc7d6cdc56135820b8b")]
        public void ExpandSpan_ProducesCorrectOkm_OkmOverlapsPrk(string algorithmName, int prkLength, int okmOffset, string expectedHexOkm)
        {
            var hashAlgorithmName = new HashAlgorithmName(algorithmName);
            var prk = new byte[prkLength];
            var info = Span<byte>.Empty;
            var expectedOkm = HexConverter.ToBytes(expectedHexOkm);
            var actualOkm = prk.AsSpan().Slice(okmOffset, expectedOkm.Length);

            Hkdf.Expand(hashAlgorithmName, prk, actualOkm, info);

            Assert.Equal(expectedOkm, actualOkm.ToArray());
        }

        [Theory]
        [InlineData("SHA512", 1000, 808, "2ca73aeead00e33a4380babbddc6349e5aaecf1ebf290cc95bcf29159d1fce1c2143e6e25bbc39792ce8bd3d5ff8ab8e67b633e0d9edcd611ef5afa85539794eddd85ce1d34a2ec699af3b25870b4796d6b635584d58887df8c2a1aa04e38ada406a86a9de3a82dde8882ad15b88a2daff3a3b08e95780275fff9219a4060667cb93a3592e7e3d6ce5778de8b194de9d38385204c0451a586a461f96d3ad41c4b46c630fbc2547c7213749ce419110e45a34613f8052768acdef6ae1ceadebd8")]
        [InlineData("SHA512", 1000, 404, "2ca73aeead00e33a4380babbddc6349e5aaecf1ebf290cc95bcf29159d1fce1c2143e6e25bbc39792ce8bd3d5ff8ab8e67b633e0d9edcd611ef5afa85539794eddd85ce1d34a2ec699af3b25870b4796d6b635584d58887df8c2a1aa04e38ada406a86a9de3a82dde8882ad15b88a2daff3a3b08e95780275fff9219a4060667cb93a3592e7e3d6ce5778de8b194de9d38385204c0451a586a461f96d3ad41c4b46c630fbc2547c7213749ce419110e45a34613f8052768acdef6ae1ceadebd8")]
        [InlineData("SHA512", 1000, 0, "2ca73aeead00e33a4380babbddc6349e5aaecf1ebf290cc95bcf29159d1fce1c2143e6e25bbc39792ce8bd3d5ff8ab8e67b633e0d9edcd611ef5afa85539794eddd85ce1d34a2ec699af3b25870b4796d6b635584d58887df8c2a1aa04e38ada406a86a9de3a82dde8882ad15b88a2daff3a3b08e95780275fff9219a4060667cb93a3592e7e3d6ce5778de8b194de9d38385204c0451a586a461f96d3ad41c4b46c630fbc2547c7213749ce419110e45a34613f8052768acdef6ae1ceadebd8")]
        [InlineData("SHA512", 192, 0, "8e0c7062b00409f2ce5210c3f71cc49b1b80439d2f45e0070e4cfe69daff898a139a204f1ac0095025f8144f908c3c0806b334279281573d3f9decdc9b894dec5ef1a55ce3ddb140bb44ad1a27983cb443d1eab7e61c84793b7dddb8ad649a01972ea8820905d9c671f4c48567f8be2f7cb2699c9f5427fede9c117a1cdca9592cf0da878b0bc4e5addf4ffcba5195a8c8b4404a0fea4442cd71327841b6935ca7563e23b28b322784c171746529f32ae0f8318012bd6b0e8da6f3235a069418")]
        [InlineData("SHA384", 1000, 856, "72b2780b829f3303f0b84fbcf0b52d74e91f3df4ccd6bfb3aa9f19fee4b234abf19fadc3dc81ed81c5c6421449c1d11c983b8ef100534ed3729bc5a6168238fd8c5f1a58cdbc0b8495694bea494f49172d0d488176a7378a5e8162131f5b8e9de2f01ab6eeaac41f0fd08cd6311629a3696d91f56e5b86bc09c319c638354ea9ddc327a3c8b71b8d792368fc7327baba")]
        [InlineData("SHA384", 1000, 428, "72b2780b829f3303f0b84fbcf0b52d74e91f3df4ccd6bfb3aa9f19fee4b234abf19fadc3dc81ed81c5c6421449c1d11c983b8ef100534ed3729bc5a6168238fd8c5f1a58cdbc0b8495694bea494f49172d0d488176a7378a5e8162131f5b8e9de2f01ab6eeaac41f0fd08cd6311629a3696d91f56e5b86bc09c319c638354ea9ddc327a3c8b71b8d792368fc7327baba")]
        [InlineData("SHA384", 1000, 0, "72b2780b829f3303f0b84fbcf0b52d74e91f3df4ccd6bfb3aa9f19fee4b234abf19fadc3dc81ed81c5c6421449c1d11c983b8ef100534ed3729bc5a6168238fd8c5f1a58cdbc0b8495694bea494f49172d0d488176a7378a5e8162131f5b8e9de2f01ab6eeaac41f0fd08cd6311629a3696d91f56e5b86bc09c319c638354ea9ddc327a3c8b71b8d792368fc7327baba")]
        [InlineData("SHA384", 144, 0, "7112c428878135ddd823b446a3ba0817d412fa3a98a8c730ae3e317f753e88856837d2d623ffbb6609b3eb7d17152b4bd21218a0e52d2c68df9a4487fd51c0e04f62c5e061d7b68bab1250713d863a934ca61788e4885eec2ae2c26c8e49c07f004f0da17e26011cbe3fa8c7a46af52957472e99153a0e84fbee15745b2eb97f99cfb5d74622d7869f1a2e710b286696")]
        [InlineData("SHA256", 1000, 904, "d80800c1916dbbeb96b4c514e4c535df3ee814f06b88ae8c2432409c1550fa0f01fd402f7e7159cca01ddf8cb9a814d3fd9bdf1e2930b67cc257a331a4f1f79e895f92707c562bf4259a7a47719e32becd114dfb9f1859f8022c98e5d5da2a11")]
        [InlineData("SHA256", 1000, 452, "d80800c1916dbbeb96b4c514e4c535df3ee814f06b88ae8c2432409c1550fa0f01fd402f7e7159cca01ddf8cb9a814d3fd9bdf1e2930b67cc257a331a4f1f79e895f92707c562bf4259a7a47719e32becd114dfb9f1859f8022c98e5d5da2a11")]
        [InlineData("SHA256", 1000, 0, "d80800c1916dbbeb96b4c514e4c535df3ee814f06b88ae8c2432409c1550fa0f01fd402f7e7159cca01ddf8cb9a814d3fd9bdf1e2930b67cc257a331a4f1f79e895f92707c562bf4259a7a47719e32becd114dfb9f1859f8022c98e5d5da2a11")]
        [InlineData("SHA256", 96, 0, "cf096833ac1155c002c136576eef1ef10f44cba48d6163ad548a91fc43fca5805a51d0d546ba981ec4226d969c6b9bb1149795190f33397a20dca85508d9dc58ea260eaa2785f2087f6fa251a19dcaa679c367d18f69dcc270c812147b40d1aa")]
        [InlineData("SHA1", 1000, 940, "c004c54954e6b222949545fee672a5cb2655062474cd6c40beffc7dd49235374d044d3588c780c2923fd77a203295c451298b02ce44a804c712500f4")]
        [InlineData("SHA1", 1000, 470, "c004c54954e6b222949545fee672a5cb2655062474cd6c40beffc7dd49235374d044d3588c780c2923fd77a203295c451298b02ce44a804c712500f4")]
        [InlineData("SHA1", 1000, 0, "c004c54954e6b222949545fee672a5cb2655062474cd6c40beffc7dd49235374d044d3588c780c2923fd77a203295c451298b02ce44a804c712500f4")]
        [InlineData("SHA1", 60, 0, "b8ea57552fc7ee253ec3c998c58388f48f21f224e04b13fbf61ef2bbe60ef367b9cb286bdb8aa048649a235fe6386a3c84e393f07468a47c4f3537d8")]
        [InlineData("MD5", 1000, 952, "5cf6323d40ac281f373d407ace086b34749e53f232c9328a6864f23efa3b6219f42e1b9f000b4adf541a5707a545d63c")]
        [InlineData("MD5", 1000, 476, "5cf6323d40ac281f373d407ace086b34749e53f232c9328a6864f23efa3b6219f42e1b9f000b4adf541a5707a545d63c")]
        [InlineData("MD5", 1000, 0, "5cf6323d40ac281f373d407ace086b34749e53f232c9328a6864f23efa3b6219f42e1b9f000b4adf541a5707a545d63c")]
        [InlineData("MD5", 48, 0, "53368be9038e6d443cc16ad23939c6fcb6377a66c61162b87e367b3fe6d1885a04045c353cc837e3bcfd3125c67ca8fc")]
        public void ExpandSpan_ProducesCorrectOkm_OkmOverlapsInfo(string algorithmName, int infoLength, int okmOffset, string expectedHexOkm)
        {
            var hashAlgorithmName = new HashAlgorithmName(algorithmName);
            var prk = new byte[128];
            var info = new byte[infoLength];
            var expectedOkm = HexConverter.ToBytes(expectedHexOkm);
            var actualOkm = info.AsSpan().Slice(okmOffset, expectedOkm.Length);

            Hkdf.Expand(hashAlgorithmName, prk, actualOkm, info);

            Assert.Equal(expectedOkm, actualOkm.ToArray());
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
        [InlineData("SHA512", 1000, 808, "46ad17ecce257742c044ea7521ad18154ba3cbbb5fa5633714b31102f3e7c1f6d5b2d73037a6005d8641337c893f76fb8d1b3c2d8b875b236048efa0b0fee2ab2e11b23095578491360e0b0ceec584390651f849aa6d81e23f101e1f4d48251f6effc3a41b549c66aa9f2dbc53b331fd1fa86f3d69e507390dd451ae0d38509ce1de2e2d84b6e3e8e14ba98f9c42976ec191694c4336ac35043852d442b87341648dfcb7641f82b22dfacda131f12d4755311735b0985a88de57594afb32a8ef")]
        [InlineData("SHA512", 1000, 404, "46ad17ecce257742c044ea7521ad18154ba3cbbb5fa5633714b31102f3e7c1f6d5b2d73037a6005d8641337c893f76fb8d1b3c2d8b875b236048efa0b0fee2ab2e11b23095578491360e0b0ceec584390651f849aa6d81e23f101e1f4d48251f6effc3a41b549c66aa9f2dbc53b331fd1fa86f3d69e507390dd451ae0d38509ce1de2e2d84b6e3e8e14ba98f9c42976ec191694c4336ac35043852d442b87341648dfcb7641f82b22dfacda131f12d4755311735b0985a88de57594afb32a8ef")]
        [InlineData("SHA512", 1000, 0, "46ad17ecce257742c044ea7521ad18154ba3cbbb5fa5633714b31102f3e7c1f6d5b2d73037a6005d8641337c893f76fb8d1b3c2d8b875b236048efa0b0fee2ab2e11b23095578491360e0b0ceec584390651f849aa6d81e23f101e1f4d48251f6effc3a41b549c66aa9f2dbc53b331fd1fa86f3d69e507390dd451ae0d38509ce1de2e2d84b6e3e8e14ba98f9c42976ec191694c4336ac35043852d442b87341648dfcb7641f82b22dfacda131f12d4755311735b0985a88de57594afb32a8ef")]
        [InlineData("SHA384", 1000, 856, "07c477a668dbc6fa0670eb26b9b7942a304be2cbc7b036298f655b27edfad8d3eda201fd5ec1bd6a6e39d249f213ab94a94dbf4513430c8dfc0726f1a874ea8c6dea2e6ee7cd73a4f20f75aa2529f0b5964faefe2ee2625c535680363f8e5781b79411ab5d1a8691ac2773e17c61c20fc57f9befd7f5335797fe0d3be30eb8f993f7a73899ea57d5cde75887f4151e77")]
        [InlineData("SHA384", 1000, 428, "07c477a668dbc6fa0670eb26b9b7942a304be2cbc7b036298f655b27edfad8d3eda201fd5ec1bd6a6e39d249f213ab94a94dbf4513430c8dfc0726f1a874ea8c6dea2e6ee7cd73a4f20f75aa2529f0b5964faefe2ee2625c535680363f8e5781b79411ab5d1a8691ac2773e17c61c20fc57f9befd7f5335797fe0d3be30eb8f993f7a73899ea57d5cde75887f4151e77")]
        [InlineData("SHA384", 1000, 0, "07c477a668dbc6fa0670eb26b9b7942a304be2cbc7b036298f655b27edfad8d3eda201fd5ec1bd6a6e39d249f213ab94a94dbf4513430c8dfc0726f1a874ea8c6dea2e6ee7cd73a4f20f75aa2529f0b5964faefe2ee2625c535680363f8e5781b79411ab5d1a8691ac2773e17c61c20fc57f9befd7f5335797fe0d3be30eb8f993f7a73899ea57d5cde75887f4151e77")]
        [InlineData("SHA256", 1000, 904, "9777e27eb2856914d509698f7535580a908b062acf25fae958ce71e1ad19a2d10847fcfadc008ce384eb70f4071281dbf4b8978873c6ab83dfd7711003403f5abba7272f4357f0d9c4a8ef1f6dd7736600fbd5597eb577ae2097f344da709558")]
        [InlineData("SHA256", 1000, 452, "9777e27eb2856914d509698f7535580a908b062acf25fae958ce71e1ad19a2d10847fcfadc008ce384eb70f4071281dbf4b8978873c6ab83dfd7711003403f5abba7272f4357f0d9c4a8ef1f6dd7736600fbd5597eb577ae2097f344da709558")]
        [InlineData("SHA256", 1000, 0, "9777e27eb2856914d509698f7535580a908b062acf25fae958ce71e1ad19a2d10847fcfadc008ce384eb70f4071281dbf4b8978873c6ab83dfd7711003403f5abba7272f4357f0d9c4a8ef1f6dd7736600fbd5597eb577ae2097f344da709558")]
        [InlineData("SHA1", 1000, 940, "0990f5537e97026e982a6d6976bf3a6130566c5cdeaf0264ceea25febcebf362ecfdefee58bbd3332b4447c594016f5768cc1b1d296c5948a644cac5")]
        [InlineData("SHA1", 1000, 470, "0990f5537e97026e982a6d6976bf3a6130566c5cdeaf0264ceea25febcebf362ecfdefee58bbd3332b4447c594016f5768cc1b1d296c5948a644cac5")]
        [InlineData("SHA1", 1000, 0, "0990f5537e97026e982a6d6976bf3a6130566c5cdeaf0264ceea25febcebf362ecfdefee58bbd3332b4447c594016f5768cc1b1d296c5948a644cac5")]
        [InlineData("MD5", 1000, 952, "8bf5fc5ca32a8d3dab04fad0e02dae61b33d99bb7abf70d653bb1e12a25a3ab3b65b8fa3f3c419083fdb6d25766e0f12")]
        [InlineData("MD5", 1000, 476, "8bf5fc5ca32a8d3dab04fad0e02dae61b33d99bb7abf70d653bb1e12a25a3ab3b65b8fa3f3c419083fdb6d25766e0f12")]
        [InlineData("MD5", 1000, 0, "8bf5fc5ca32a8d3dab04fad0e02dae61b33d99bb7abf70d653bb1e12a25a3ab3b65b8fa3f3c419083fdb6d25766e0f12")]
        public void DeriveKeySpan_ProducesCorrectOkm_OkmOverlapsIkm(string algorithmName, int ikmLength, int okmOffset, string expectedHexOkm)
        {
            var hashAlgorithmName = new HashAlgorithmName(algorithmName);
            var ikm = new byte[ikmLength];
            var salt = Span<byte>.Empty;
            var info = Span<byte>.Empty;
            var expectedOkm = HexConverter.ToBytes(expectedHexOkm);
            var actualOkm = ikm.AsSpan().Slice(okmOffset, expectedOkm.Length);

            Hkdf.DeriveKey(hashAlgorithmName, ikm, actualOkm, salt, info);

            Assert.Equal(expectedOkm, actualOkm.ToArray());
        }

        [Theory]
        [InlineData("SHA512", 1000, 808, "43f28359b80cd62f0d68f8ed2bca64d42a5572a23915e49839f78f033f9a968640536b9c24eee81810511a3e9b84c1e27603747b08f9d47c5b5540b853e5976dc11f5eb92a562a6b36d909934c9dddf2ff91173484ea69fe62106f63fa23799e93f9912ab25f1477f44a715dbb0fcc1baeb9f630d4825500e3fe6c50b8c3034551eb1d60c7331749a3b04c2ef59ccd05237bee807f0be533eb36828105c500e4294586f15bfa6f0ff40f706e50c3e31b6c56aacddd6c80febda5146e48a5918d")]
        [InlineData("SHA512", 1000, 404, "43f28359b80cd62f0d68f8ed2bca64d42a5572a23915e49839f78f033f9a968640536b9c24eee81810511a3e9b84c1e27603747b08f9d47c5b5540b853e5976dc11f5eb92a562a6b36d909934c9dddf2ff91173484ea69fe62106f63fa23799e93f9912ab25f1477f44a715dbb0fcc1baeb9f630d4825500e3fe6c50b8c3034551eb1d60c7331749a3b04c2ef59ccd05237bee807f0be533eb36828105c500e4294586f15bfa6f0ff40f706e50c3e31b6c56aacddd6c80febda5146e48a5918d")]
        [InlineData("SHA512", 1000, 0, "43f28359b80cd62f0d68f8ed2bca64d42a5572a23915e49839f78f033f9a968640536b9c24eee81810511a3e9b84c1e27603747b08f9d47c5b5540b853e5976dc11f5eb92a562a6b36d909934c9dddf2ff91173484ea69fe62106f63fa23799e93f9912ab25f1477f44a715dbb0fcc1baeb9f630d4825500e3fe6c50b8c3034551eb1d60c7331749a3b04c2ef59ccd05237bee807f0be533eb36828105c500e4294586f15bfa6f0ff40f706e50c3e31b6c56aacddd6c80febda5146e48a5918d")]
        [InlineData("SHA512", 128, 0, "9b90096889d7e1327b2962e5b0dc9b6a92ed4f0be3604ba50333aa5bf8d9de4f164bb6fd4b8ac1fc607180b6e40b090f9d8b59b96e485dae9c98f3bac44cd2df59f81557c3bf5c02294d820d6ac883a94253d6aea4fbb8a71008ca68fb70d93ad8073e22eb9d43475d76640b5502d268ac8f62a4a177c17ff26377969911d458")]
        [InlineData("SHA384", 1000, 856, "ec4fff6fff132bbcfe4dc8708510b5d78bab694e834f635d081ce391626bfa55128501836eb60fe3ac5d5511903d59d1c8186c081ae498b82195ba52b8bd7a3f28c3d21a8894d919e0e80bfef9ac477e2b3bec9977e3198fe5a1a016eef178eeb3595fd663612bbe76f80a14ae5aec808ff605b868f2459e857e425ead970a440d2b567696cb074af2feebb586a875ea")]
        [InlineData("SHA384", 1000, 428, "ec4fff6fff132bbcfe4dc8708510b5d78bab694e834f635d081ce391626bfa55128501836eb60fe3ac5d5511903d59d1c8186c081ae498b82195ba52b8bd7a3f28c3d21a8894d919e0e80bfef9ac477e2b3bec9977e3198fe5a1a016eef178eeb3595fd663612bbe76f80a14ae5aec808ff605b868f2459e857e425ead970a440d2b567696cb074af2feebb586a875ea")]
        [InlineData("SHA384", 1000, 0, "ec4fff6fff132bbcfe4dc8708510b5d78bab694e834f635d081ce391626bfa55128501836eb60fe3ac5d5511903d59d1c8186c081ae498b82195ba52b8bd7a3f28c3d21a8894d919e0e80bfef9ac477e2b3bec9977e3198fe5a1a016eef178eeb3595fd663612bbe76f80a14ae5aec808ff605b868f2459e857e425ead970a440d2b567696cb074af2feebb586a875ea")]
        [InlineData("SHA384", 96, 0, "bb863f9b0619a7f96758eb0667bcc3fd18e780399025edb724caf1abf4de8b18088faca37680be96a9469e412f2a54e0f81caf76c778f11acccb393ec13beb33c0fdc27ad1697299a2b86bc0d104a1a079672fe2ae11a2a6ea8f29fa7cc4471d")]
        [InlineData("SHA256", 1000, 904, "37fd86187ca2a92ff0cdfb3021ebc3f05557238d0af04942e092b22fb462bb3ea14db0f9dc035adc986b5996c611be85a97d7a523ca3531aa2cd7b00a4a30cb7691a9075ef20f2d759786bd324ecba6ed44151a278c39c8fd9d9d94f855d35e0")]
        [InlineData("SHA256", 1000, 452, "37fd86187ca2a92ff0cdfb3021ebc3f05557238d0af04942e092b22fb462bb3ea14db0f9dc035adc986b5996c611be85a97d7a523ca3531aa2cd7b00a4a30cb7691a9075ef20f2d759786bd324ecba6ed44151a278c39c8fd9d9d94f855d35e0")]
        [InlineData("SHA256", 1000, 0, "37fd86187ca2a92ff0cdfb3021ebc3f05557238d0af04942e092b22fb462bb3ea14db0f9dc035adc986b5996c611be85a97d7a523ca3531aa2cd7b00a4a30cb7691a9075ef20f2d759786bd324ecba6ed44151a278c39c8fd9d9d94f855d35e0")]
        [InlineData("SHA256", 64, 0, "7e44ff7889f5f157d43c93904cf7e7fa239c4e2fb974f98210d849cc4851fbe56e37aa245d1eabde7c55a6a3e98b9cea80cf3e458bfb938d2f48735dea1a27f3")]
        [InlineData("SHA1", 1000, 940, "9f05d70a4242086d4b712dd7f9ac38e1ea9ed7bf7954669bd3ec16ae043a5f0adcd534d6edc52ca457f2cf266dda94280272ec24bbb6f9ccca301dc2")]
        [InlineData("SHA1", 1000, 470, "9f05d70a4242086d4b712dd7f9ac38e1ea9ed7bf7954669bd3ec16ae043a5f0adcd534d6edc52ca457f2cf266dda94280272ec24bbb6f9ccca301dc2")]
        [InlineData("SHA1", 1000, 0, "9f05d70a4242086d4b712dd7f9ac38e1ea9ed7bf7954669bd3ec16ae043a5f0adcd534d6edc52ca457f2cf266dda94280272ec24bbb6f9ccca301dc2")]
        [InlineData("SHA1", 40, 0, "78d2bf8b5a6b9288efb7bc5f482b8294b241ef2cae59b5e1260138810ac2f6b974331fb620cd6e7c")]
        [InlineData("MD5", 1000, 952, "bd64f0d4a852b0525290769147fbc71dd37ef720de1c470ac8e8ebe2d8fe4ddac177d08b94c96bf08ede531436d5eb31")]
        [InlineData("MD5", 1000, 476, "bd64f0d4a852b0525290769147fbc71dd37ef720de1c470ac8e8ebe2d8fe4ddac177d08b94c96bf08ede531436d5eb31")]
        [InlineData("MD5", 1000, 0, "bd64f0d4a852b0525290769147fbc71dd37ef720de1c470ac8e8ebe2d8fe4ddac177d08b94c96bf08ede531436d5eb31")]
        [InlineData("MD5", 32, 0, "a244d79b29f0f6ecfd5a3cb1724a148f9d4d885db3977987c44976e8ef77865b")]
        public void DeriveKeySpan_ProducesCorrectOkm_OkmOverlapsSalt(string algorithmName, int saltLength, int okmOffset, string expectedHexOkm)
        {
            var hashAlgorithmName = new HashAlgorithmName(algorithmName);
            var ikm = new byte[128];
            var salt = new byte[saltLength];
            var info = Span<byte>.Empty;
            var expectedOkm = HexConverter.ToBytes(expectedHexOkm);
            var actualOkm = salt.AsSpan().Slice(okmOffset, expectedOkm.Length);

            Hkdf.DeriveKey(hashAlgorithmName, ikm, actualOkm, salt, info);

            Assert.Equal(expectedOkm, actualOkm.ToArray());
        }

        [Theory]
        [InlineData("SHA512", 1000, 808, "b0083b02b49890b5652ff036d279dfbdcd1019734eff6e01d5c40be76cba4bd787a6ecc83edf55477d9139e876b61115cc648119195e1289968d69f49c3ba23d8fdc1636bb607a7bc6063f105009159fd8688b29819b8b577aacadcd18962da2449723f77c54505dfafbfaedab7ac814d132f73b450008fe83bef0bc682bd0e8eb44b1791cf88ac0e52845f82622e9b95a81c32fba4a63f0f6bd58443616771de3e17b2021eb4ebf28a0d496e045da0a5f81dad2d581bc3bc540aaa95b83e68f")]
        [InlineData("SHA512", 1000, 404, "b0083b02b49890b5652ff036d279dfbdcd1019734eff6e01d5c40be76cba4bd787a6ecc83edf55477d9139e876b61115cc648119195e1289968d69f49c3ba23d8fdc1636bb607a7bc6063f105009159fd8688b29819b8b577aacadcd18962da2449723f77c54505dfafbfaedab7ac814d132f73b450008fe83bef0bc682bd0e8eb44b1791cf88ac0e52845f82622e9b95a81c32fba4a63f0f6bd58443616771de3e17b2021eb4ebf28a0d496e045da0a5f81dad2d581bc3bc540aaa95b83e68f")]
        [InlineData("SHA512", 1000, 0, "b0083b02b49890b5652ff036d279dfbdcd1019734eff6e01d5c40be76cba4bd787a6ecc83edf55477d9139e876b61115cc648119195e1289968d69f49c3ba23d8fdc1636bb607a7bc6063f105009159fd8688b29819b8b577aacadcd18962da2449723f77c54505dfafbfaedab7ac814d132f73b450008fe83bef0bc682bd0e8eb44b1791cf88ac0e52845f82622e9b95a81c32fba4a63f0f6bd58443616771de3e17b2021eb4ebf28a0d496e045da0a5f81dad2d581bc3bc540aaa95b83e68f")]
        [InlineData("SHA512", 192, 0, "8d9d9cf03b4f49e0b9dc03685ddfee46ccc9fa4d405edc797fc0896b29bebc2768b917969128a0f22b7ca5bb94eb572c363bcac0b48067b84cd997edaae3b339c0f556f43b867330312694fc8bad1536468aac1f3c7d4588979b42aec81495265e3c929b653338bbb8b6f1177ee787ae964add9a60322181f1cf4fc84555b390c258de6b255b40a0951dcb991336261132dca9682f041e3251608d3796673d10329192b30937e28a84a4999580525c20b80fb7a22abca271e8d7d565b99b76b0")]
        [InlineData("SHA384", 1000, 856, "6ca35c05487c5c7a6f9a8f3ea17de0c5ff0eb2bf89afb84010b9653cb0b8a331d27934e1fcdfd35b08ace9e3d3ded9d930f450d63ced797032227f8ae732042db797e359fe6e9723ea9a0e3b49febea280895008971d59338ce1d33160b1812045af8f0e624e71f66a0716ed9c8b203575cb38d76566400292b7ca205ac32942fc1573ec258290bf376996f0b998a039")]
        [InlineData("SHA384", 1000, 428, "6ca35c05487c5c7a6f9a8f3ea17de0c5ff0eb2bf89afb84010b9653cb0b8a331d27934e1fcdfd35b08ace9e3d3ded9d930f450d63ced797032227f8ae732042db797e359fe6e9723ea9a0e3b49febea280895008971d59338ce1d33160b1812045af8f0e624e71f66a0716ed9c8b203575cb38d76566400292b7ca205ac32942fc1573ec258290bf376996f0b998a039")]
        [InlineData("SHA384", 1000, 0, "6ca35c05487c5c7a6f9a8f3ea17de0c5ff0eb2bf89afb84010b9653cb0b8a331d27934e1fcdfd35b08ace9e3d3ded9d930f450d63ced797032227f8ae732042db797e359fe6e9723ea9a0e3b49febea280895008971d59338ce1d33160b1812045af8f0e624e71f66a0716ed9c8b203575cb38d76566400292b7ca205ac32942fc1573ec258290bf376996f0b998a039")]
        [InlineData("SHA384", 144, 0, "ba09d15242a36a6f49b19271c83cdf68b1f8968bf0cc8a82dbf48d81afeb3ba8c5655389a00683b88d123d5b61f1bb28c29deebbb6e4b834a9e97e127359699678b21576ea10c143d78df7ed6b655a666940019fd9bc62572d99f696701c330bb7f8b58a8fe02762bee77e63d58a7a195292ff0fe6e1ea92d7cd64f839aed8f600519d542ed27d9d195ecf043f37abff")]
        [InlineData("SHA256", 1000, 904, "146b56d4c93855f18a45d0e1091f811c358a975040258e64914701dc1f966d4209f947c7102308688d82e3590ea917edc38862ace036bb501e3853811bef05c270e771791daa73f09c09793de9b6ddaf2f45d7f3fce481d6543d6a06435e5b12")]
        [InlineData("SHA256", 1000, 452, "146b56d4c93855f18a45d0e1091f811c358a975040258e64914701dc1f966d4209f947c7102308688d82e3590ea917edc38862ace036bb501e3853811bef05c270e771791daa73f09c09793de9b6ddaf2f45d7f3fce481d6543d6a06435e5b12")]
        [InlineData("SHA256", 1000, 0, "146b56d4c93855f18a45d0e1091f811c358a975040258e64914701dc1f966d4209f947c7102308688d82e3590ea917edc38862ace036bb501e3853811bef05c270e771791daa73f09c09793de9b6ddaf2f45d7f3fce481d6543d6a06435e5b12")]
        [InlineData("SHA256", 96, 0, "f3e54edeed0f2b741924c033fbeed562c5539be13231ddcfcfeebff664e2399c6ba91a04b575ddcd09d343de7892d16a42ef4b04c57300bce548c8afccbe9777a44ce7072bdc2e78b9917d7dc2f42c47e2f74d79e474d8324273c5b74a2105bd")]
        [InlineData("SHA1", 1000, 940, "ee08bc63ba0697f0a2e054a6e82a99065fdac5958fa673ae65a37b8c6f0bdda09bb178bbbcb2402d43785a4c17dff1372b1592d919fb76a6abbcc7c6")]
        [InlineData("SHA1", 1000, 470, "ee08bc63ba0697f0a2e054a6e82a99065fdac5958fa673ae65a37b8c6f0bdda09bb178bbbcb2402d43785a4c17dff1372b1592d919fb76a6abbcc7c6")]
        [InlineData("SHA1", 1000, 0, "ee08bc63ba0697f0a2e054a6e82a99065fdac5958fa673ae65a37b8c6f0bdda09bb178bbbcb2402d43785a4c17dff1372b1592d919fb76a6abbcc7c6")]
        [InlineData("SHA1", 60, 0, "e75e81c92c45f66722a32fcaf5dc6a2a0dc23d7132b54519e578caefb2f1db85204bc627f04bf65fd9091f0c5e20bc7e86b43bbe372f0d6ec64b277c")]
        [InlineData("MD5", 1000, 952, "05889ef0ad4706a73dca10a25a64490675c141facdca1d58d6f4e5b09add2dcd88b85a4c5f4296d9e1ad60e3ba82b825")]
        [InlineData("MD5", 1000, 476, "05889ef0ad4706a73dca10a25a64490675c141facdca1d58d6f4e5b09add2dcd88b85a4c5f4296d9e1ad60e3ba82b825")]
        [InlineData("MD5", 1000, 0, "05889ef0ad4706a73dca10a25a64490675c141facdca1d58d6f4e5b09add2dcd88b85a4c5f4296d9e1ad60e3ba82b825")]
        [InlineData("MD5", 48, 0, "7b8f100cc7a5cecd3c395883c69298349e03f659adf7afe59168894bbe3bacafe6a9755dd99be7eb03c80154172683ea")]
        public void DeriveKeySpan_ProducesCorrectOkm_OkmOverlapsInfo(string algorithmName, int infoLength, int okmOffset, string expectedHexOkm)
        {
            var hashAlgorithmName = new HashAlgorithmName(algorithmName);
            var ikm = new byte[128];
            var salt = Span<byte>.Empty;
            var info = new byte[infoLength];
            var expectedOkm = HexConverter.ToBytes(expectedHexOkm);
            var actualOkm = info.AsSpan().Slice(okmOffset, expectedOkm.Length);

            Hkdf.DeriveKey(hashAlgorithmName, ikm, actualOkm, salt, info);

            Assert.Equal(expectedOkm, actualOkm.ToArray());
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
