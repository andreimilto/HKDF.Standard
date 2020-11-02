using System;
using System.Globalization;

namespace HkdfStandard.Test.HkdfTestAux
{
    internal static class HexConverter
    {
        internal static byte[] ToBytes(string hexString)
        {
            if (hexString == null)
                throw new ArgumentNullException(nameof(hexString));
            if (hexString.Length % 2 != 0)
                throw new FormatException("Invalid hexadecimal string: the length is not a multiple of 2.");
            
            byte[] result = new byte[hexString.Length / 2];
            var hexSpan = hexString.AsSpan();
            for (int i = 0; i < result.Length; i++)
            {
                int offset = i * 2;
                if (!byte.TryParse(hexSpan.Slice(offset, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out byte currentByte))
                    throw new FormatException($"Invalid character at position {offset}-{offset + 1}.");
                result[i] = currentByte;
            }

            return result;
        }
    }
}
