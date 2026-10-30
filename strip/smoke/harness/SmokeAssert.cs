using System;
using System.Text;

namespace TurboSmoke
{
    /// <summary>A failed row check; the runner prints its message without a type prefix.</summary>
    public sealed class SmokeCheckException : Exception
    {
        public SmokeCheckException(string message)
            : base(message)
        {
        }
    }

    /// <summary>Minimal asserts for rows (no test framework in the harness).</summary>
    public static class SmokeAssert
    {
        public static void True(bool condition, string what)
        {
            if (!condition)
            {
                throw new SmokeCheckException(what);
            }
        }

        public static void Equal(string expected, string actual, string what)
        {
            if (!string.Equals(expected, actual, StringComparison.Ordinal))
            {
                throw new SmokeCheckException(what + ": expected '" + expected + "', got '" + actual + "'");
            }
        }

        public static void Equal(int expected, int actual, string what)
        {
            if (expected != actual)
            {
                throw new SmokeCheckException(what + ": expected " + expected + ", got " + actual);
            }
        }

        public static void Equal(byte[] expected, byte[] actual, string what)
        {
            if (actual == null)
            {
                throw new SmokeCheckException(what + ": expected " + SmokeHex.Short(expected) + ", got null");
            }
            if (expected.AsSpan().SequenceEqual(actual))
            {
                return;
            }
            int at = 0;
            while (at < expected.Length && at < actual.Length && expected[at] == actual[at])
            {
                at++;
            }
            throw new SmokeCheckException(what + ": differs at byte " + at + " (expected " + expected.Length
                + " bytes, got " + actual.Length + "): expected ..." + SmokeHex.Window(expected, at) + ", got ..."
                + SmokeHex.Window(actual, at));
        }

        public static void NotNull(object value, string what)
        {
            if (value == null)
            {
                throw new SmokeCheckException(what + ": null");
            }
        }

        /// <summary>The body must throw <typeparamref name="T"/> (or a subclass); returns it.</summary>
        public static T Throws<T>(Action body, string what) where T : Exception
        {
            try
            {
                body();
            }
            catch (T e)
            {
                return e;
            }
            catch (Exception e)
            {
                throw new SmokeCheckException(what + ": expected " + typeof(T).Name + ", got " + e.GetType().Name
                    + ": " + e.Message);
            }
            throw new SmokeCheckException(what + ": expected " + typeof(T).Name + ", nothing thrown");
        }
    }

    /// <summary>Hex helpers owned by the harness, so vectors do not depend on either library.</summary>
    public static class SmokeHex
    {
        /// <summary>Decodes hex, ignoring whitespace.</summary>
        public static byte[] Decode(string hex)
        {
            var digits = new StringBuilder(hex.Length);
            foreach (char c in hex)
            {
                if (!char.IsWhiteSpace(c))
                {
                    digits.Append(c);
                }
            }
            return Convert.FromHexString(digits.ToString());
        }

        public static string Encode(byte[] data) => Convert.ToHexString(data).ToLowerInvariant();

        /// <summary>Up to 16 bytes from <paramref name="at"/>, for messages.</summary>
        public static string Window(byte[] data, int at) =>
            at >= data.Length ? "(end)" : Encode(data.AsSpan(at, Math.Min(16, data.Length - at)).ToArray());

        /// <summary>Hex, cut to 32 bytes for messages.</summary>
        public static string Short(byte[] data) =>
            data.Length <= 32 ? Encode(data) : Encode(data.AsSpan(0, 32).ToArray()) + "...(" + data.Length + " bytes)";
    }
}
