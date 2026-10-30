// Copyright (c) 2026 fatal10110 and contributors. Licensed under the MIT License.
// Regression checks for strip-v2 edge cut E7 (STRIP_PLAN_V2.md §3 E7) until the smoke suite (#26) exists.

using System;
using System.Diagnostics;

using NUnit.Framework;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Turbo.Tests
{
    [TestFixture]
    public class RsaKeyParametersE7Test
    {
        // Acceptance target from #17. The bound is checked against the fastest of several warm runs, so a
        // loaded box or a JIT/GC pause in one run does not fail it; upstream's Miller-Rabin costs ~1 s per
        // 8192-bit key, more than an order of magnitude above it.
        private const long AcceptMillisBound = 50;
        private const int TimedRuns = 5;

        private static readonly BigInteger E65537 = BigInteger.ValueOf(65537);

        // Built once, outside every timed region.
        private static readonly BigInteger N8192 = MakeModulus(8192, 5);
        private static readonly BigInteger N8193 = MakeModulus(8193, 6);

        // A prime "modulus" with no small factors: only Miller-Rabin can reject it, so its acceptance
        // shows that the default runs no Miller-Rabin.
        private static readonly BigInteger P1024 = BigInteger.ProbablePrime(1024, new Random(7));

        [TearDown]
        public void RemoveThreadProperties()
        {
            Properties.RemoveThreadProperty(Properties.RsaMaxSize);
            Properties.RemoveThreadProperty(Properties.RsaMaxMRTests);
        }

        [Test]
        public void Modulus8192AcceptedFast()
        {
            // Warm-up: JIT and first-call costs stay out of the measurement.
            Assert.AreEqual(N8192, new RsaKeyParameters(false, N8192, E65537).Modulus);

            long best = long.MaxValue;
            for (int i = 0; i < TimedRuns && best >= AcceptMillisBound; ++i)
            {
                var stopwatch = Stopwatch.StartNew();
                var key = new RsaKeyParameters(false, N8192, E65537);
                stopwatch.Stop();

                Assert.AreEqual(N8192, key.Modulus);
                best = System.Math.Min(best, stopwatch.ElapsedMilliseconds);
            }

            Assert.Less(best, AcceptMillisBound, "fastest 8192-bit RsaKeyParameters construction, ms");
        }

        [Test]
        public void Modulus8193Rejected()
        {
            var ex = Assert.Throws<ArgumentException>(() => new RsaKeyParameters(false, N8193, E65537));
            StringAssert.StartsWith("RSA modulus out of range", ex.Message);

            Assert.Throws<ArgumentException>(() => RsaKeyParameters.ValidateModulus(N8193));
        }

        [Test]
        public void MaxSizeOverrideStillRespected()
        {
            Properties.SetThreadInt32(Properties.RsaMaxSize, 8193);
            Assert.AreEqual(N8193, new RsaKeyParameters(false, N8193, E65537).Modulus);

            Properties.SetThreadInt32(Properties.RsaMaxSize, 4096);
            var ex = Assert.Throws<ArgumentException>(() => new RsaKeyParameters(false, N8192, E65537));
            StringAssert.StartsWith("RSA modulus out of range", ex.Message);
        }

        [Test]
        public void NoMillerRabinByDefault()
        {
            Assert.AreEqual(P1024, new RsaKeyParameters(false, P1024, E65537).Modulus);
        }

        [Test]
        public void MillerRabinOverrideStillRespected()
        {
            Properties.SetThreadInt32(Properties.RsaMaxMRTests, 3);
            var ex = Assert.Throws<ArgumentException>(() => new RsaKeyParameters(false, P1024, E65537));
            StringAssert.StartsWith("RSA modulus is not composite", ex.Message);
        }

        // Deterministic odd composite of exactly 'bits' bits with no small prime factors (copied from
        // TurboKeyFactoryTest), so the small-factor check passes and only the size cap decides.
        private static BigInteger MakeModulus(int bits, int seed)
        {
            var random = new Random(seed);
            BigInteger n = new BigInteger(bits, random).SetBit(bits - 1).SetBit(bits - 2).SetBit(0);
            while (BigIntegers.HasAnySmallFactors(n) || n.IsProbablePrime(8))
            {
                n = n.Add(BigInteger.Two);
            }
            Assert.AreEqual(bits, n.BitLength);
            return n;
        }
    }
}
