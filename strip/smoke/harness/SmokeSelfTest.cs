using System;
using System.Collections.Generic;
using System.Threading;

namespace TurboSmoke
{
    /// <summary>
    /// Checks the runner itself (run.sh calls --self-test before the rows): a failing row, an exception, a
    /// static initializer that throws (the E6 failure mode: CustomNamedCurves.DefineCurveAlias), a hanging row
    /// and a group whose registration throws each fail alone, and the rows after them still run; slow rows
    /// (#27) are selected only with --slow and listed as skipped otherwise.
    /// </summary>
    internal static class SmokeSelfTest
    {
        internal static bool Run()
        {
            var failures = new List<SmokeResult>();
            List<SmokeRow> rows = SmokeRunner.Register(
                new SmokeRowGroup[] { new BrokenGroup(), new SampleGroup(), new DuplicateGroup() }, failures);
            var results = new List<SmokeResult>(failures);
            foreach (SmokeRow row in rows)
            {
                results.Add(SmokeRunner.Run(row));
            }
            Console.Write(SmokeRunner.Format("self-test (7 failures expected)", results));

            var expected = new[]
            {
                // id, passed, detail fragment; registration failures come first
                new object[] { "broken/(registration)", false, "InvalidOperationException: registration broke" },
                new object[] { "sample/pass", false, "duplicate row id" },
                new object[] { "sample/(registration)", false, "duplicate group name" },
                new object[] { "sample/pass", true, "" },
                new object[] { "sample/check", false, "value: expected 1, got 2" },
                new object[] { "sample/throw", false, "NotSupportedException: thrown" },
                new object[] { "sample/static-init", false, "TypeInitializationException" },
                new object[] { "sample/timeout", false, "timed out after 1000 ms" },
                new object[] { "sample/after-timeout", true, "" },
            };
            bool ok = results.Count == expected.Length;
            for (int i = 0; ok && i < expected.Length; i++)
            {
                SmokeResult r = results[i];
                ok = r.Id == (string)expected[i][0] && r.Passed == (bool)expected[i][1]
                    && r.Detail.Contains((string)expected[i][2], StringComparison.Ordinal);
            }
            ok = ok && results[6].Detail.Contains("static init broke", StringComparison.Ordinal);
            ok = ok && SelectsSlowRowsOnlyWithSlow();
            Console.WriteLine(ok ? "self-test: OK" : "self-test: FAILED (runner isolation broken)");
            return ok;
        }

        // Slow rows (#27) run only with --slow and are listed as skipped otherwise; the filter still applies.
        private static bool SelectsSlowRowsOnlyWithSlow()
        {
            var failures = new List<SmokeResult>();
            List<SmokeRow> rows = SmokeRunner.Register(new SmokeRowGroup[] { new SlowGroup() }, failures);
            var none = new List<string>();
            var skippedFast = new List<string>();
            string fast = Ids(SmokeRunner.Select(rows, none, false, skippedFast));
            var skippedSlow = new List<string>();
            string all = Ids(SmokeRunner.Select(rows, none, true, skippedSlow));
            var skippedFiltered = new List<string>();
            string filtered = Ids(SmokeRunner.Select(rows, new List<string> { "LONG" }, false, skippedFiltered));
            bool ok = failures.Count == 0
                && fast == "pace/quick" && string.Join(" ", skippedFast) == "pace/long"
                && all == "pace/quick pace/long" && skippedSlow.Count == 0
                && filtered == "" && string.Join(" ", skippedFiltered) == "pace/long";
            Console.WriteLine((ok ? "PASS" : "FAIL") + " self-test/slow-selection (without --slow: [" + fast
                + "] skipped [" + string.Join(" ", skippedFast) + "]; with --slow: [" + all + "])");
            return ok;
        }

        private static string Ids(List<SmokeRow> rows) => string.Join(" ", rows.ConvertAll(r => r.Id));

        private sealed class SlowGroup : SmokeRowGroup
        {
            public override string Name => "pace";
            public override int Order => 0;

            public override void AddRows(SmokeRows rows)
            {
                rows.Add("quick", () => { });
                rows.AddSlow("long", () => { });
            }
        }

        private sealed class BrokenGroup : SmokeRowGroup
        {
            public override string Name => "broken";
            public override int Order => 0;
            public override void AddRows(SmokeRows rows) => throw new InvalidOperationException("registration broke");
        }

        private sealed class SampleGroup : SmokeRowGroup
        {
            public override string Name => "sample";
            public override int Order => 1;

            public override void AddRows(SmokeRows rows)
            {
                rows.Add("pass", () => { });
                rows.Add("check", () => SmokeAssert.Equal(1, 2, "value"));
                rows.Add("throw", () => throw new NotSupportedException("thrown"));
                rows.Add("static-init", () => Exploding.Touch());
                rows.Add("timeout", () => new ManualResetEventSlim(false).Wait(), 1000);
                rows.Add("after-timeout", () => { });
                rows.Add("pass", () => { });
            }
        }

        // Same name as SampleGroup, ordered after it: must be reported, not merged.
        private sealed class DuplicateGroup : SmokeRowGroup
        {
            public override string Name => "sample";
            public override int Order => 2;
            public override void AddRows(SmokeRows rows) => rows.Add("extra", () => { });
        }

        private static class Exploding
        {
            private static readonly int s_value = Explode();

            internal static void Touch() => GC.KeepAlive(s_value);

            private static int Explode() => throw new InvalidOperationException("static init broke");
        }
    }
}
