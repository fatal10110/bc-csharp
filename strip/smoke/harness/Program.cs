using System;
using System.Collections.Generic;
using System.IO;

namespace TurboSmoke
{
    /// <summary>
    /// TurboSmoke --label &lt;x&gt; --dll &lt;TurboBC.x.dll&gt; [--results &lt;file&gt;] [--work &lt;dir&gt;]
    ///            [--filter &lt;substring of group/row&gt;]... [--slow]
    /// TurboSmoke --self-test
    /// Slow rows (<see cref="SmokeRows.AddSlow"/>) run only with --slow; otherwise they are listed as skipped.
    /// Exit: 0 every row passed, 1 a row failed (or no row ran), 2 usage.
    /// </summary>
    public static class Program
    {
        public static int Main(string[] args)
        {
            int code;
            try
            {
                code = Run(args);
            }
            catch (UsageException e)
            {
                Console.Error.WriteLine("TurboSmoke: " + e.Message);
                Console.Error.WriteLine("usage: TurboSmoke --label <x> --dll <TurboBC.x.dll> [--results <file>] "
                    + "[--work <dir>] [--filter <text>]... [--slow] | --self-test");
                code = 2;
            }
            Console.Out.Flush();
            // Abandoned (timed-out) rows may still hold threads; do not wait for them.
            Environment.Exit(code);
            return code;
        }

        private static int Run(string[] args)
        {
            string label = null, dll = null, results = null, work = null;
            var filters = new List<string>();
            bool selfTest = false, slow = false;
            for (int i = 0; i < args.Length; i++)
            {
                switch (args[i])
                {
                case "--self-test":
                    selfTest = true;
                    break;
                case "--label":
                    label = Value(args, ref i);
                    break;
                case "--dll":
                    dll = Value(args, ref i);
                    break;
                case "--results":
                    results = Value(args, ref i);
                    break;
                case "--work":
                    work = Value(args, ref i);
                    break;
                case "--filter":
                    filters.Add(Value(args, ref i));
                    break;
                case "--slow":
                    slow = true;
                    break;
                default:
                    throw new UsageException("unknown argument: " + args[i]);
                }
            }
            if (selfTest)
            {
                return SmokeSelfTest.Run() ? 0 : 1;
            }
            if (label == null || dll == null)
            {
                throw new UsageException("--label and --dll are required");
            }

            SmokeContext.Label = label;
            SmokeContext.TurboBcDll = Path.GetFullPath(dll);
            SmokeContext.WorkDir = Path.GetFullPath(work ?? Path.Combine(Path.GetTempPath(), "turbo-smoke-" + label));

            var outcomes = new List<SmokeResult>();
            List<SmokeRowGroup> groups = SmokeRunner.FindGroups(outcomes);
            List<SmokeRow> rows = SmokeRunner.Register(groups, outcomes);
            int ran = 0;
            var skipped = new List<string>();
            List<SmokeRow> selected = SmokeRunner.Select(rows, filters, slow, skipped);
            foreach (string id in skipped)
            {
                Console.WriteLine("SKIP " + id + " (slow row; needs --slow)");
            }
            foreach (SmokeRow row in selected)
            {
                SmokeResult r = SmokeRunner.Run(row);
                outcomes.Add(r);
                ran++;
                Console.WriteLine((r.Passed ? "PASS " : "FAIL ") + r.Id + " (" + r.Millis + " ms)"
                    + (r.Passed ? "" : ": " + r.Detail));
            }
            if (ran == 0)
            {
                outcomes.Add(new SmokeResult("harness/rows", false, "no row ran (filter: "
                    + string.Join(", ", filters) + "; slow rows skipped without --slow: " + skipped.Count + ")", 0));
            }

            string title = Path.GetFileName(SmokeContext.TurboBcDll);
            string text = SmokeRunner.Format(title, outcomes);
            foreach (string id in skipped)
            {
                // Not a result: the package says which rows this run left out (strip.sh --smoke-slow runs them).
                text += "  SKIP " + id + " (slow row; not run without --slow)\n";
            }
            Console.Write(text);
            if (results != null)
            {
                File.WriteAllText(results, text);
            }
            return outcomes.TrueForAll(r => r.Passed) ? 0 : 1;
        }

        private static string Value(string[] args, ref int i)
        {
            if (i + 1 >= args.Length || args[i + 1].Length == 0)
            {
                throw new UsageException(args[i] + " needs a value");
            }
            return args[++i];
        }

        private sealed class UsageException : Exception
        {
            public UsageException(string message)
                : base(message)
            {
            }
        }
    }
}
