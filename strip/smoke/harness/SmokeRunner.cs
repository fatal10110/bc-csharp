using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading;

namespace TurboSmoke
{
    public sealed class SmokeResult
    {
        internal SmokeResult(string id, bool passed, string detail, long millis)
        {
            Id = id;
            Passed = passed;
            Detail = detail;
            Millis = millis;
        }

        public string Id { get; }
        public bool Passed { get; }
        public string Detail { get; }
        public long Millis { get; }
    }

    /// <summary>Discovers row groups, runs rows isolated, formats the results.</summary>
    internal static class SmokeRunner
    {
        private const int MaxDetailLength = 300;

        /// <summary>Every row group of the harness assembly except the runner's own self-test groups.</summary>
        internal static List<SmokeRowGroup> FindGroups(List<SmokeResult> failures)
        {
            Type[] types;
            try
            {
                types = typeof(SmokeRunner).Assembly.GetTypes();
            }
            catch (ReflectionTypeLoadException e)
            {
                types = e.Types.Where(t => t != null).ToArray();
                failures.Add(Failure("harness/load", e));
            }

            var groups = new List<SmokeRowGroup>();
            foreach (Type t in types)
            {
                if (t.IsAbstract || !typeof(SmokeRowGroup).IsAssignableFrom(t) || t.DeclaringType == typeof(SmokeSelfTest))
                {
                    continue;
                }
                try
                {
                    groups.Add((SmokeRowGroup)Activator.CreateInstance(t));
                }
                catch (Exception e)
                {
                    failures.Add(Failure("harness/" + t.Name, e));
                }
            }
            return groups;
        }

        /// <summary>Registers the rows of the groups in run order; a group whose registration throws, or a
        /// duplicate group or row id, becomes a failure instead of rows.</summary>
        internal static List<SmokeRow> Register(IEnumerable<SmokeRowGroup> groups, List<SmokeResult> failures)
        {
            var rows = new List<SmokeRow>();
            var groupNames = new HashSet<string>(StringComparer.Ordinal);
            var ids = new HashSet<string>(StringComparer.Ordinal);
            foreach (SmokeRowGroup group in groups.OrderBy(g => g.Order).ThenBy(g => g.Name, StringComparer.Ordinal))
            {
                if (!groupNames.Add(group.Name))
                {
                    failures.Add(new SmokeResult(group.Name + "/(registration)", false,
                        "duplicate group name (" + group.GetType().Name + ")", 0));
                    continue;
                }
                var groupRows = new List<SmokeRow>();
                try
                {
                    group.AddRows(new SmokeRows(group.Name, groupRows));
                }
                catch (Exception e)
                {
                    failures.Add(Failure(group.Name + "/(registration)", e));
                    continue;
                }
                foreach (SmokeRow row in groupRows)
                {
                    if (ids.Add(row.Id))
                    {
                        rows.Add(row);
                    }
                    else
                    {
                        failures.Add(new SmokeResult(row.Id, false, "duplicate row id", 0));
                    }
                }
            }
            return rows;
        }

        /// <summary>Runs one row on its own thread: whatever it throws fails the row only; a row past its
        /// timeout is abandoned (background thread) and failed.</summary>
        internal static SmokeResult Run(SmokeRow row)
        {
            Exception error = null;
            var watch = Stopwatch.StartNew();
            var thread = new Thread(() =>
            {
                try
                {
                    row.Body();
                }
                catch (Exception e)
                {
                    error = e;
                }
            });
            thread.IsBackground = true;
            thread.Name = "smoke " + row.Id;
            thread.Start();
            if (!thread.Join(row.TimeoutMillis))
            {
                return new SmokeResult(row.Id, false, "timed out after " + row.TimeoutMillis + " ms (row abandoned)",
                    watch.ElapsedMilliseconds);
            }
            return error == null
                ? new SmokeResult(row.Id, true, "", watch.ElapsedMilliseconds)
                : Failure(row.Id, error, watch.ElapsedMilliseconds);
        }

        internal static SmokeResult Failure(string id, Exception e, long millis = 0) =>
            new SmokeResult(id, false, Describe(e), millis);

        /// <summary>One line: the exception chain (type: message -> inner ...), capped.</summary>
        internal static string Describe(Exception e)
        {
            while ((e is TargetInvocationException || e is AggregateException) && e.InnerException != null)
            {
                e = e.InnerException;
            }
            var sb = new StringBuilder();
            for (int depth = 0; e != null && depth < 4; depth++, e = e.InnerException)
            {
                if (depth > 0)
                {
                    sb.Append(" -> ");
                }
                if (!(e is SmokeCheckException))
                {
                    sb.Append(e.GetType().Name).Append(": ");
                }
                sb.Append(e.Message);
            }
            string text = sb.ToString().Replace('\r', ' ').Replace('\n', ' ');
            return text.Length <= MaxDetailLength ? text : text.Substring(0, MaxDetailLength) + "...";
        }

        /// <summary>The results block for one DLL: a summary line, then one line per row. No timings, so a
        /// rerun on the same inputs writes the same text (it goes into STRIP_INFO.md).</summary>
        internal static string Format(string title, IList<SmokeResult> results)
        {
            int passed = results.Count(r => r.Passed);
            var sb = new StringBuilder();
            sb.Append(title).Append(": ").Append(results.Count).Append(" rows, ").Append(passed)
                .Append(" passed, ").Append(results.Count - passed).Append(" failed\n");
            foreach (SmokeResult r in results)
            {
                sb.Append(r.Passed ? "  PASS " : "  FAIL ").Append(r.Id);
                if (!r.Passed)
                {
                    sb.Append(": ").Append(r.Detail);
                }
                sb.Append('\n');
            }
            return sb.ToString();
        }
    }
}
