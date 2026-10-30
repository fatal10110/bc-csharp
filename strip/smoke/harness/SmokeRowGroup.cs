using System;
using System.Collections.Generic;

namespace TurboSmoke
{
    /// <summary>
    /// One group of smoke rows, one file per group under strip/smoke/rows/ (curves, kat-*, interop, hostile,
    /// timeout, ...). The runner finds every non-abstract subclass with a public parameterless constructor by
    /// reflection, so adding a group never edits a shared file. Groups run by <see cref="Order"/>, then by
    /// <see cref="Name"/>; rows in the order <see cref="AddRows"/> adds them.
    /// </summary>
    /// <remarks>
    /// <see cref="AddRows"/> only registers: it must not touch library types (a static initializer that throws
    /// there would take the whole group down instead of one row). Row bodies run isolated: an exception, a
    /// TypeInitializationException or a missing member fails that row only, and a row that outlives its timeout
    /// is abandoned and failed while the next row runs.
    /// </remarks>
    public abstract class SmokeRowGroup
    {
        /// <summary>Short group name, the first part of every row id ("curves", "kat-aead", ...).</summary>
        public abstract string Name { get; }

        /// <summary>Run order; curve lookup runs first (0), KATs at 10, everything else at 100 by default.</summary>
        public virtual int Order => 100;

        public abstract void AddRows(SmokeRows rows);
    }

    public sealed class SmokeRow
    {
        internal SmokeRow(string group, string name, Action body, int timeoutMillis)
        {
            Group = group;
            Name = name;
            Body = body;
            TimeoutMillis = timeoutMillis;
        }

        public string Group { get; }
        public string Name { get; }
        public string Id => Group + "/" + Name;
        public Action Body { get; }
        public int TimeoutMillis { get; }
    }

    /// <summary>Row registration for one group.</summary>
    public sealed class SmokeRows
    {
        /// <summary>Default per-row timeout; a row that needs longer passes its own.</summary>
        public const int DefaultTimeoutMillis = 60000;

        private readonly string m_group;
        private readonly List<SmokeRow> m_rows;

        internal SmokeRows(string group, List<SmokeRow> rows)
        {
            m_group = group;
            m_rows = rows;
        }

        public void Add(string name, Action body, int timeoutMillis = DefaultTimeoutMillis)
        {
            if (string.IsNullOrEmpty(name))
            {
                throw new ArgumentException("row name is empty", nameof(name));
            }
            if (body == null)
            {
                throw new ArgumentNullException(nameof(body));
            }
            if (timeoutMillis <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(timeoutMillis));
            }
            m_rows.Add(new SmokeRow(m_group, name, body, timeoutMillis));
        }
    }

    /// <summary>What the runner knows about the current run (set once by Program before any row runs).</summary>
    public static class SmokeContext
    {
        /// <summary>The define-set label of the TurboBC DLL under test ("min", "ns21", "netfx", ...).</summary>
        public static string Label { get; internal set; } = "";

        /// <summary>Path of the TurboBC DLL under test.</summary>
        public static string TurboBcDll { get; internal set; } = "";

        /// <summary>A scratch directory owned by this run (certificates, server logs); created on demand.</summary>
        public static string WorkDir { get; internal set; } = "";
    }
}
