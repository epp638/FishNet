#nullable enable

namespace LiteNetLib
{
    /// <summary>Ein einzelner Diagnose-Eintrag aus <see cref="FjDiagRing"/> (plan_FJ1488 rev5 §9).</summary>
    public readonly struct FjDiagEntry
    {
        /// <summary>Monotoner Zeitpunkt (<see cref="System.Diagnostics.Stopwatch.GetTimestamp"/>).</summary>
        public readonly long TimestampTicks;
        /// <summary>Transport-Epoche, in der der Eintrag entstand (rev5 §4.1) -- 0 fuer Eintraege
        /// ohne Bezug zu einer konkreten serverseitigen NetManager-Instanz.</summary>
        public readonly long Epoch;
        /// <summary>Kurzer, stabiler Kategorie-Token (z.B. "Accept", "Closed", "RecvOverflow",
        /// "SendOverflow") -- kein Freitext, damit Auswertung nach Kategorie filtern kann.</summary>
        public readonly string Category;
        /// <summary>Freitext, bereits auf <see cref="FjDiagRing.MaxMessageLength"/> Zeichen
        /// abgeschnitten.</summary>
        public readonly string Message;

        internal FjDiagEntry(long timestampTicks, long epoch, string category, string message)
        {
            TimestampTicks = timestampTicks;
            Epoch = epoch;
            Category = category;
            Message = message;
        }
    }

    /// <summary>
    /// FJ#1488 (plan_FJ1488 rev5 §7.1/§9): primitive, thread-sichere Ringpuffer-Diagnose OHNE
    /// Unity-Abhaengigkeit. Der Paketcode ruft KEINE Projekt-Diagnoseklasse auf (kein
    /// <c>UnityEngine.Debug</c>, kein <c>FJDiag</c>) -- er bietet diese Rohdaten nur zum Abholen
    /// an; die projektseitige Weiterleitung nach <c>[Net_DIAG]</c>/File-Sink ist Sache des
    /// Projekt-Codes (Assembly-Grenze, s. <c>Fj1459SocketDiag</c>-Vorbild, ebenfalls <c>public</c>).
    /// </summary>
    /// <remarks>
    /// Kapazitaet <see cref="Capacity"/> = 4096 Eintraege (rev5 §7.1). Bei Vollstand werden die
    /// aeltesten Eintraege ueberschrieben; <see cref="ReadSnapshot"/> liefert die Anzahl dadurch
    /// verlorener (fuer den Aufrufer nie einsehbarer) Eintraege mit zurueck -- rev5 §7.3: "Ein Lauf
    /// ohne benoetigten Nachweis wegen Diagnoseverlust gilt als nicht auswertbar." Ein einfacher
    /// Lock schuetzt Schreiben/Lesen; das ist kein Hot-Path im Sinne von "pro Paket", sondern
    /// "pro bedeutsamem Zustandsuebergang" (Accept, Close, Ueberlast, spaeter Auth-Gate/Join/Ack) --
    /// Kontention bleibt gering.
    /// </remarks>
    public static class FjDiagRing
    {
        public const int Capacity = 4096;
        public const int MaxMessageLength = 512;

        private static readonly FjDiagEntry[] _entries = new FjDiagEntry[Capacity];
        private static readonly object _lock = new();
        private static long _writeIndex;

        /// <summary>Schreibt einen Eintrag. Sicher von jedem Thread (Receive/Logic/Main) aus
        /// aufrufbar. Kuerzt <paramref name="message"/> auf <see cref="MaxMessageLength"/> Zeichen.</summary>
        public static void Log(long epoch, string category, string message)
        {
            if (message != null && message.Length > MaxMessageLength)
                message = message.Substring(0, MaxMessageLength);

            long ts = System.Diagnostics.Stopwatch.GetTimestamp();
            lock (_lock)
            {
                int idx = (int)(_writeIndex % Capacity);
                _entries[idx] = new FjDiagEntry(ts, epoch, category, message);
                _writeIndex++;
            }
        }

        /// <summary>Liest bis zu <paramref name="max"/> der zuletzt geschriebenen Eintraege in
        /// chronologischer Reihenfolge (aeltester zuerst), OHNE den Ring zu leeren -- reiner
        /// Snapshot, mehrfach lesbar. <paramref name="totalWritten"/> ist die Gesamtzahl seit
        /// Prozessstart geschriebener Eintraege, <paramref name="overwrittenCount"/> die Anzahl
        /// davon, die durch Ueberlauf bereits unwiederbringlich ueberschrieben wurden.</summary>
        public static FjDiagEntry[] ReadSnapshot(int max, out long totalWritten, out long overwrittenCount)
        {
            lock (_lock)
            {
                totalWritten = _writeIndex;
                int available = (int)System.Math.Min(totalWritten, Capacity);
                overwrittenCount = totalWritten > Capacity ? totalWritten - Capacity : 0;
                int count = System.Math.Min(max, available);
                var result = new FjDiagEntry[count];
                for (int i = 0; i < count; i++)
                {
                    long sourceIndex = totalWritten - count + i;
                    result[i] = _entries[(int)(sourceIndex % Capacity)];
                }
                return result;
            }
        }
    }
}
