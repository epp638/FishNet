#nullable enable
using System.Threading;

namespace LiteNetLib
{
    /// <summary>
    /// FJ#1488 (plan_FJ1488 rev5 §4-§5): Admission-Zustand fuer EINE serverseitig angenommene
    /// physische Verbindung. Lebt direkt am <see cref="NetPeer"/>-Objekt (<see cref="NetPeer.FjLease"/>),
    /// NICHT in einem nach Id oder Adresse+Port indizierten Dictionary -- das vermeidet sowohl die
    /// Wiederverwendung der numerischen Peer-Id (<c>NetManager.GetNextPeerId</c> recycelt sie) als
    /// auch die von <see cref="NetPeer"/> geerbte <c>IPEndPoint.Equals</c>-Semantik (Adresse+Port)
    /// als Identitaetstraeger fuer die Admission-Verwaltung (rev5 §4.1).
    /// </summary>
    /// <remarks>
    /// Ausgehende Client-Peers und die kurzlebigen Benachrichtigungs-Peers eines abgelehnten
    /// Verbindungsversuchs (<c>ConnectionRequestResult.Reject</c>, <see cref="NetManager"/>
    /// „OnConnectionSolved" Reject-Zweig) bekommen KEINE Lease -- <see cref="NetPeer.FjLease"/>
    /// bleibt dort <c>null</c>.
    /// </remarks>
    internal sealed class FjAdmissionLease
    {
        internal const int StatePending = 0;
        internal const int StateAuthenticated = 1;
        internal const int StateTimedOut = 2;
        internal const int StateClosed = 3;

        /// <summary>Transport-Epoche des <see cref="NetManager"/> beim Erzeugen dieser Lease
        /// (rev5 §4.1) -- erlaubt, ein verspaetetes Ereignis/eine verspaetete Freigabe aus einer
        /// bereits gestoppten Epoche zu erkennen, statt es auf eine neue Epoche wirken zu lassen.</summary>
        internal readonly long Epoch;

        /// <summary>Monotoner Zeitpunkt der Annahme (<see cref="System.Diagnostics.Stopwatch.GetTimestamp"/>),
        /// gesetzt auf dem Netz-Thread. NICHT <c>Environment.TickCount64</c> -- existiert unter
        /// Unitys .NET-Standard-Kompatibilitaetsstufe nicht (CS0117, verifiziert).</summary>
        internal readonly long AcceptedAtTicks;

        /// <summary>Monotoner Zeitpunkt (dieselbe Stopwatch-Zeiteinheit wie <see cref="AcceptedAtTicks"/>),
        /// ab dem die Vor-Auth-Frist als abgelaufen gilt (<c>AcceptedAtTicks + FjPreAuthTimeoutMs</c>
        /// umgerechnet ueber <see cref="System.Diagnostics.Stopwatch.Frequency"/>).</summary>
        internal readonly long PreAuthDeadlineTicks;

        private int _state;

        internal FjAdmissionLease(long epoch, long acceptedAtTicks, long preAuthDeadlineTicks)
        {
            Epoch = epoch;
            AcceptedAtTicks = acceptedAtTicks;
            PreAuthDeadlineTicks = preAuthDeadlineTicks;
            _state = StatePending;
        }

        /// <summary>Aktueller Zustand, NUR fuer Diagnose/Logs -- niemals als Grundlage fuer einen
        /// nachfolgenden unbedingten Schreibzugriff verwenden (das waere wieder der rev2-Fehler:
        /// ein Read gefolgt von einem separaten Write ist kein atomarer Uebergang).</summary>
        internal int CurrentState => Volatile.Read(ref _state);

        /// <summary>Versucht den atomaren Uebergang von <paramref name="fromState"/> nach
        /// <paramref name="toState"/>. Gibt <c>true</c> zurueck, wenn DIESER Aufruf den Uebergang
        /// gewonnen hat -- nur der Gewinner darf den zugehoerigen Seiteneffekt (Budget-Freigabe,
        /// Fortsetzung der Authentifizierung, Disconnect) ausloesen. Der Verlierer tut nichts.</summary>
        internal bool TryTransition(int fromState, int toState) =>
            Interlocked.CompareExchange(ref _state, toState, fromState) == fromState;
    }
}
