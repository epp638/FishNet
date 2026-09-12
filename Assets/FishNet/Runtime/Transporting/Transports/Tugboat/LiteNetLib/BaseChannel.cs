using System.Collections.Generic;
using System.Threading;

namespace LiteNetLib
{
    internal abstract class BaseChannel
    {
        protected readonly NetPeer Peer;
        protected readonly Queue<NetPacket> OutgoingQueue = new(NetConstants.DefaultWindowSize);
        private int _isAddedToPeerChannelSendQueue;
        public int PacketsInQueue => OutgoingQueue.Count;

        protected BaseChannel(NetPeer peer)
        {
            Peer = peer;
        }

        public void AddToQueue(NetPacket packet)
        {
            // FJ#1488 (plan_FJ1488 rev5 §7.1/§7.2): OutgoingQueue ist die einzige unbegrenzt
            // wachsende ausgehende Struktur -- waechst, solange ein entfernter Peer nicht/langsam
            // bestaetigt. Budget VOR dem Einreihen reservieren, bei Ueberschreitung Paket
            // verwerfen UND den Peer kontrolliert trennen (rev5 §7.3, derselbe Grundsatz wie auf
            // der Empfangsseite -- kein unbegrenztes Anwachsen fuer einen stockenden Peer).
            if (!Peer.NetManager.FjTryReserveSend(Peer, packet.Size))
            {
                Peer.NetManager.PoolRecycle(packet);
                Peer.NetManager.DisconnectPeerForce(Peer, DisconnectReason.FjQueueOverflow, 0, null);
                return;
            }

            lock (OutgoingQueue)
            {
                OutgoingQueue.Enqueue(packet);
            }
            AddToPeerChannelSendQueue();
        }

        /// <summary>FJ#1488 (rev5 §7.2): EINZIGER Ausgang aus <see cref="OutgoingQueue"/> --
        /// gibt beim Dequeue exakt die Menge frei, die <see cref="AddToQueue"/> reserviert hat.
        /// Ab hier lebt das Paket im festen <c>_pendingPackets</c>/Sende-Fenster der jeweiligen
        /// Channel-Implementierung, das schon vor FJ#1488 auf <c>_windowSize</c> begrenzt war --
        /// dafuer ist kein zusaetzliches Budget noetig.</summary>
        protected NetPacket DequeueOutgoing()
        {
            NetPacket packet = OutgoingQueue.Dequeue();
            Peer.NetManager.FjReleaseSend(Peer, packet.Size);
            return packet;
        }

        protected void AddToPeerChannelSendQueue()
        {
            if (Interlocked.CompareExchange(ref _isAddedToPeerChannelSendQueue, 1, 0) == 0)
            {
                Peer.AddToReliableChannelSendQueue(this);
            }
        }

        public bool SendAndCheckQueue()
        {
            bool hasPacketsToSend = SendNextPackets();
            if (!hasPacketsToSend)
                Interlocked.Exchange(ref _isAddedToPeerChannelSendQueue, 0);

            return hasPacketsToSend;
        }

        protected abstract bool SendNextPackets();
        public abstract bool ProcessPacket(NetPacket packet);
    }
}