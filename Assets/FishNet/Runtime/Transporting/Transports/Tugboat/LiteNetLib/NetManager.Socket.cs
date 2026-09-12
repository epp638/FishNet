#if UNITY_2018_3_OR_NEWER
#define UNITY_SOCKET_FIX
#endif
using System.Runtime.InteropServices;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using LiteNetLib.Utils;

namespace LiteNetLib
{
    // FJ#1459 (Brief 1459b, temporaer -- Diagnose, siehe Ledger FJ#1459): instrumentiert die
    // Socket-Grenze (Client-Send -> Npcap-Loopback-Capture -> Host-Receive), um zu unterscheiden
    // ob ein UDP-Paket beim intermittierenden Verbindungsfehlschlag (a) nie gesendet, (b) gesendet
    // aber nicht am Socket empfangen, oder (c) am Socket empfangen aber danach verworfen wird.
    // Queue + eigener Writer-Thread PFLICHT (Brief-Vorgabe) -- kein synchrones File-IO auf dem
    // Sende-/Empfangsthread, das waere selbst ein Beobachtereffekt fuer genau das Timing, das
    // untersucht wird. NICHT dauerhaft gedacht -- nach Abschluss der Testserie wieder entfernen
    // (PackageCache-Datei, ohnehin nicht versioniert).
    // Public statt internal: CONNECT_RESULT wird zusaetzlich aus FJNetBootstrap.cs (Assets-
    // Assembly, siehe FJ#1459) in dasselbe Log geschrieben.
    public static class Fj1459SocketDiag
    {
        private static readonly BlockingCollection<string> _queue = new BlockingCollection<string>();
        private static readonly object _initLock = new object();
        private static volatile bool _started;
        private static string _run = "";
        private static string _role = "unknown";
        private static string _filePath = "";

        private static void EnsureStarted()
        {
            if (_started)
                return;

            lock (_initLock)
            {
                if (_started)
                    return;

                string[] args = Environment.GetCommandLineArgs();
                bool hasServer = false;
                bool hasClient = false;
                foreach (string a in args)
                {
                    if (string.Equals(a, "-fjserver", StringComparison.OrdinalIgnoreCase)) hasServer = true;
                    else if (string.Equals(a, "-fjclient", StringComparison.OrdinalIgnoreCase)) hasClient = true;
                }
                _role = (hasServer, hasClient) switch
                {
                    (true, true) => "host",
                    (true, false) => "server",
                    (false, true) => "client",
                    _ => "unknown",
                };

                int pid = System.Diagnostics.Process.GetCurrentProcess().Id;
                _run = DateTime.UtcNow.ToString("yyyyMMdd_HHmmss") + "_" + pid;

                string dir = Path.Combine(AppContext.BaseDirectory, "FJ1459_NetDiag");
                try { Directory.CreateDirectory(dir); }
                catch { /* best effort -- Diagnose darf den Netzwerk-Betrieb nie stoeren */ }

                _filePath = Path.Combine(dir, $"fj1459_{_role}_{pid}.log");

                Thread writer = new Thread(WriterLoop) { IsBackground = true, Name = "Fj1459DiagWriter" };
                writer.Start();
                _started = true;

                Emit("RUN_START", "");
            }
        }

        private static void WriterLoop()
        {
            try
            {
                using StreamWriter sw = new StreamWriter(_filePath, append: true, Encoding.UTF8) { AutoFlush = false };
                int sinceFlush = 0;
                foreach (string line in _queue.GetConsumingEnumerable())
                {
                    sw.WriteLine(line);
                    sinceFlush++;
                    if (sinceFlush >= 8)
                    {
                        sw.Flush();
                        sinceFlush = 0;
                    }
                }
                sw.Flush();
            }
            catch
            {
                // Diagnose darf den Netzwerk-Betrieb nie stoeren.
            }
        }

        public static void Emit(string evt, string extra)
        {
            EnsureStarted();
            string line = $"{evt}\trun={_run}\tpid={System.Diagnostics.Process.GetCurrentProcess().Id}\trole={_role}" +
                $"\tutc={DateTime.UtcNow:O}\tticks={Environment.TickCount}" +
                (string.IsNullOrEmpty(extra) ? "" : $"\t{extra}");
            _queue.Add(line);
        }

        // Volle Nutzlast, nicht nur ein Praefix (Brief-Vorgabe) -- Handshake-Pakete in dieser
        // Phase sind klein (Connect/Accept/Ping), kein Grosstext-Risiko.
        public static string Hex(byte[] data, int offset, int length)
        {
            var sb = new StringBuilder(length * 2);
            for (int i = 0; i < length; i++)
                sb.Append(data[offset + i].ToString("x2"));
            return sb.ToString();
        }
    }

    public partial class NetManager
    {
        private const int ReceivePollingTime = 500000; // 0.5 second
        private Socket _udpSocketv4;
        private Socket _udpSocketv6;
        private Thread _receiveThread;
        private IPEndPoint _bufferEndPointv4;
        private IPEndPoint _bufferEndPointv6;
        #if UNITY_SOCKET_FIX
        private PausedSocketFix _pausedSocketFix;
        private bool _useSocketFix;
        #endif
        #if NET8_0_OR_GREATER
        private readonly SocketAddress _sockAddrCacheV4 = new SocketAddress(AddressFamily.InterNetwork);
        private readonly SocketAddress _sockAddrCacheV6 = new SocketAddress(AddressFamily.InterNetworkV6);
        #endif
        private const int SioUdpConnreset = -1744830452; // SIO_UDP_CONNRESET = IOC_IN | IOC_VENDOR | 12
        private static readonly IPAddress MulticastAddressV6 = IPAddress.Parse("ff02::1");
        public static readonly bool IPv6Support;

        // special case in iOS (and possibly android that should be resolved in unity)
        internal bool NotConnected;
        public short Ttl
        {
            get
            {
                #if UNITY_SWITCH
                return 0;
                #else
                return _udpSocketv4.Ttl;
                #endif
            }
            internal set
            {
                #if !UNITY_SWITCH
                _udpSocketv4.Ttl = value;
                #endif
            }
        }

        static NetManager()
        {
            #if DISABLE_IPV6
            IPv6Support = false;
            #elif !UNITY_2019_1_OR_NEWER && !UNITY_2018_4_OR_NEWER && (!UNITY_EDITOR && ENABLE_IL2CPP)
            string version = UnityEngine.Application.unityVersion;
            IPv6Support = Socket.OSSupportsIPv6 && int.Parse(version.Remove(version.IndexOf('f')).Split('.')[2]) >= 6;
            #else
            IPv6Support = Socket.OSSupportsIPv6;
            #endif
        }

        private bool ProcessError(SocketException ex)
        {
            switch (ex.SocketErrorCode)
            {
                case SocketError.NotConnected:
                    NotConnected = true;
                    return true;
                case SocketError.Interrupted:
                case SocketError.NotSocket:
                case SocketError.OperationAborted:
                    return true;
                case SocketError.ConnectionReset:
                case SocketError.MessageSize:
                case SocketError.TimedOut:
                case SocketError.NetworkReset:
                case SocketError.WouldBlock:
                    // NetDebug.Write($"[R]Ignored error: {(int)ex.SocketErrorCode} - {ex}");
                    break;
                default:
                    NetDebug.WriteError($"[R]Error code: {(int)ex.SocketErrorCode} - {ex}");
                    CreateEvent(NetEvent.EType.Error, errorCode: ex.SocketErrorCode);
                    break;
            }
            return false;
        }

        private void ManualReceive(Socket socket, EndPoint bufferEndPoint, int maxReceive)
        {
            // Reading data
            try
            {
                int packetsReceived = 0;
                while (socket.Available > 0)
                {
                    ReceiveFrom(socket, ref bufferEndPoint);
                    packetsReceived++;
                    if (packetsReceived == maxReceive)
                        break;
                }
            }
            catch (SocketException ex)
            {
                ProcessError(ex);
            }
            catch (ObjectDisposedException) { }
            catch (Exception e)
            {
                // protects socket receive thread
                NetDebug.WriteError("[NM] SocketReceiveThread error: " + e);
            }
        }

        private void NativeReceiveLogic()
        {
            IntPtr socketHandle4 = _udpSocketv4.Handle;
            IntPtr socketHandle6 = _udpSocketv6?.Handle ?? IntPtr.Zero;
            byte[] addrBuffer4 = new byte[NativeSocket.IPv4AddrSize];
            byte[] addrBuffer6 = new byte[NativeSocket.IPv6AddrSize];
            IPEndPoint tempEndPoint = new(IPAddress.Any, 0);
            List<Socket> selectReadList = new(2);
            Socket socketv4 = _udpSocketv4;
            Socket socketV6 = _udpSocketv6;
            NetPacket packet = PoolGetPacket(NetConstants.MaxPacketSize);

            while (IsRunning)
            {
                try
                {
                    if (socketV6 == null)
                    {
                        if (NativeReceiveFrom(socketHandle4, addrBuffer4) == false)
                            return;
                        continue;
                    }
                    bool messageReceived = false;
                    if (socketv4.Available != 0 || selectReadList.Contains(socketv4))
                    {
                        if (NativeReceiveFrom(socketHandle4, addrBuffer4) == false)
                            return;
                        messageReceived = true;
                    }
                    if (socketV6.Available != 0 || selectReadList.Contains(socketV6))
                    {
                        if (NativeReceiveFrom(socketHandle6, addrBuffer6) == false)
                            return;
                        messageReceived = true;
                    }

                    selectReadList.Clear();

                    if (messageReceived)
                        continue;

                    selectReadList.Add(socketv4);
                    selectReadList.Add(socketV6);

                    Socket.Select(selectReadList, null, null, ReceivePollingTime);
                }
                catch (SocketException ex)
                {
                    if (ProcessError(ex))
                        return;
                }
                catch (ObjectDisposedException)
                {
                    // socket closed
                    return;
                }
                catch (ThreadAbortException)
                {
                    // thread closed
                    return;
                }
                catch (Exception e)
                {
                    // protects socket receive thread
                    NetDebug.WriteError("[NM] SocketReceiveThread error: " + e);
                }
            }

            bool NativeReceiveFrom(IntPtr s, byte[] address)
            {
                int addrSize = address.Length;
                packet.Size = NativeSocket.RecvFrom(s, packet.RawData, NetConstants.MaxPacketSize, address, ref addrSize);
                if (packet.Size == 0)
                    return true; // socket closed or empty packet

                if (packet.Size == -1)
                {
                    // Linux timeout EAGAIN
                    return ProcessError(new((int)NativeSocket.GetSocketError())) == false;
                }

                // NetDebug.WriteForce($"[R]Received data from {endPoint}, result: {packet.Size}");
                // refresh temp Addr/Port
                short family = (short)((address[1] << 8) | address[0]);
                tempEndPoint.Port = (ushort)((address[2] << 8) | address[3]);
                if ((NativeSocket.UnixMode && family == NativeSocket.AF_INET6) || (!NativeSocket.UnixMode && (AddressFamily)family == AddressFamily.InterNetworkV6))
                {
                    uint scope = unchecked((uint)((address[27] << 24) + (address[26] << 16) + (address[25] << 8) + address[24]));
                    #if NETCOREAPP || NETSTANDARD2_1 || NETSTANDARD2_1_OR_GREATER
                    tempEndPoint.Address = new(new ReadOnlySpan<byte>(address, 8, 16), scope);
                    #else
                    byte[] addrBuffer = new byte[16];
                    Buffer.BlockCopy(address, 8, addrBuffer, 0, 16);
                    tempEndPoint.Address = new(addrBuffer, scope);
                    #endif
                }
                else // IPv4
                {
                    long ipv4Addr = unchecked((uint)((address[4] & 0x000000FF) | ((address[5] << 8) & 0x0000FF00) | ((address[6] << 16) & 0x00FF0000) | (address[7] << 24)));
                    tempEndPoint.Address = new(ipv4Addr);
                }

                if (TryGetPeer(tempEndPoint, out NetPeer peer))
                {
                    // use cached native ep
                    OnMessageReceived(packet, peer);
                }
                else
                {
                    OnMessageReceived(packet, tempEndPoint);
                    tempEndPoint = new(IPAddress.Any, 0);
                }
                packet = PoolGetPacket(NetConstants.MaxPacketSize);
                return true;
            }
        }

        private void ReceiveFrom(Socket s, ref EndPoint bufferEndPoint)
        {
            NetPacket packet = PoolGetPacket(NetConstants.MaxPacketSize);
            Fj1459SocketDiag.Emit("RX_BEGIN", $"socketId={s.Handle}");
            try
            {
                #if NET8_0_OR_GREATER
                var sockAddr = s.AddressFamily == AddressFamily.InterNetwork ? _sockAddrCacheV4 : _sockAddrCacheV6;
                packet.Size = s.ReceiveFrom(packet, SocketFlags.None, sockAddr);
                IPEndPoint from = TryGetPeer(sockAddr, out var peer) ? peer : (IPEndPoint)bufferEndPoint.Create(sockAddr);
                // FJ#1459: Bytes+Absender SOFORT als String kopiert, bevor der Puffer wiederverwendet wird.
                Fj1459SocketDiag.Emit("RX_OK", $"socketId={s.Handle} from={from} len={packet.Size} payload={Fj1459SocketDiag.Hex(packet.RawData, 0, packet.Size)}");
                OnMessageReceived(packet, from);
                #else
                packet.Size = s.ReceiveFrom(packet.RawData, 0, NetConstants.MaxPacketSize, SocketFlags.None, ref bufferEndPoint);
                IPEndPoint from = (IPEndPoint)bufferEndPoint;
                // FJ#1459: Bytes+Absender SOFORT als String kopiert, bevor der Puffer wiederverwendet wird.
                Fj1459SocketDiag.Emit("RX_OK", $"socketId={s.Handle} from={from} len={packet.Size} payload={Fj1459SocketDiag.Hex(packet.RawData, 0, packet.Size)}");
                OnMessageReceived(packet, from);
                #endif
            }
            catch (Exception ex)
            {
                Fj1459SocketDiag.Emit("RX_ERROR", $"socketId={s.Handle} error={ex.GetType().Name}:{ex.Message}");
                throw;
            }
        }

        private void ReceiveLogic()
        {
            EndPoint bufferEndPoint4 = new IPEndPoint(IPAddress.Any, 0);
            EndPoint bufferEndPoint6 = new IPEndPoint(IPAddress.IPv6Any, 0);
            List<Socket> selectReadList = new(2);
            Socket socketv4 = _udpSocketv4;
            Socket socketV6 = _udpSocketv6;

            while (IsRunning)
            {
                // Reading data
                try
                {
                    if (socketV6 == null)
                    {
                        if (socketv4.Available == 0 && !socketv4.Poll(ReceivePollingTime, SelectMode.SelectRead))
                            continue;
                        ReceiveFrom(socketv4, ref bufferEndPoint4);
                    }
                    else
                    {
                        bool messageReceived = false;
                        if (socketv4.Available != 0 || selectReadList.Contains(socketv4))
                        {
                            ReceiveFrom(socketv4, ref bufferEndPoint4);
                            messageReceived = true;
                        }
                        if (socketV6.Available != 0 || selectReadList.Contains(socketV6))
                        {
                            ReceiveFrom(socketV6, ref bufferEndPoint6);
                            messageReceived = true;
                        }

                        selectReadList.Clear();

                        if (messageReceived)
                            continue;

                        selectReadList.Add(socketv4);
                        selectReadList.Add(socketV6);
                        Socket.Select(selectReadList, null, null, ReceivePollingTime);
                    }
                    // NetDebug.Write(NetLogLevel.Trace, $"[R]Received data from {bufferEndPoint}, result: {packet.Size}");
                }
                catch (SocketException ex)
                {
                    if (ProcessError(ex))
                        return;
                }
                catch (ObjectDisposedException)
                {
                    // socket closed
                    return;
                }
                catch (ThreadAbortException)
                {
                    // thread closed
                    return;
                }
                catch (Exception e)
                {
                    // protects socket receive thread
                    NetDebug.WriteError("[NM] SocketReceiveThread error: " + e);
                }
            }
        }

        /// <summary>
        /// Start logic thread and listening on selected port
        /// </summary>
        /// <param name = "addressIPv4">bind to specific ipv4 address</param>
        /// <param name = "addressIPv6">bind to specific ipv6 address</param>
        /// <param name = "port">port to listen</param>
        /// <param name = "manualMode">mode of library</param>
        public bool Start(IPAddress addressIPv4, IPAddress addressIPv6, int port, bool manualMode)
        {
            if (IsRunning && NotConnected == false)
                return false;

            NotConnected = false;
            _manualMode = manualMode;
            UseNativeSockets = UseNativeSockets && NativeSocket.IsSupported;
            _udpSocketv4 = new(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            if (!BindSocket(_udpSocketv4, new(addressIPv4, port)))
                return false;

            LocalPort = ((IPEndPoint)_udpSocketv4.LocalEndPoint).Port;

            // FJ#1488 (rev5 §4.1/§5.3): neue Transport-Epoche VOR dem Thread-Start setzen --
            // Thread.Start() weiter unten stellt die Sichtbarkeit fuer ReceiveThread/LogicThread
            // sicher, ein spaeteres Ereignis/eine spaete Freigabe aus einer VORHERIGEN Epoche
            // (z.B. nach Stop()+Restart()) traegt dadurch nachweisbar die alte Epochennummer.
            _fjEpoch++;
            _fjPendingUnauthenticatedCount = 0;

            #if UNITY_SOCKET_FIX
            if (_useSocketFix && _pausedSocketFix == null)
                _pausedSocketFix = new(this, addressIPv4, addressIPv6, port, manualMode);
            #endif

            IsRunning = true;
            if (_manualMode)
            {
                _bufferEndPointv4 = new(IPAddress.Any, 0);
            }

            // Check IPv6 support
            if (IPv6Support && IPv6Enabled)
            {
                _udpSocketv6 = new(AddressFamily.InterNetworkV6, SocketType.Dgram, ProtocolType.Udp);
                // Use one port for two sockets
                if (BindSocket(_udpSocketv6, new(addressIPv6, LocalPort)))
                {
                    if (_manualMode)
                        _bufferEndPointv6 = new(IPAddress.IPv6Any, 0);
                }
                else
                {
                    _udpSocketv6 = null;
                }
            }

            if (!manualMode)
            {
                ThreadStart ts = ReceiveLogic;
                if (UseNativeSockets)
                    ts = NativeReceiveLogic;
                _receiveThread = new(ts)
                {
                    Name = $"ReceiveThread({LocalPort})",
                    IsBackground = true
                };
                _receiveThread.Start();
                if (_logicThread == null)
                {
                    _logicThread = new(UpdateLogic) { Name = "LogicThread", IsBackground = true };
                    _logicThread.Start();
                }
            }

            return true;
        }

        private bool BindSocket(Socket socket, IPEndPoint ep)
        {
            // Setup socket
            socket.ReceiveTimeout = 500;
            socket.SendTimeout = 500;
            socket.ReceiveBufferSize = NetConstants.SocketBufferSize;
            socket.SendBufferSize = NetConstants.SocketBufferSize;
            socket.Blocking = true;

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                try
                {
                    socket.IOControl(SioUdpConnreset, new byte[] { 0 }, null);
                }
                catch
                {
                    // ignored
                }
            }

            try
            {
                socket.ExclusiveAddressUse = !ReuseAddress;
                socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, ReuseAddress);
                socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.DontRoute, DontRoute);
            }
            catch
            {
                // Unity with IL2CPP throws an exception here, it doesn't matter in most cases so just ignore it
            }
            if (ep.AddressFamily == AddressFamily.InterNetwork)
            {
                Ttl = NetConstants.SocketTTL;

                try
                {
                    socket.EnableBroadcast = true;
                }
                catch (SocketException e)
                {
                    NetDebug.WriteError($"[B]Broadcast error: {e.SocketErrorCode}");
                }

                if (!RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
                {
                    try
                    {
                        socket.DontFragment = true;
                    }
                    catch (SocketException e)
                    {
                        NetDebug.WriteError($"[B]DontFragment error: {e.SocketErrorCode}");
                    }
                }
            }
            // Bind
            try
            {
                socket.Bind(ep);
                NetDebug.Write(NetLogLevel.Trace, $"[B]Successfully binded to port: {((IPEndPoint)socket.LocalEndPoint).Port}, AF: {socket.AddressFamily}");
                Fj1459SocketDiag.Emit("BIND_OK", $"socketId={socket.Handle} local={socket.LocalEndPoint} af={socket.AddressFamily}");

                // join multicast
                if (ep.AddressFamily == AddressFamily.InterNetworkV6)
                {
                    try
                    {
                        #if !UNITY_SOCKET_FIX
                        socket.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.AddMembership, new IPv6MulticastOption(MulticastAddressV6));
                        #endif
                    }
                    catch (Exception)
                    {
                        // Unity3d throws exception - ignored
                    }
                }
            }
            catch (SocketException bindException)
            {
                switch (bindException.SocketErrorCode)
                {
                    // IPv6 bind fix
                    case SocketError.AddressAlreadyInUse:
                        if (socket.AddressFamily == AddressFamily.InterNetworkV6)
                        {
                            try
                            {
                                // Set IPv6Only
                                socket.DualMode = false;
                                socket.Bind(ep);
                            }
                            catch (SocketException ex)
                            {
                                // because its fixed in 2018_3
                                NetDebug.WriteError($"[B]Bind exception: {ex}, errorCode: {ex.SocketErrorCode}");
                                return false;
                            }
                            return true;
                        }
                        break;
                    // hack for iOS (Unity3D)
                    case SocketError.AddressFamilyNotSupported:
                        return true;
                }
                NetDebug.WriteError($"[B]Bind exception: {bindException}, errorCode: {bindException.SocketErrorCode}");
                return false;
            }
            return true;
        }

        internal int SendRawAndRecycle(NetPacket packet, IPEndPoint remoteEndPoint)
        {
            int result = SendRaw(packet.RawData, 0, packet.Size, remoteEndPoint);
            PoolRecycle(packet);
            return result;
        }

        internal int SendRaw(NetPacket packet, IPEndPoint remoteEndPoint)
        {
            return SendRaw(packet.RawData, 0, packet.Size, remoteEndPoint);
        }

        internal int SendRaw(byte[] message, int start, int length, IPEndPoint remoteEndPoint)
        {
            if (!IsRunning)
                return 0;

            NetPacket expandedPacket = null;
            if (_extraPacketLayer != null)
            {
                expandedPacket = PoolGetPacket(length + _extraPacketLayer.ExtraPacketSizeForLayer);
                Buffer.BlockCopy(message, start, expandedPacket.RawData, 0, length);
                start = 0;
                _extraPacketLayer.ProcessOutBoundPacket(ref remoteEndPoint, ref expandedPacket.RawData, ref start, ref length);
                message = expandedPacket.RawData;
            }

            Socket socket = _udpSocketv4;
            if (remoteEndPoint.AddressFamily == AddressFamily.InterNetworkV6 && IPv6Support)
            {
                socket = _udpSocketv6;
                if (socket == null)
                    return 0;
            }

            int result;
            Fj1459SocketDiag.Emit("TX_BEGIN", $"socketId={socket.Handle} to={remoteEndPoint} len={length} payload={Fj1459SocketDiag.Hex(message, start, length)}");
            try
            {
                if (UseNativeSockets && remoteEndPoint is NetPeer peer)
                {
                    unsafe
                    {
                        fixed (byte* dataWithOffset = &message[start])
                        {
                            result = NativeSocket.SendTo(socket.Handle, dataWithOffset, length, peer.NativeAddress, peer.NativeAddress.Length);
                        }
                    }
                    if (result == -1)
                        throw NativeSocket.GetSocketException();
                }
                else
                {
                    #if NET8_0_OR_GREATER
                    result = socket.SendTo(new ReadOnlySpan<byte>(message, start, length), SocketFlags.None, remoteEndPoint.Serialize());
                    #else
                    result = socket.SendTo(message, start, length, SocketFlags.None, remoteEndPoint);
                    #endif
                }
                // NetDebug.WriteForce("[S]Send packet to {0}, result: {1}", remoteEndPoint, result);
                Fj1459SocketDiag.Emit("TX_OK", $"socketId={socket.Handle} to={remoteEndPoint} result={result}");
            }
            catch (SocketException ex)
            {
                Fj1459SocketDiag.Emit("TX_ERROR", $"socketId={socket.Handle} to={remoteEndPoint} error={ex.SocketErrorCode}");
                switch (ex.SocketErrorCode)
                {
                    case SocketError.NoBufferSpaceAvailable:
                    case SocketError.Interrupted:
                        return 0;
                    case SocketError.MessageSize:
                        NetDebug.Write(NetLogLevel.Trace, $"[SRD] 10040, datalen: {length}");
                        return 0;

                    case SocketError.HostUnreachable:
                    case SocketError.NetworkUnreachable:
                        if (DisconnectOnUnreachable && remoteEndPoint is NetPeer peer)
                        {
                            DisconnectPeerForce(peer, ex.SocketErrorCode == SocketError.HostUnreachable ? DisconnectReason.HostUnreachable : DisconnectReason.NetworkUnreachable, ex.SocketErrorCode, null);
                        }

                        CreateEvent(NetEvent.EType.Error, remoteEndPoint: remoteEndPoint, errorCode: ex.SocketErrorCode);
                        return -1;

                    case SocketError.Shutdown:
                        CreateEvent(NetEvent.EType.Error, remoteEndPoint: remoteEndPoint, errorCode: ex.SocketErrorCode);
                        return -1;

                    default:
                        NetDebug.WriteError($"[S] {ex}");
                        return -1;
                }
            }
            catch (Exception ex)
            {
                Fj1459SocketDiag.Emit("TX_ERROR", $"socketId={socket.Handle} to={remoteEndPoint} error={ex.GetType().Name}:{ex.Message}");
                NetDebug.WriteError($"[S] {ex}");
                return 0;
            }
            finally
            {
                if (expandedPacket != null)
                    PoolRecycle(expandedPacket);
            }

            if (result <= 0)
                return 0;

            if (EnableStatistics)
            {
                Statistics.IncrementPacketsSent();
                Statistics.AddBytesSent(length);
            }

            return result;
        }

        public bool SendBroadcast(NetDataWriter writer, int port)
        {
            return SendBroadcast(writer.Data, 0, writer.Length, port);
        }

        public bool SendBroadcast(byte[] data, int port)
        {
            return SendBroadcast(data, 0, data.Length, port);
        }

        public bool SendBroadcast(byte[] data, int start, int length, int port)
        {
            if (!IsRunning)
                return false;

            NetPacket packet;
            int packetSize;
            if (_extraPacketLayer != null)
            {
                int headerSize = NetPacket.GetHeaderSize(PacketProperty.Broadcast);
                packet = PoolGetPacket(headerSize + length + _extraPacketLayer.ExtraPacketSizeForLayer);
                packet.Property = PacketProperty.Broadcast;
                Buffer.BlockCopy(data, start, packet.RawData, headerSize, length);
                int checksumComputeStart = 0;
                packetSize = length + headerSize;
                IPEndPoint emptyEp = null;
                _extraPacketLayer.ProcessOutBoundPacket(ref emptyEp, ref packet.RawData, ref checksumComputeStart, ref packetSize);
            }
            else
            {
                packet = PoolGetWithData(PacketProperty.Broadcast, data, start, length);
                packetSize = packet.Size;
            }

            bool broadcastSuccess = false;
            bool multicastSuccess = false;
            try
            {
                broadcastSuccess = _udpSocketv4.SendTo(packet.RawData, 0, packetSize, SocketFlags.None, new IPEndPoint(IPAddress.Broadcast, port)) > 0;

                if (_udpSocketv6 != null)
                {
                    multicastSuccess = _udpSocketv6.SendTo(packet.RawData, 0, packetSize, SocketFlags.None, new IPEndPoint(MulticastAddressV6, port)) > 0;
                }
            }
            catch (SocketException ex)
            {
                if (ex.SocketErrorCode == SocketError.HostUnreachable)
                    return broadcastSuccess;
                NetDebug.WriteError($"[S][MCAST] {ex}");
                return broadcastSuccess;
            }
            catch (Exception ex)
            {
                NetDebug.WriteError($"[S][MCAST] {ex}");
                return broadcastSuccess;
            }
            finally
            {
                PoolRecycle(packet);
            }

            return broadcastSuccess || multicastSuccess;
        }

        private void CloseSocket()
        {
            Fj1459SocketDiag.Emit("SOCKET_CLOSE", $"v4={_udpSocketv4?.Handle} v6={_udpSocketv6?.Handle}");
            IsRunning = false;
            _udpSocketv4?.Close();
            _udpSocketv6?.Close();
            _udpSocketv4 = null;
            _udpSocketv6 = null;
            if (_receiveThread != null && _receiveThread != Thread.CurrentThread)
                _receiveThread.Join();
            _receiveThread = null;
        }
    }
}