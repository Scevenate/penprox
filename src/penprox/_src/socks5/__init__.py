from ..sdk import *

logger = getLogger(__name__)

@dataclass(eq=False, slots=True)
class SOCKS5ServerNewConnection:
    # SOCKS5 connection is always bound to its unstream TCP connection
    # This makes this structure conceptually a wrapper around the TCP connection
    tcp: ProxyTCPConnection
    # Waiting for client hello or request
    established: bool
    # Fragmented client hello / request
    buffer: bytes

@dataclass(eq=False, slots=True)
class SOCKS5ClientNewConnection:
    tcp: ProxyTCPConnection
    # Destination proxy
    session: ProxyTCPSession
    # Waiting for server hello or response
    established: bool
    # Fragmented server hello / reply
    buffer: bytes
    # Queued proxy data
    data: list[bytes]

@dataclass(eq=False, slots=True)
class SOCKS5ConnectConnection:
    tcp: ProxyTCPConnection
    session: ProxyTCPSession

class SOCKS5ServerNode(ProxyNode):
    """
    SOCKS5 server. Only supports `CONNECT`; Does not support authentication.

    Does not bother DNS; SOCK5 `DST.ADDR` type is faithfully translated into
    `ProxyTCPSession.host`.

    Has a `ProxyTCPPacket` upstream and a `ProxyTCPMessage` downstream.
    """

    _version = "0.1.0"
    __slots__ = (
        "_boundary",
        "_connections",
        "_controller",
        "_edges",
        "_inverse",
        "_running",
        "_signal"
    )

    def __init__(self, /,
        boundary: bool=False):
        self._controller: Queue[ProxySignal] = Queue()
        self._edges: list[ProxyEdgeEnd | None] = [None, None]
        self._boundary: bool = boundary
        self._running: bool = False

    async def run(self) -> ProxySignal | None:
        """
        Run `SOCKS5ServerNode`.
        """
        if self._running:
            logger.critical("Attempted to run a running SOCKS5ServerNode")
            return "SIGKILL"
        if len(self._edges) != 2 or not all(self._edges):
            logger.critical("Running improperly connected SOCKS5ServerNode")
            return "SIGKILL"
        logger.info("Running SOCKS5ServerNode...")
        self._running = True
        # Primary connection mapping
        self._connections: dict[
            ProxyTCPConnection, SOCKS5ServerNewConnection | SOCKS5ConnectConnection
        ] = {}
        # Inverse lookup
        self._inverse: dict[
            ProxyTCPSession, SOCKS5ServerNewConnection | SOCKS5ConnectConnection
        ] = {}
        self._signal: ProxySignal | None = None
        while not self._controller.empty():
            self._controller.get_nowait()

        controller = create_task(self._controller.get())
        upstream = create_task(self._edges[0][0].get()) # type: ignore
        downstream = create_task(self._edges[1][0].get()) # type: ignore
        while True:
            done, _ = await asyncio.wait(
                (controller, upstream, downstream),
                return_when=asyncio.FIRST_COMPLETED
            )
            for task in done:
                match task:
                    case _ if task is upstream:
                        packet = cast(ProxyTCPPacket, upstream.result())
                        # Get connection
                        if packet.flag == "SYN":
                            if self._signal == "SIGTERM" and self._boundary:
                                self._reject(0, packet)
                                upstream = create_task(self._edges[0][0].get()) # type: ignore
                                continue
                            connection = SOCKS5ServerNewConnection(
                                packet.bound, False, b""
                            )
                            self._connections[packet.bound] = connection
                        else:
                            connection = self._connections.get(packet.bound)
                            if not connection:
                                self._reject(0, packet)
                                upstream = create_task(self._edges[0][0].get()) # type: ignore
                                continue
                        # FIN processing
                        if packet.flag == "FIN":
                            logger.debug(f"SOCKS5ServerNode: Connection from {connection.tcp.host} closed from client")
                            if isinstance(connection, SOCKS5ConnectConnection):
                                if packet.data:
                                    self._send(1, connection.session, packet.data)
                                self._inverse.pop(connection.session, None)
                                self._close(1, connection.session)
                            self._connections.pop(connection.tcp, None)
                            if self._signal == "SIGTERM" and not self._connections:
                                self._running = False
                                logger.info("SOCKS5ServerNode: All connection served, quitting (SIGTERM)")
                                return
                            upstream = create_task(self._edges[0][0].get()) # type: ignore
                            continue
                        # Processing
                        if isinstance(connection, SOCKS5ServerNewConnection):
                            if not connection.established: # Waiting for client hello
                                connection.buffer += packet.data
                                buffer = connection.buffer
                                if len(buffer) < 2 or len(buffer) < buffer[1] + 2:
                                    upstream = create_task(self._edges[0][0].get()) # type: ignore
                                    continue
                                if  buffer[0] != 5 or \
                                    buffer[1] == 0 or \
                                    len(buffer) > buffer[1] + 2 or \
                                    all(buffer[2:]):
                                    logger.debug(f"SOCKS5ServerNode: Invalid client hello from {connection.tcp.host}, closing")
                                    self._connections.pop(connection.tcp, None)
                                    self._close(0, connection.tcp)
                                    upstream = create_task(self._edges[0][0].get()) # type: ignore
                                    continue
                                self._send(0, connection.tcp, b"\x05\x00")
                                connection.buffer = b""
                                connection.established = True
                            else: # Waiting for request
                                connection.buffer += packet.data
                                buffer = connection.buffer
                                if len(connection.buffer) < 6 or \
                                    buffer[3] == 1 and len(buffer) < 10 or \
                                    buffer[3] == 3 and len(buffer) < buffer[4] + 7 or \
                                    buffer[3] == 4 and len(buffer) < 22:
                                    upstream = create_task(self._edges[0][0].get()) # type: ignore
                                    continue
                                if  buffer[3] == 1 and len(buffer) > 10 or \
                                    buffer[3] == 3 and len(buffer) > buffer[4] + 7 or \
                                    buffer[3] == 4 and len(buffer) > 22:
                                    logger.debug("SOCKS5ServerNode: Request too long")
                                    self._connections.pop(connection.tcp, None)
                                    self._close(0, connection.tcp)
                                    upstream = create_task(self._edges[0][0].get()) # type: ignore
                                    continue
                                if  buffer[0] != 5 or \
                                    buffer[1] not in (1, 2, 3) or \
                                    buffer[2] != 0 or \
                                    buffer[3] not in (1, 3, 4):
                                    logger.debug("SOCKS5ServerNode: Invalid request, closing")
                                    self._connections.pop(connection.tcp, None)
                                    self._close(0, connection.tcp)
                                    upstream = create_task(self._edges[0][0].get()) # type: ignore
                                    continue
                                if buffer[1] != 1:
                                    logger.debug("SOCKS5ServerNode: Unsupported command")
                                    self._send(0, connection.tcp, b"\x05\x07\x00\x03\x00\x00\x00")
                                    self._connections.pop(connection.tcp, None)
                                    self._close(0, connection.tcp)
                                    upstream = create_task(self._edges[0][0].get()) # type: ignore
                                    continue
                                match buffer[3]: # DST.ADDR
                                    case 1: # IPv4
                                        host = IPv4Address(buffer[4:-2])
                                    case 3: # Domain name
                                        try:
                                            host = buffer[5: -2].decode("idna")
                                        except UnicodeDecodeError:
                                            logger.debug("SOCKS5ServerNode: Invalid DST.ADDR")
                                            self._send(0, connection.tcp, b"\x05\x04\x00\x03\x00\x00\x00")
                                            self._connections.pop(connection.tcp, None)
                                            self._close(0, connection.tcp)
                                            upstream = create_task(self._edges[0][0].get()) # type: ignore
                                            continue
                                    case 4: # IPv6
                                        host = IPv6Address(buffer[4: -2])
                                    case _: # Never
                                        raise ValueError("SOCKS5ServerNode: Never (CONNECT ATYP)")
                                self._send(0, connection.tcp, b"\x05\x00\x00\x03\x00\x00\x00")
                                session = ProxyTCPSession(host, int.from_bytes(buffer[-2:], byteorder="big"))
                                self._open(1, session)
                                connection = SOCKS5ConnectConnection(connection.tcp, session)
                                self._connections[connection.tcp] = connection
                                self._inverse[session] = connection
                                logger.debug(f"SOCKS5ServerNode: Received connection request {connection}")
                        else: # SOCKS5ConnectConnection
                            self._send(1, connection.session, packet.data)
                        upstream = create_task(self._edges[0][0].get()) # type: ignore
                        continue
                    case _ if task is downstream:
                        message = cast(ProxyTCPMessage, task.result())
                        connection = self._inverse.get(message.bound)
                        if not isinstance(connection, SOCKS5ConnectConnection):
                            self._reject(1, message)
                            downstream = create_task(self._edges[1][0].get()) # type: ignore
                            continue
                        self._send(0, connection.tcp, message.data)
                        if message.flag == "FIN":
                            self._connections.pop(connection.tcp, None)
                            self._inverse.pop(connection.session, None)
                            self._close(0, connection.tcp)
                            logger.debug(f"SOCKS5Server: {connection.tcp} closed from downstream")
                            if self._signal == "SIGTERM" and not self._connections:
                                self._running = False
                                logger.info("SOCKS5ServerNode: All connection served, quitting (SIGTERM)")
                                return
                        downstream = create_task(self._edges[1][0].get()) # type: ignore
                        continue
                    case _: # controller
                        signal = cast(ProxySignal, task.result())
                        logger.info(f"SOCKS5ServerNode: Received {signal} signal")
                        if signal == "SIGKILL":
                            self._running = False
                            return
                        if signal == "SIGTERM":
                            if not self._connections:
                                logger.info("SOCKS5ServerNode: All connection served, quitting (SIGTERM)")
                                self._running = False
                                return
                            self._signal = "SIGTERM"
                        controller = create_task(self._controller.get())
                        continue

class SOCKS5ClientNode(ProxyNode):
    """
    SOCKS5 client. Only supports `CONNECT`; Does not support authentication.

    Must provide remote SOCKS5 server address. Use python native IP represenation
    or a string domain, which is resolved using system DNS at construct time.

    Does not bother runtime DNS; `ProxyTCPSession.host` type is faithfully
    translated into SOCK5 `DST.ADDR`.

    Has a `ProxyTCPMessage` upstream and a `ProxyTCPPacket` downstream.
    """

    _version = "0.1.0"
    __slots__ = (
        "_boundary",
        "_connections",
        "_controller",
        "_edges",
        "_inverse",
        "_remote",
        "_running",
        "_signal"
    )

    def __init__(
        self,
        remote: tuple[IPv4Address | IPv6Address | str, int],
        /,
        boundary: bool=False
    ):
        if isinstance(remote[0], str):
            remote = (waitDNS(remote[0]), remote[1])
        self._remote: tuple[IPv4Address | IPv6Address, int] = cast(
            tuple[IPv4Address | IPv6Address, int], remote
        )
        self._controller: Queue[ProxySignal] = Queue()
        self._edges: list[ProxyEdgeEnd | None] = [None, None]
        self._boundary: bool = boundary
        self._running: bool = False

    async def run(self) -> ProxySignal | None:
        """
        Run `SOCKS5ClientNode`.
        """
        if self._running:
            logger.critical("Attempted to run a running SOCKS5ClientNode")
            return "SIGKILL"
        if len(self._edges) != 2 or not all(self._edges):
            logger.critical("Running improperly connected SOCKS5ClientNode")
            return "SIGKILL"
        logger.info("Running SOCKS5ClientNode...")
        self._running = True
        # Primary session mapping
        self._connections: dict[
            ProxyTCPSession, SOCKS5ClientNewConnection | SOCKS5ConnectConnection
        ] = {}
        # Inverse lookup
        self._inverse: dict[
            ProxyTCPConnection, SOCKS5ClientNewConnection | SOCKS5ConnectConnection
        ] = {}
        self._signal: ProxySignal | None = None
        while not self._controller.empty():
            self._controller.get_nowait()

        controller = create_task(self._controller.get())
        upstream = create_task(self._edges[0][0].get()) # type: ignore
        downstream = create_task(self._edges[1][0].get()) # type: ignore
        while True:
            done, _ = await asyncio.wait(
                (controller, upstream, downstream),
                return_when=asyncio.FIRST_COMPLETED
            )
            for task in done:
                match task:
                    case _ if task is upstream:
                        message = cast(ProxyTCPMessage, upstream.result())
                        # Get connection
                        if message.flag == "SYN":
                            if self._signal == "SIGTERM" and self._boundary:
                                self._reject(0, message)
                                upstream = create_task(self._edges[0][0].get()) # type: ignore
                                continue
                            connection = SOCKS5ClientNewConnection(
                                ProxyTCPConnection(
                                    *cast(tuple[IPv4Address | IPv6Address, int], self._remote)
                                ),
                                message.bound,
                                False,
                                b"",
                                [message.data] if message.data else []
                            )
                            self._connections[message.bound] = connection
                            self._inverse[connection.tcp] = connection
                            # Send client hello
                            self._open(1, connection.tcp)
                            self._send(1, connection.tcp, b"\x05\x01\x00")
                        else:
                            connection = self._connections.get(message.bound)
                            if not connection:
                                self._reject(0, message)
                                upstream = create_task(self._edges[0][0].get()) # type: ignore
                                continue
                        # FIN processing
                        if message.flag == "FIN":
                            logger.debug(f"SOCKS5ClientNode: Session to {message.bound.host} closed from upstream")
                            if isinstance(connection, SOCKS5ConnectConnection) and message.data:
                                self._send(1, connection.tcp, message.data)
                            self._close(1, connection.tcp)
                            self._connections.pop(message.bound, None)
                            self._inverse.pop(connection.tcp, None)
                            if self._signal == "SIGTERM" and not self._connections:
                                self._running = False
                                logger.info("SOCKS5ClientNode: All sessions served, quitting (SIGTERM)")
                                return
                            upstream = create_task(self._edges[0][0].get()) # type: ignore
                            continue
                        # Processing
                        if isinstance(connection, SOCKS5ClientNewConnection):
                            connection.data.append(message.data)
                        else: # SOCKS5ConnectConnection
                            self._send(1, connection.tcp, message.data)
                        upstream = create_task(self._edges[0][0].get()) # type: ignore
                        continue
                    case _ if task is downstream:
                        packet = cast(ProxyTCPPacket, task.result())
                        # Get connection
                        connection = self._inverse.get(packet.bound)
                        if not connection:
                            self._reject(1, packet)
                            downstream = create_task(self._edges[1][0].get()) # type: ignore
                            continue
                        # FIN processing
                        if packet.flag == "FIN":
                            logger.debug(f"SOCKS5ClientNode: Session to {connection.session.host} closed from downstream")
                            if isinstance(connection, SOCKS5ConnectConnection) and packet.data:
                                self._send(0, connection.session, packet.data)
                            self._close(0, connection.session)
                            self._connections.pop(connection.session, None)
                            self._inverse.pop(connection.tcp, None)
                            if self._signal == "SIGTERM" and not self._connections:
                                self._running = False
                                logger.info("SOCKS5ClientNode: All sessions served, quitting (SIGTERM)")
                                return
                            downstream = create_task(self._edges[1][0].get()) # type: ignore
                            continue
                        # Processing
                        if isinstance(connection, SOCKS5ClientNewConnection):
                            if not connection.established: # Waiting for server hello
                                connection.buffer += packet.data
                                buffer = connection.buffer
                                if len(buffer) < 2:
                                    downstream = create_task(self._edges[1][0].get()) # type: ignore
                                    continue
                                if len(buffer) > 2 or buffer != b"\x05\x00":
                                    logger.debug("SOCKS5ClientNode: Invalid server hello from server, closing")
                                    self._connections.pop(connection.session, None)
                                    self._inverse.pop(connection.tcp, None)
                                    self._close(0, connection.session)
                                    self._close(1, connection.tcp)
                                    downstream = create_task(self._edges[1][0].get()) # type: ignore
                                    continue
                                # Request construction
                                dst = connection.session.host
                                request = b"\x05\x01\x00"
                                if isinstance(dst, IPv4Address):
                                    request += b"\x01" + dst.packed
                                elif isinstance(dst, IPv6Address):
                                    request += b"\x04" + dst.packed
                                else:
                                    domain = dst.encode("idna")
                                    # A domain is at most 255 bytes
                                    request += b"\x03" + len(domain).to_bytes(length=1, byteorder="big") + domain
                                print(1)
                                request += connection.session.port.to_bytes(length=2, byteorder="big")
                                print(2)
                                self._send(1, connection.tcp, request)
                                connection.buffer = b""
                                connection.established = True
                            else: # Waiting for reply
                                connection.buffer += packet.data
                                buffer = connection.buffer
                                if len(connection.buffer) < 4:
                                    downstream = create_task(self._edges[1][0].get()) # type: ignore
                                    continue
                                if  buffer[3] == 1 and len(buffer) > 10 or \
                                    buffer[3] == 3 and len(buffer) > buffer[4] + 7 or \
                                    buffer[3] == 4 and len(buffer) > 22:
                                    logger.debug("SOCKS5ClientNode: Reply too long")
                                    self._connections.pop(connection.session, None)
                                    self._inverse.pop(connection.tcp, None)
                                    self._close(0, connection.session)
                                    self._close(1, connection.tcp)
                                    downstream = create_task(self._edges[1][0].get()) # type: ignore
                                    continue
                                if  buffer[:3] != b"\x05\x00\x00":
                                    logger.debug(f"SOCKS5ClientNode: Server declined session to {connection.session.host}, closing")
                                    self._connections.pop(connection.session, None)
                                    self._inverse.pop(connection.tcp, None)
                                    self._close(0, connection.session)
                                    self._close(1, connection.tcp)
                                    upstream = create_task(self._edges[0][0].get()) # type: ignore
                                    continue
                                # success
                                for data in connection.data:
                                    self._send(1, connection.tcp, data)
                                connection = SOCKS5ConnectConnection(connection.tcp, connection.session)
                                self._connections[connection.session] = connection
                                self._inverse[connection.tcp] = connection
                                logger.debug(f"SOCKS5ClientNode: Established session for dst {connection.session.host}")
                        else: # SOCKS5ConnectConnection
                            self._send(0, connection.session, packet.data)
                        downstream = create_task(self._edges[1][0].get()) # type: ignore
                        continue
                    case _: # controller
                        signal = cast(ProxySignal, task.result())
                        logger.info(f"SOCKS5ClientNode: Received {signal} signal")
                        if signal == "SIGKILL":
                            self._running = False
                            return
                        if signal == "SIGTERM":
                            if not self._connections:
                                logger.info("SOCKS5ClientNode: All connection served, quitting (SIGTERM)")
                                self._running = False
                                return
                            self._signal = "SIGTERM"
                        controller = create_task(self._controller.get())
                        continue

