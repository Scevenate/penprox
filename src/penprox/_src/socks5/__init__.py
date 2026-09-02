from ..sdk import *

logger = getLogger(__name__)

class SOCKS5ServerNode(ProxyNode):
    """
    SOCKS5 server. Only supports `CONNECT`; Does not support authentication.

    Does not bother DNS; SOCK5 `DST.ADDR` type is faithfully translated into
    `ProxyTCPSession.host`.

    Has a `ProxyTCPPacket` upstream and a `ProxyTCPMessage` downstream.
    """
    # Note: We also dont support UDP fragmentation or domain name source limiting
    # Who uses these features?

    _version = "0.1.0"
    __slots__ = (
        "_boundary",
        "_connections",
        "_controller",
        "_edges",
        "_inverse",
        "_running",
        "_sessions",
        "_signal"
    )

    @dataclass(eq=False, slots=True)
    class _SOCKS5ServerNewConnection:
        # SOCKS5 connection is always bound to its unstream TCP connection
        # This makes this structure conceptually a wrapper around the TCP connection
        tcp: ProxyTCPConnection
        # Waiting for client hello or request
        established: bool
        # Just for fragmented client hello / request, very very very light weight
        buffer: bytes

    @dataclass(eq=False, slots=True)
    class _SOCKS5ServerConnectConnection:
        tcp: ProxyTCPConnection
        # Destination proxy
        session: ProxyTCPSession

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
            ProxyTCPConnection,
              SOCKS5ServerNode._SOCKS5ServerNewConnection
            | SOCKS5ServerNode._SOCKS5ServerConnectConnection
        ] = {}
        # Inverse lookup
        self._inverse: dict[
            ProxyTCPSession,
              SOCKS5ServerNode._SOCKS5ServerNewConnection
            | SOCKS5ServerNode._SOCKS5ServerConnectConnection
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
                            connection = SOCKS5ServerNode._SOCKS5ServerNewConnection(
                                packet.bound, False, b""
                            )
                            self._connections[packet.bound] = connection
                        else:
                            connection = self._connections.get(packet.bound)
                            if not connection:
                                if packet.flag != "FIN":
                                    logger.debug("SOCKS5ServerNode: Received unknown connection from upstream, rejecting")
                                    self._reject(0, packet)
                                upstream = create_task(self._edges[0][0].get()) # type: ignore
                                continue
                        if packet.flag == "FIN":
                            if isinstance(connection, SOCKS5ServerNode._SOCKS5ServerConnectConnection):
                                self._forward(1, packet)
                                self._inverse.pop(connection.session, None)
                            self._connections.pop(connection.tcp, None)
                            if self._signal == "SIGTERM" and self._boundary and not self._connections:
                                self._running = False
                                return
                        # Processing
                        if isinstance(connection, SOCKS5ServerNode._SOCKS5ServerNewConnection):
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
                                    logger.debug("SOCKS5ServerNode: Invalid client hello, closing")
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
                                connection = SOCKS5ServerNode._SOCKS5ServerConnectConnection(connection.tcp, session)
                                self._connections[connection.tcp] = connection
                                self._inverse[session] = connection
                        else: # connection: SOCKS5ServerNode._SOCKS5ServerConnectConnection
                            self._send(1, connection.session, packet.data)
                        upstream = create_task(self._edges[0][0].get()) # type: ignore
                        continue
                    case _ if task is downstream:
                        message = cast(ProxyTCPMessage, task.result())
                        connection = self._inverse.get(message.bound)
                        if not isinstance(connection, SOCKS5ServerNode._SOCKS5ServerConnectConnection):
                            if message.flag != "FIN":
                                logger.debug("SOCKS5ServerNode: Received downstream message with unknown session")
                                self._reject(1, message)
                            downstream = create_task(self._edges[1][0].get()) # type: ignore
                            continue
                        self._send(0, connection.tcp, message.data)
                        if message.flag == "FIN":
                            self._connections.pop(connection.tcp, None)
                            self._inverse.pop(connection.session, None)
                            self._close(0, connection.tcp)
                            if self._signal == "SIGTERM" and self._boundary and not self._connections:
                                self._running = False
                                return
                        downstream = create_task(self._edges[1][0].get()) # type: ignore
                        continue
                    case _: # controller:
                        signal= cast(ProxySignal, task.result())
                        logger.info(f"SOCKS5ServerNode: Received {signal} signal")
                        if signal == "SIGKILL":
                            self._running = False
                            return
                        if signal == "SIGTERM":
                            if not self._connections:
                                self._running = False
                                return
                            self._signal = "SIGTERM"
                        controller = create_task(self._controller.get())
                        continue
                        



                                


                                    

                            





class SOCKS5ClientNode(ProxyNode):
    ...

