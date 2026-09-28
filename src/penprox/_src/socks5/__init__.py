from ..dns import waitDNS
from ..sdk import *


@id_hash
@dataclass(eq=False, slots=True)
class SOCKS5ServerNewConnection:
    # Waiting for client hello or request
    established: bool
    # Fragmented client hello / request
    buffer: bytes

@id_hash
@dataclass(eq=False, slots=True)
class SOCKS5ClientNewConnection:
    # Waiting for server hello or response
    established: bool
    # Fragmented server hello / reply
    buffer: bytes
    # Queued proxy data
    data: list[bytes]

@id_hash
@dataclass(eq=False, slots=True)
class SOCKS5ConnectConnection:
    pass

class SOCKS5ServerNode(Node):
    """
    SOCKS5 server. Only supports `CONNECT`; Does not support authentication.

    Does not bother DNS; SOCK5 `DST.ADDR` type is faithfully translated into
    `TCPSession.host`.

    Has a `TCPPacket` upstream and a `TCPMessage` downstream.
    """
    _edges = 2
    _upstreams = (0,)
    _downstreams = (1,)
    __slots__ = (
        "_connections",
    )
    async def _run(self) -> Signal | None:
        self._connections: BidictAD[
            TCPConnection, TCPSession, SOCKS5ServerNewConnection | SOCKS5ConnectConnection
        ] = BidictAD()

    async def _onGet(self, edge: int, obj: TCPPacket | UDPPacket | TCPMessage | UDPMessage) -> Signal | None:
        match edge:
            case 0:
                packet = cast(TCPPacket, obj)
                # SYN
                if packet.payload == "SYN":
                    # ADC implies that
                    ADC = SOCKS5ServerNewConnection(False, b"")
                    session = TCPSession("", 0)
                    self._connections.set(packet.bound, session, ADC)
                    return
                # Get stuff
                connection = packet.bound
                ADC = self._connections.xgetd(connection)
                if not ADC:
                    if packet.payload != "FIN":
                        self._reject(0, packet)
                    return
                session = cast(TCPSession, self._connections.xgety(connection))
                # FIN
                if packet.payload == "FIN":
                    logger.debug(f"SOCKS5ServerNode: Connection from {connection.host} closed from client")
                    if isinstance(ADC, SOCKS5ConnectConnection):
                        self._close(1, session)
                    self._connections.xdiscard(connection)
                    return
                # Data
                if isinstance(ADC, SOCKS5ServerNewConnection):
                    if not ADC.established: # Waiting for client hello
                        ADC.buffer += packet.payload
                        buffer = ADC.buffer
                        if len(buffer) < 2 or len(buffer) < buffer[1] + 2:
                            return
                        if  buffer[0] != 5 or \
                            buffer[1] == 0 or \
                            len(buffer) > buffer[1] + 2 or \
                            all(buffer[2:]):
                            logger.debug(f"SOCKS5ServerNode: Invalid client hello from {connection.host}, closing")
                            self._connections.xdiscard(connection)
                            self._close(0, connection)
                            return
                        self._send(0, connection, b"\x05\x00")
                        ADC.buffer = b""
                        ADC.established = True
                    else: # Waiting for request
                        ADC.buffer += packet.payload
                        buffer = ADC.buffer
                        if len(ADC.buffer) < 6 or \
                            buffer[3] == 1 and len(buffer) < 10 or \
                            buffer[3] == 3 and len(buffer) < buffer[4] + 7 or \
                            buffer[3] == 4 and len(buffer) < 22:
                            return
                        if  buffer[3] == 1 and len(buffer) > 10 or \
                            buffer[3] == 3 and len(buffer) > buffer[4] + 7 or \
                            buffer[3] == 4 and len(buffer) > 22:
                            logger.debug("SOCKS5ServerNode: Request too long")
                            self._connections.xdiscard(connection)
                            self._close(0, connection)
                            return
                        if  buffer[0] != 5 or \
                            buffer[1] not in (1, 2, 3) or \
                            buffer[2] != 0 or \
                            buffer[3] not in (1, 3, 4):
                            logger.debug("SOCKS5ServerNode: Invalid request, closing")
                            self._connections.xdiscard(connection)
                            self._close(0, connection)
                            return
                        if buffer[1] != 1:
                            logger.debug("SOCKS5ServerNode: Unsupported command")
                            self._send(0, connection, b"\x05\x07\x00\x03\x00\x00\x00")
                            self._connections.xdiscard(connection)
                            self._close(0, connection)
                            return
                        match buffer[3]: # DST.ADDR
                            case 1: # IPv4
                                host = IPv4Address(buffer[4:-2])
                            case 3: # Domain name
                                try:
                                    host = buffer[5: -2].decode("idna")
                                except UnicodeDecodeError:
                                    logger.debug("SOCKS5ServerNode: Invalid DST.ADDR")
                                    self._send(0, connection, b"\x05\x04\x00\x03\x00\x00\x00")
                                    self._connections.xdiscard(connection)
                                    self._close(0, connection)
                                    return
                            case 4: # IPv6
                                host = IPv6Address(buffer[4: -2])
                            case _: # Never
                                raise ValueError("SOCKS5ServerNode: Never (CONNECT ATYP)")
                        self._send(0, connection, b"\x05\x00\x00\x03\x00\x00\x00")
                        session = TCPSession(host, int.from_bytes(buffer[-2:], byteorder="big"))
                        self._open(1, session)
                        ADC = SOCKS5ConnectConnection()
                        self._connections.set(connection, session, ADC)
                        logger.debug(f"SOCKS5ServerNode: Received connection request to {host}")
                else: # SOCKS5ConnectConnection
                    self._send(1, session, packet.payload)
                return
            case 1:
                message = cast(TCPMessage, obj)
                # SYN (Never)
                if message.payload == "SYN":
                    self._reject(1, message)
                    return
                # Get stuff
                session = message.bound
                ADC = self._connections.ygetd(message.bound)
                if not ADC:
                    if message.payload != "FIN":
                        self._reject(1, message)
                    return
                connection = cast(TCPConnection, self._connections.ygetx(session))
                # FIN
                if message.payload == "FIN":
                    self._connections.xdiscard(connection)
                    self._close(0, connection)
                    logger.debug(f"SOCKS5ServerNode: Session to {session.host} closed from downstream")
                    return
                self._send(0, connection, message.payload)
                return

class SOCKS5ClientNode(Node):
    """
    SOCKS5 client. Only supports `CONNECT`; Does not support authentication.

    SOCKS5 server address uses python native IP represenation or a string
    domain, which is resolved using system DNS at construct time. Port is
    1080 by default.

    Does not bother runtime DNS; `TCPSession.host` type is faithfully
    translated into SOCK5 `DST.ADDR`.

    Has a `TCPMessage` upstream and a `TCPPacket` downstream.
    """
    _edges = 2
    _upstreams = (0,)
    _downstreams = (1,)
    __slots__ = (
        "_connections",
        "_server",
    )

    def __init__(
        self,
        server: IPv4Address | IPv6Address | str | tuple[
            IPv4Address | IPv6Address | str, int
        ],
        *args,
        boundary: bool=False
    ):
        super().__init__(boundary)
        if not isinstance(server, tuple):
            server = (server, 1080)
        if isinstance(server[0], str):
            server = (waitDNS(server[0]), server[1])
        self._server: tuple[IPv4Address | IPv6Address, int] = cast(
            tuple[IPv4Address | IPv6Address, int], server
        )

    async def _run(self) -> Signal | None:
        self._connections: BidictAD[
            TCPSession, TCPConnection, SOCKS5ClientNewConnection | SOCKS5ConnectConnection
        ] = BidictAD()

    async def _onGet(self, edge: int, obj: TCPPacket | UDPPacket | TCPMessage | UDPMessage) -> Signal | None:
        match edge:
            case 0:
                message = cast(TCPMessage, obj)
                # SYN
                if message.payload == "SYN":
                    ADC = SOCKS5ClientNewConnection(False, b"", [])
                    connection = TCPConnection(*self._server)
                    self._connections.set(message.bound, connection, ADC)
                    logger.debug(f"SOCKS5ClientNode: Requesting connection to {message.bound.host}")
                    # Send client hello
                    self._open(1, connection)
                    self._send(1, connection, b"\x05\x01\x00")
                    return
                # Get stuff
                session = message.bound
                ADC = self._connections.xgetd(session)
                if not ADC:
                    if message.payload != "FIN":
                        self._reject(0, message)
                    return
                connection = cast(TCPConnection, self._connections.xgety(session))
                # FIN
                if message.payload == "FIN":
                    logger.debug(f"SOCKS5ClientNode: Session to {message.bound.host} closed from upstream")
                    self._close(1, connection)
                    self._connections.xdiscard(session)
                    return
                # Data
                if isinstance(ADC, SOCKS5ClientNewConnection):
                    ADC.data.append(message.payload)
                else: # SOCKS5ConnectConnection
                    self._send(1, connection, message.payload)
                return
            case 1:
                packet = cast(TCPPacket, obj)
                # SYN (Never)
                if packet.payload == "SYN":
                    self._reject(1, obj)
                    return
                # Get stuff
                connection = packet.bound
                ADC = self._connections.ygetd(connection)
                if not ADC:
                    if packet.payload != "FIN":
                        self._reject(1, packet)
                    return
                session = cast(TCPSession, self._connections.ygetx(connection))
                # FIN
                if packet.payload == "FIN":
                    logger.debug(f"SOCKS5ClientNode: Session to {session.host} closed from downstream")
                    self._close(0, session)
                    self._connections.xdiscard(session)
                    return
                # Data
                if isinstance(ADC, SOCKS5ClientNewConnection):
                    if not ADC.established: # Waiting for server hello
                        ADC.buffer += packet.payload
                        buffer = ADC.buffer
                        if len(buffer) < 2:
                            return
                        if len(buffer) > 2 or buffer != b"\x05\x00":
                            logger.debug("SOCKS5ClientNode: Invalid server hello from server, closing")
                            self._connections.xdiscard(session)
                            self._close(0, session)
                            self._close(1, connection)
                            return
                        # Request construction
                        dst = session.host
                        request = b"\x05\x01\x00"
                        if isinstance(dst, IPv4Address):
                            request += b"\x01" + dst.packed
                        elif isinstance(dst, IPv6Address):
                            request += b"\x04" + dst.packed
                        else:
                            domain = dst.encode("idna")
                            # A domain is at most 255 bytes
                            request += b"\x03" + len(domain).to_bytes(length=1, byteorder="big") + domain
                        request += session.port.to_bytes(length=2, byteorder="big")
                        self._send(1, connection, request)
                        ADC.buffer = b""
                        ADC.established = True
                    else: # Waiting for reply
                        ADC.buffer += packet.payload
                        buffer = ADC.buffer
                        if len(ADC.buffer) < 4:
                            return
                        if  buffer[3] == 1 and len(buffer) > 10 or \
                            buffer[3] == 3 and len(buffer) > buffer[4] + 7 or \
                            buffer[3] == 4 and len(buffer) > 22:
                            logger.debug("SOCKS5ClientNode: Reply too long")
                            self._connections.xdiscard(session)
                            self._close(0, session)
                            self._close(1, connection)
                            return
                        if  buffer[:3] != b"\x05\x00\x00":
                            logger.debug(f"SOCKS5ClientNode: Server declined session to {session.host}, closing")
                            self._connections.xdiscard(session)
                            self._close(0, session)
                            self._close(1, connection)
                            return
                        # success
                        for data in ADC.data:
                            self._send(1, connection, data)
                        ADC = SOCKS5ConnectConnection()
                        self._connections.set(session, connection, ADC)
                        logger.debug(f"SOCKS5ClientNode: Established session for dst {session.host}")
                else: # SOCKS5ConnectConnection
                    self._send(0, session, packet.payload)
                return
