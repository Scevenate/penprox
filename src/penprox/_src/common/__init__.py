from __future__ import annotations

from ..sdk import *


class UpstreamTCPNode(BaseNode):
    """
    Node that listens a TCP port.

    Has one `TCPPacket` downstream edge.

    Only listens to `127.0.0.1` by default. Explicitly assign `0.0.0.0` or 
    `::` if you want access from remote host.

    As a most upstream node, claims SIGTERM boundary by default.

    Listen to port `0` to get an ephemeral port at `self.address()[2]` at
    runtime.
    """
    __slots__ = (
        "_address",
        "_boundary",
        "_connections",
        "_controller",
        "_edges",
        "_running",
        "_signal"
    )
    def __init__(
        self,
        address: int | tuple[IPv4Address | IPv6Address, int],
        /,
        boundary: bool = True
    ) -> None:
        self._controller: Queue[Signal] = Queue()
        self._edges: list[EdgeEnd | None] = [None]
        self._running: bool = False
        self._boundary: bool = boundary
        if not isinstance(address, tuple):
            address = (IPv4Address("127.0.0.1"), address)
        self._address: tuple[IPv4Address | IPv6Address, int] = address

    def boundary(self) -> bool:
        return self._boundary
    def controller(self) -> Queue[Signal]:
        return self._controller
    def edges(self) -> list[EdgeEnd | None]:
        return self._edges
    def running(self) -> bool:
        return self._running
    def upstreams(self) -> tuple[int, ...]:
        return ()
    def downstreams(self) -> tuple[int, ...]:
        return (0,)
    def address(self) -> tuple[IPv4Address | IPv6Address, int]:
        return self._address

    class _UpstreamTCPProtocol(asyncio.Protocol):
        __slots__ = (
            "_connection",
            "_node"
        )
        def __init__(self, node: UpstreamTCPNode):
            self._node: UpstreamTCPNode = node
        def connection_made( # pyright: ignore[reportIncompatibleMethodOverride]
            self,
            transport: asyncio.Transport
        ):
            if self._node._signal == "SIGTERM" and self._node._boundary:
                transport.close()
                return
            peerName = transport.get_extra_info("peername")
            if not peerName:
                logger.error("UpstreamTCPNode: getpeername failed, closing new connection")
                transport.close()
                return
            if len(peerName) == 2: # v4
                connection = TCPConnection(IPv4Address(peerName[0]), peerName[1])
            else: # v6
                connection = TCPConnection(IPv6Address(peerName[0]), peerName[1])
            logger.debug(f"UpstreamTCPNode: New connection {connection}")
            self._connection: TCPConnection = connection
            self._node._connections[connection] = transport
            self._node._open(0, connection)
        def data_received(self, data: bytes) -> None:
            self._node._send(0, self._connection, data) 
        def connection_lost(self, exc: Exception | None) -> None:
            if exc:
                logger.error(f"UpstreamTCPNode: Received {exc} when closing connection")
            logger.debug(f"UpstreamTCPNode: Connection closed {self._connection}")
            if self._node._connections.pop(self._connection, None):
                self._node._close(0, self._connection)
            if self._node._signal == "SIGTERM" and not self._node._connections:
                self._node._controller.put_nowait("SIGKILL")

    async def _dispatch(self) -> None:
        try:
            while True:
                packet = cast(TCPPacket, await self._edges[0][0].get()) # pyright: ignore[reportOptionalSubscript]
                if packet.payload == "SYN":
                    logger.error("UpstreamTCPNode: Received SYN packet from downstream")
                    self._reject(0, packet)
                    continue
                transport: asyncio.Transport | None = self._connections.get(packet.bound)
                if not transport or transport.is_closing():
                    if packet.payload != "FIN":
                        self._reject(0, packet)
                    continue
                if packet.payload == "FIN":
                    transport.close()
                    continue
                transport.write(packet.payload)
                
        except asyncio.CancelledError:
            return

    async def run(self) -> Signal | None:
        if self._running:
            raise RuntimeError("Attempted to run a running UpstreamTCPNode")
        if len(self._edges) != 1 or not self._edges[0]:
            raise ValueError("Running improperly connected UpstreamTCPNode")
        while not self._controller.empty():
            self._controller.get_nowait()
        self._connections: dict[TCPConnection, asyncio.Transport] = {}
        self._signal: Signal | None = None
        logger.info("Running UpstreamTCPNode...")
        self._running = True
        
        address = self._address
        loop = asyncio.get_running_loop()
        sock = socket.socket(socket.AF_INET6 if isinstance(address[0],
            IPv6Address) else socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setblocking(False)
        if isinstance(address[0], IPv6Address):
            sock.bind((str(address[0]), address[1], 0, 0))
        else:
            sock.bind((str(address[0]), address[1]))
        if not address[1]:
            addr = sock.getsockname()
            self._address = (address[0], addr[1])
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.listen()

        server = create_task((await loop.create_server(
            lambda: UpstreamTCPNode._UpstreamTCPProtocol(self), sock=sock
        )).serve_forever())
        dispatcher = create_task(self._dispatch())
        controller = create_task(self._controller.get())
        while True:
            done, _ = await asyncio.wait(
                (server, dispatcher, controller),
                return_when=asyncio.FIRST_COMPLETED
            )
            if server in done or dispatcher in done:
                server.cancel()
                dispatcher.cancel()
                self._running = False
                return None if self._signal else "SIGKILL"
            signal = cast(Signal, done.pop().result())
            logger.info(f"UpstreamTCPNode: Received {signal} signal")
            if signal == "SIGKILL" or \
                signal == "SIGTERM" and not self._connections:
                server.cancel()
                dispatcher.cancel()
                self._running = False
                logger.info("UpstreamTCPNode: Quitting (SIGTERM / SIGKILL)")
                return
            self._signal = signal
            controller = create_task(self._controller.get())

class UpstreamUDPNode(BaseNode):
    """
    Node that listens a UDP port.

    Has one `UDPPacket` downstream edge.

    Only listens to `127.0.0.1` by default. Explicitly assign `0.0.0.0` or 
    `::` if you want access from remote host.

    As a most upstream node, claims SIGTERM boundary by default.

    Listen to port `0` to get an ephemeral port at `self.address()[2]` at
    runtime.

    UDP connections must be closed by downstream.
    """
    __slots__ = (
        "_address",
        "_boundary",
        "_connections",
        "_controller",
        "_edges",
        "_running",
        "_signal",
    )
    def __init__(
        self,
        address: int | tuple[IPv4Address | IPv6Address, int],
        /,
        boundary: bool = True
    ) -> None:
        self._controller: Queue[Signal] = Queue()
        self._edges: list[EdgeEnd | None] = [None]
        self._running: bool = False
        self._boundary: bool = boundary
        if not isinstance(address, tuple):
            address = (IPv4Address("127.0.0.1"), address)
        self._address: tuple[IPv4Address | IPv6Address, int] = address

    def boundary(self) -> bool:
        return self._boundary
    def controller(self) -> Queue[Signal]:
        return self._controller
    def edges(self) -> list[EdgeEnd | None]:
        return self._edges
    def running(self) -> bool:
        return self._running
    def upstreams(self) -> tuple[int, ...]:
        return ()
    def downstreams(self) -> tuple[int, ...]:
        return (0,)
    def address(self) -> tuple[IPv4Address | IPv6Address, int]:
        return self._address

    class _UpstreamUDPProtocol(asyncio.DatagramProtocol):
        __slots__ = (
            "_node",
            "_transport"
        )
        def __init__(self, node: UpstreamUDPNode):
            self._node: UpstreamUDPNode = node
        def connection_made(
            self,
            transport: asyncio.DatagramTransport
        ):
            self._transport = transport
        def datagram_received(self, data: bytes, addr: tuple) -> None:
            node = self._node
            if len(addr) == 2:
                address = (IPv4Address(addr[0]), addr[1])
            else:
                address = (IPv6Address(addr[0]), addr[1])
            connection = node._connections.get(address)
            if not connection:
                if node._signal == "SIGTERM" and node._boundary:
                    return
                logger.debug(f"UpstreamUDPNode: New connection from {addr[0]}")
                connection = UDPConnection(*address)
                node._connections[address] = connection
                node._open(0, connection)
            else:
                node._send(0, connection, data)


    async def _dispatch(self) -> None:
        try:
            while True:
                packet = cast(UDPPacket, await self._edges[0][0].get()) # pyright: ignore[reportOptionalSubscript]
                if packet.payload == "SYN":
                   logger.error("UpstreamUDPNode: Received SYN packet from downstream")
                   self._reject(0, packet)
                   continue
                if packet.payload == "FIN":
                    logger.debug(f"UpstreamUDPNode: Connection closed {packet.bound}")
                    self._connections.pop((packet.bound.host, packet.bound.port), None)
                    if self._signal == "SIGTERM" and not self._connections:
                        self._controller.put_nowait("SIGKILL")
                    continue
                if self._transport.is_closing():
                    raise ConnectionError("UpstreamUDPNode: Unexpected transport closure")
                self._transport.sendto(packet.payload, (str(packet.bound.host), packet.bound.port))

        except asyncio.CancelledError:
            return

    async def run(self) -> Signal | None:
        if self._running:
            raise RuntimeError("Attempted to run a running UpstreamUDPNode")
        if len(self._edges) != 1 or not self._edges[0]:
            raise ValueError("Running improperly connected UpstreamUDPNode")
        self._connections: dict[tuple[IPv4Address | IPv6Address, int], UDPConnection] = {}
        self._signal: Signal | None = None
        while not self._controller.empty():
            self._controller.get_nowait()
        logger.info("Running UpstreamUDPNode...")
        self._running = True

        address = self._address
        loop = asyncio.get_running_loop()
        sock = socket.socket(socket.AF_INET6 if isinstance(address[0],
            IPv6Address) else socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setblocking(False)
        if isinstance(address[0], IPv6Address):
            sock.bind((str(address[0]), address[1], 0, 0))
        else:
            sock.bind((str(address[0]), address[1]))
        if not address[1]:
            addr = sock.getsockname()
            self._address = (address[0], addr[1])

        transport, _ = await loop.create_datagram_endpoint(
            lambda: UpstreamUDPNode._UpstreamUDPProtocol(self), sock=sock
        )
        self._transport: asyncio.DatagramTransport = transport
        dispatcher = create_task(self._dispatch())
        controller = create_task(self._controller.get())
        while True:
            done, _ = await asyncio.wait(
                (dispatcher, controller),
                return_when=asyncio.FIRST_COMPLETED
            )
            if dispatcher in done:
                self._transport.close()
                self._running = False
                return None if self._signal else "SIGKILL"
            signal = cast(Signal, done.pop().result())
            logger.info(f"UpstreamUDPNode: Received {signal} signal")
            if signal == "SIGKILL" or \
                signal == "SIGTERM" and not self._connections:
                dispatcher.cancel()
                self._transport.close()
                self._running = False
                logger.info("UpstreamUDPNode: Quitting (SIGTERM / SIGKILL)")
                return
            self._signal = signal
            controller = create_task(self._controller.get())


class DownstreamTCPNode(BaseNode):
    """
    Downstream network servant node.

    Has one `TCPPacket` upstream edge.
    """
    __slots__ = (
        "_boundary",
        "_connections",
        "_controller",
        "_edges",
        "_running",
        "_signal",
    )
    def __init__(self, /, boundary: bool = False) -> None:
        self._controller: Queue[Signal] = Queue()
        self._edges: list[EdgeEnd | None] = [None]
        self._running: bool = False
        self._boundary: bool = boundary

    def boundary(self) -> bool:
        return self._boundary
    def controller(self) -> Queue[Signal]:
        return self._controller
    def edges(self) -> list[EdgeEnd | None]:
        return self._edges
    def running(self) -> bool:
        return self._running
    def upstreams(self) -> tuple[int, ...]:
        return (0,)
    def downstreams(self) -> tuple[int, ...]:
        return ()

    class _DownstreamTCPProtocol(asyncio.Protocol):
        __slots__ = (
            "_connection",
            "_node"
        )
        def __init__(self, node: DownstreamTCPNode, connection: TCPConnection):
            self._node: DownstreamTCPNode = node
            self._connection: TCPConnection = connection
        def connection_made( # pyright: ignore[reportIncompatibleMethodOverride]
            self,
            transport: asyncio.Transport
        ):
            # SYN from upstream only, guarding SIGTERM boundary in dispatcher
            logger.debug(f"UpstreamUDPNode: New connection to {self._connection.host}")
            self._node._connections[self._connection] = transport
        def data_received(self, data: bytes) -> None:
            self._node._send(0, self._connection, data)
        def connection_lost(self, exc: Exception | None) -> None:
            if exc:
                logger.error(f"DownstreamTCPNode: Received {exc} when closing connection")
            logger.debug(f"DownstreamTCPNode: Connection closed: {self._connection}")
            if self._node._connections.pop(self._connection, None):
                self._node._close(0, self._connection)
            if self._node._signal == "SIGTERM" and not self._node._connections:
                self._node._controller.put_nowait("SIGKILL")

    async def _dispatch(self) -> None:
        try:
            while True:
                packet = cast(TCPPacket, await self._edges[0][0].get()) # pyright: ignore[reportOptionalSubscript]
                if packet.payload == "SYN":
                    if self._signal == "SIGTERM" and self._boundary:
                        self._reject(0, packet)
                        continue
                    loop = asyncio.get_running_loop()
                    protocol = DownstreamTCPNode._DownstreamTCPProtocol(
                        self, packet.bound
                    )
                    # We only await next packet after current iteration
                    # So the next packet would only be read after transport
                    # assignment
                    try:
                        transport, _ = await loop.create_connection(
                            lambda: protocol, # noqa: B023
                            str(packet.bound.host),
                            packet.bound.port
                        )
                    except OSError as e:
                        logger.error(f"DownstreamTCPNode: Received {e.strerror} while constructing connection")
                        self._reject(0, packet)
                    continue
                transport: asyncio.Transport | None = self._connections.get(packet.bound)
                if not transport or transport.is_closing():
                    if packet.payload != "FIN":
                        self._reject(0, packet)
                    continue
                if packet.payload == "FIN":
                    transport.close()
                    continue
                transport.write(packet.payload)
                
        except asyncio.CancelledError:
            return

    async def run(self) -> Signal | None:
        if self._running:
            raise RuntimeError("Attempted to run a running DownstreamTCPNode")
        if len(self._edges) != 1 or not self._edges[0]:
            raise ValueError("Running improperly connected DownstreamTCPNode")
        self._connections: dict[TCPConnection, asyncio.Transport] = {}
        self._signal: Signal | None = None
        while not self._controller.empty():
            self._controller.get_nowait()
        logger.info("Running DownstreamTCPNode...")
        self._running = True

        dispatcher = create_task(self._dispatch())
        controller = create_task(self._controller.get())
        while True:
            done, _ = await asyncio.wait(
                (dispatcher, controller),
                return_when=asyncio.FIRST_COMPLETED
            )
            if dispatcher in done:
                self._running = False
                return None if self._signal else "SIGKILL"
            signal = cast(Signal, done.pop().result())
            logger.info(f"DownstreamTCPNode: Received {signal} signal")
            if signal == "SIGKILL" or \
                signal == "SIGTERM" and not self._connections:
                for transport in self._connections.values():
                    transport.close()
                dispatcher.cancel()
                self._running = False
                logger.info("DownstreamTCPNode: Quitting (SIGTERM / SIGKILL)")
                return
            self._signal = signal
            controller = create_task(self._controller.get())

class DownstreamUDPNode(BaseNode):
    """
    Downstream network servant node.

    Has one `UDPPacket` upstream edge.
    """
    __slots__ = (
        "_boundary",
        "_connections",
        "_controller",
        "_edges",
        "_running",
        "_signal",
        "_transport",
    )
    def __init__(self, /, boundary: bool = False) -> None:
        self._controller: Queue[Signal] = Queue()
        self._edges: list[EdgeEnd | None] = [None]
        self._running: bool = False
        self._boundary: bool = boundary

    def boundary(self) -> bool:
        return self._boundary
    def controller(self) -> Queue[Signal]:
        return self._controller
    def edges(self) -> list[EdgeEnd | None]:
        return self._edges
    def running(self) -> bool:
        return self._running
    def upstreams(self) -> tuple[int, ...]:
        return (0,)
    def downstreams(self) -> tuple[int, ...]:
        return ()

    class _DownstreamUDPProtocol(asyncio.DatagramProtocol):
        __slots__ = (
            "_node",
        )
        def __init__(self, node: DownstreamUDPNode):
            self._node: DownstreamUDPNode = node
        def connection_made(
            self,
            transport: asyncio.DatagramTransport
        ):
            self._node._transport = transport
        def datagram_received(self, data: bytes, addr: tuple) -> None:
            node = self._node
            if len(addr) == 2:
                address = (IPv4Address(addr[0]), addr[1])
            else:
                address = (IPv6Address(addr[0]), addr[1])
            connection = node._connections.get(address)
            if connection:
                node._send(0, connection, data)

    async def _dispatch(self) -> None:
        try:
            while True:
                packet = cast(UDPPacket, await self._edges[0][0].get()) # pyright: ignore[reportOptionalSubscript]
                if self._transport.is_closing():
                    raise ConnectionError("Unexpected transport close")
                if packet.payload == "SYN":
                    if self._signal == "SIGTERM" and self._boundary:
                        self._reject(0, packet)
                        continue
                    logger.debug(f"DownstreamUDPNode: New connection to {packet.bound.host}")
                    self._connections[(packet.bound.host, packet.bound.port)] = packet.bound
                    continue
                if packet.payload == "FIN":
                    logger.debug(f"DownstreamUDPNode: Connection closed to {packet.bound.host}")
                    self._connections.pop((packet.bound.host, packet.bound.port), None)
                    if self._signal == "SIGTERM" and not self._connections:
                        self._controller.put_nowait("SIGKILL")
                    continue
                self._transport.sendto(packet.payload, (str(packet.bound.host), packet.bound.port))
        except asyncio.CancelledError:
            return

    async def run(self) -> Signal | None:
        if self._running:
            raise RuntimeError("Attempted to run a running DownstreamUDPNode")
        if len(self._edges) != 1 or not self._edges[0]:
            raise ValueError("Running improperly connected DownstreamUDPNode")
        self._connections: dict[tuple[IPv4Address | IPv6Address, int], UDPConnection] = {}
        self._signal: Signal | None = None
        while not self._controller.empty():
            self._controller.get_nowait()
        logger.info("Running DownstreamUDPNode...")
        self._running = True

        loop = asyncio.get_running_loop()
        transport, _ = await loop.create_datagram_endpoint(
            lambda: DownstreamUDPNode._DownstreamUDPProtocol(self),
            local_addr=("0.0.0.0", 0)
        )
        self._transport: asyncio.DatagramTransport = transport
        dispatcher = create_task(self._dispatch())
        controller = create_task(self._controller.get())
        while True:
            done, _ = await asyncio.wait(
                (dispatcher, controller),
                return_when=asyncio.FIRST_COMPLETED
            )
            if dispatcher in done:
                self._transport.close()
                self._running = False
                return None if self._signal else "SIGKILL"
            signal = cast(Signal, done.pop().result())
            logger.info(f"DownstreamUDPNode: Received {signal} signal")
            if signal == "SIGKILL" or \
                signal == "SIGTERM" and not self._connections:
                dispatcher.cancel()
                if self._transport:
                    self._transport.close()
                self._running = False
                logger.info("DownstreamUDPNode: Quitting (SIGTERM / SIGKILL)")
                return
            self._signal = signal
            controller = create_task(self._controller.get())

class ExitNode(Node):
    """
    Exit server node that resolves proxy sessions locally.

    Has one DNS-resolved `Message` upstream and one `Packet`
    downstream.

    Serves both TCP and UDP. Consider adding a demultiplexing node if you
    use both.
    """
    _edges = 2
    _upstreams = (0,)
    _downstreams = (1,)
    __slots__ = (
        "_connections",
    )
    async def _run(self) -> Signal | None:
        self._connections: Bidict[
            TCPSession | UDPSession,
            TCPConnection | UDPConnection
        ] = Bidict()

    async def _onGet(self, edge: int, obj: TCPPacket | UDPPacket | TCPMessage | UDPMessage) -> Signal | None:
        match edge:
            case 0:
                message = cast(TCPMessage | UDPMessage, obj)
                if message.payload == "SYN":
                    logger.debug(f"ExitNode: New session to {message.bound.host}")
                    if isinstance(message.bound.host, str):
                        logger.error(f"ExitNode: Received unresolved host {message.bound.host} from upstream")
                        self._reject(0, message)
                        return
                    if isinstance(message, TCPMessage):
                        connection = TCPConnection(message.bound.host, message.bound.port)
                    else:
                        connection = UDPConnection(message.bound.host, message.bound.port)
                    self._connections.set(message.bound, connection)
                    self._open(1, connection)
                    return
                connection = self._connections.xgety(message.bound)
                if not connection:
                    if message.payload != "FIN":
                        self._reject(0, message)
                    return
                if message.payload == "FIN":
                    logger.debug(f"ExitNode: Session closed {message.bound.host}")
                    self._connections.ydiscard(connection)
                    return
                self._send(1, connection, message.payload)
                return
            case 1:
                packet = cast(TCPPacket | UDPPacket, obj)
                if packet.payload == "SYN":
                    logger.error("ExitSereverNode: Received SYN packet from downstream")
                    self._reject(1, packet)
                    return
                session = self._connections.ygetx(packet.bound)
                if not session:
                    if packet.payload != "FIN":
                        self._reject(1, packet)
                    return
                if packet.payload == "FIN":
                    logger.debug(f"ExitNode: Session closed {packet.bound.host}")
                    self._connections.ydiscard(packet.bound)
                    return
                self._send(0, session, packet.payload)


class MuxNode(BaseNode):
    """
    Node that multiplexes traffic.

    Has multiple upstreams and a mixed downstream. Accepts any `TCPPacket`,
    `UDPPacket`, `TCPMessage` or `UDPMessage`. The node
    does not mutate traffic and acts simply as a router.

    `initial_size` specifies the initial amount of upstreams. This can be modified
    provided the node is not running and the downstream is still the last.
    """
    __slots__ = (
        "_boundary",
        "_controller",
        "_edges",
        "_running",
    )
    def __init__(self, initial_size: int = 2, /, boundary: bool = False) -> None:
        assert initial_size >= 2
        self._controller: Queue[Signal] = Queue()
        self._edges: list[EdgeEnd | None] = [None] * (initial_size + 1)
        self._running: bool = False
        self._boundary: bool = boundary

    def boundary(self) -> bool:
        return self._boundary
    def controller(self) -> Queue[Signal]:
        return self._controller
    def edges(self) -> list[EdgeEnd | None]:
        return self._edges
    def running(self) -> bool:
        return self._running
    def upstreams(self) -> tuple[int, ...]:
        return tuple(range(len(self._edges)))
    def downstreams(self) -> tuple[int, ...]:
        return (len(self._edges),)

    async def run(self) -> Signal | None:
        if self._running:
            raise RuntimeError("Attempted to run a running MuxNode")
        if len(self._edges) < 3 or not all(self._edges):
            raise ValueError("Running improperly connected MuxNode")
        pool: dict[
            TCPConnection | UDPConnection | TCPSession | UDPSession, int
        ] = {}
        signal: Signal | None = None
        while not self._controller.empty():
            self._controller.get_nowait()
        logger.info("Running MuxNode...")
        self._running = True

        controller = create_task(self._controller.get())
        upstreams = [create_task(self._edges[i][0].get()) for i in range(len(self._edges))] # pyright: ignore[reportOptionalSubscript]
        downstream = create_task(self._edges[2][0].get()) # pyright: ignore[reportOptionalSubscript]
        while True:
            done, _ = await asyncio.wait(
                upstreams + [controller, downstream],
                return_when=asyncio.FIRST_COMPLETED
            )
            for task in done:
                match task:
                    case _ if task is downstream:
                        downstream = create_task(self._edges[2][0].get()) # pyright: ignore[reportOptionalSubscript]
                        packet = cast(TCPPacket | UDPPacket | TCPMessage | UDPMessage, task.result())
                        if packet.payload == "SYN": # Never
                            logger.error("MuxNode: Received SYN request from downstream, rejecting")
                            self._reject(2, packet)
                            continue
                        upstream = pool.get(packet.bound)
                        if not upstream:
                            if packet.payload != "FIN":
                                self._reject(-1, packet)
                            continue
                        self._forward(upstream, packet)
                        if packet.payload == "FIN":
                            pool.pop(packet.bound, None)
                            if signal == "SIGTERM" and not pool:
                                logger.info("MuxNode: All connection served, quitting (SIGTERM)")
                                self._running = False
                                return
                        continue
                    case _ if task is controller:
                        controller = create_task(self._controller.get())
                        _signal = cast(Signal, task.result())
                        logger.info(f"MuxNode: Received {_signal} signal")
                        if _signal == "SIGKILL":
                            self._running = False
                            return
                        if _signal == "SIGTERM":
                            if not pool:
                                logger.info("MuxNode: All connection served, quitting (SIGTERM)")
                                self._running = False
                                return
                            signal = "SIGTERM"
                        continue
                    case _: # upstream
                        upstream = upstreams.index(task)
                        upstreams[upstream] = create_task(self._edges[upstream][0].get()) # pyright: ignore[reportOptionalSubscript]
                        packet = cast(TCPPacket | UDPPacket | TCPMessage | UDPMessage, task.result())
                        if packet.payload == "SYN":
                            if signal == "SIGTERM" and self._boundary:
                                self._reject(upstream, packet)
                                continue
                            pool[packet.bound] = upstream
                        self._forward(2, packet)
                        if packet.payload == "FIN":
                            pool.pop(packet.bound, None)
                            if signal == "SIGTERM" and not pool:
                                logger.info("MuxNode: All connection served, quitting (SIGTERM)")
                                self._running = False
                                return
                        continue


class DemuxTCPUDPNode(Node):
    """
    Node that demultiplexes TCP and UDP traffic.

    Has a mixed upstream, a TCP downstream and a UDP downstream. Accepts any
    `TCPPacket`, `UDPPacket`, `TCPMessage` or `UDPMessage`.
    The node does not mutate traffic and acts simply as a router.
    """
    _edges = 3
    _upstreams = (0,)
    _downstreams = (1, 2)
    __slots__ = ()

    async def _onGet(self, edge: int, obj: TCPPacket | UDPPacket | TCPMessage | UDPMessage) -> Signal | None:
        if edge == 0:
            self._forward(1 + isinstance(obj, (UDPPacket, UDPMessage)), obj)
        else:
            self._forward(0, obj)
