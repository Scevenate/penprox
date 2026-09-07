from __future__ import annotations

import socket
from logging import getLogger

from ..sdk import *

logger = getLogger(__name__)

class UpstreamTCPNode(ProxyNode):
    """
    Node that listens a TCP port.

    Has one `ProxyTCPPacket` downstream edge.

    Only listens to `127.0.0.1` by default. Explicitly assign `0.0.0.0` or 
    `::` if you want access from remote host.

    As a most upstream node, claims SIGTERM boundary by default.

    Listen to port `0` to get an ephemeral port at `self.address()[2]` at
    runtime.
    """
    _version = "0.1.0"
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
        port: int,
        ip: IPv4Address | IPv6Address | None = None,
        /,
        boundary: bool = True
    ) -> None:
        self._controller: Queue[ProxySignal] = Queue()
        self._edges: list[ProxyEdgeEnd | None] = [None]
        self._running: bool = False
        self._boundary: bool = boundary
        if ip:
            self._address: tuple[IPv4Address | IPv6Address, int] = (ip, port)
        else:
            self._address: tuple[IPv4Address | IPv6Address, int] = (IPv4Address("127.0.0.1"), port)

    def address(self) -> tuple[IPv4Address | IPv6Address, int]:
        """
        Get the local listening address `(ip, port)` of the node.
        """
        return self._address

    class _UpstreamTCPProtocol(asyncio.Protocol):
        __slots__ = (
            "_connection",
            "_node"
        )
        def __init__(self, node: UpstreamTCPNode):
            self._node: UpstreamTCPNode = node
        def connection_made( # type: ignore
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
                connection = ProxyTCPConnection(IPv4Address(peerName[0]), peerName[1])
            else: # v6
                connection = ProxyTCPConnection(IPv6Address(peerName[0]), peerName[1])
            logger.debug(f"UpstreamTCPNode: New connection {connection}")
            self._connection: ProxyTCPConnection = connection
            self._node._connections[connection] = transport
            self._node._open(0, connection)
        def data_received(self, data: bytes) -> None:
            self._node._send(0, self._connection, data) 
        def connection_lost(self, exc: Exception | None) -> None:
            if exc:
                logger.error(f"UpstreamTCPNode: Received {exc} when closing connection")
            logger.debug(f"UpstreamTCPNode: Connection closed {self._connection}")
            self._node._close(0, self._connection)
            self._node._connections.pop(self._connection, None)
            if self._node._signal == "SIGTERM" and not self._node._connections:
                self._node._controller.put_nowait("SIGKILL")

    async def _dispatch(self) -> None:
        try:
            while True:
                packet = cast(ProxyTCPPacket, await self._edges[0][0].get()) # type: ignore
                if packet.flag == "SYN":
                    logger.error("UpstreamTCPNode: Received SYN packet from downstream")
                    self._reject(0, packet)
                    continue
                transport: asyncio.Transport | None = self._connections.get(packet.bound)
                if not transport or transport.is_closing():
                    # Possible close race between remote and downstream
                    # In this case, connection_lost will send FIN
                    continue
                transport.write(packet.data)
                if packet.flag == "FIN":
                    # We'll send back a FIN anyway...
                    transport.close()
                    continue
        except asyncio.CancelledError:
            return

    async def run(self) -> ProxySignal | None:
        """
        Run `UpstreamTCPNode`.
        """
        if self._running:
            logger.critical("Attempted to run a running UpstreamTCPNode")
            return "SIGKILL"
        if len(self._edges) != 1 or not self._edges[0]:
            logger.critical("Running improperly connected UpstreamTCPNode")
            return "SIGKILL"
        logger.info("Running UpstreamTCPNode...")
        self._running = True
        self._connections: dict[ProxyTCPConnection, asyncio.Transport] = {}
        self._signal: ProxySignal | None = None
        while not self._controller.empty():
            self._controller.get_nowait()
        
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
            signal = cast(ProxySignal, done.pop().result())
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

class UpstreamUDPNode(ProxyNode):
    """
    Node that listens a UDP port.

    Has one `ProxyUDPPacket` downstream edge.

    Only listens to `127.0.0.1` by default. Explicitly assign `0.0.0.0` or 
    `::` if you want access from remote host.

    As a most upstream node, claims SIGTERM boundary by default.

    Listen to port `0` to get an ephemeral port at `self.address()[2]` at
    runtime.

    UDP connections must be closed by downstream.
    """
    _version = "0.1.0"
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
        port: int,
        ip: IPv4Address | IPv6Address | None = None,
        /,
        boundary: bool = True
    ) -> None:
        self._controller: Queue[ProxySignal] = Queue()
        self._edges: list[ProxyEdgeEnd | None] = [None]
        self._running: bool = False
        self._boundary: bool = boundary
        if ip:
            self._address: tuple[IPv4Address | IPv6Address, int] = (ip, port)
        else:
            self._address: tuple[IPv4Address | IPv6Address, int] = (IPv4Address("127.0.0.1"), port)

    def address(self) -> tuple[IPv4Address | IPv6Address, int]:
        """
        Get the local listening address of the node.
        """
        return self._address

    class _UpstreamUDPProtocol(asyncio.DatagramProtocol):
        __slots__ = (
            "_node",
            "_transport"
        )
        def __init__(self, node: UpstreamUDPNode):
            self._node: UpstreamUDPNode = node
        def connection_made( # type: ignore
            self,
            transport: asyncio.DatagramTransport
        ):
            self._transport = transport
        def datagram_received(self, data: bytes,addr: tuple) -> None:
            node = self._node
            if len(addr) == 2:
                address = (IPv4Address(addr[0]), addr[1])
            else:
                address = (IPv6Address(addr[0]), addr[1])
            connection = node._connections.get(address)
            if not connection:
                if node._signal == "SIGTERM" and node._boundary:
                    return
                logger.debug(f"UpstreamUDPNode: New connection {connection}")
                connection = ProxyUDPConnection(*address)
                node._connections[address] = connection
                node._open(0, connection)
            else:
                node._send(0, connection, data)


    async def _dispatch(self) -> None:
        try:
            while True:
                packet = cast(ProxyUDPPacket, await self._edges[0][0].get()) # type: ignore
                if packet.flag == "SYN":
                   logger.error("UpstreamUDPNode: Received SYN packet from downstream")
                   self._reject(0, packet)
                   continue
                if self._transport.is_closing():
                    raise ConnectionError("UpstreamUDPNode: Unexpected transport closure")
                self._transport.sendto(packet.data, (packet.bound.host, packet.bound.port))
                if packet.flag == "FIN":
                    logger.debug(f"UpstreamUDPNode: Connection closed {packet.bound}")
                    self._connections.pop((packet.bound.host, packet.bound.port), None)
                    if self._signal == "SIGTERM" and not self._connections:
                        self._controller.put_nowait("SIGKILL")
                    continue
        except asyncio.CancelledError:
            return

    async def run(self) -> ProxySignal | None:
        """
        Run `UpstreamUDPNode`.
        """
        if self._running:
            logger.critical("Attempted to run a running UpstreamUDPNode")
            return "SIGKILL"
        if len(self._edges) != 1 or not self._edges[0]:
            logger.critical("Running improperly connected UpstreamUDPNode")
            return "SIGKILL"
        logger.info("Running UpstreamUDPNode...")
        self._running = True
        self._connections: dict[tuple[IPv4Address | IPv6Address, int], ProxyUDPConnection] = {}
        self._signal: ProxySignal | None = None
        while not self._controller.empty():
            self._controller.get_nowait()

        address = self._address
        loop = asyncio.get_running_loop()
        sock = socket.socket(socket.AF_INET6 if isinstance(address[1],
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
            signal = cast(ProxySignal, done.pop().result())
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


class DownstreamTCPNode(ProxyNode):
    """
    Downstream network servant node.

    Has one `ProxyTCPPacket` upstream edge.
    """
    _version = "0.1.0"
    __slots__ = (
        "_boundary",
        "_connections",
        "_controller",
        "_edges",
        "_running",
        "_signal",
    )
    def __init__(self, /, boundary: bool = False) -> None:
        self._controller: Queue[ProxySignal] = Queue()
        self._edges: list[ProxyEdgeEnd | None] = [None]
        self._running: bool = False
        self._boundary: bool = boundary

    class _DownstreamTCPProtocol(asyncio.Protocol):
        __slots__ = (
            "_connection",
            "_node"
        )
        def __init__(self, node: DownstreamTCPNode, connection: ProxyTCPConnection):
            self._node: DownstreamTCPNode = node
            self._connection: ProxyTCPConnection = connection
        def connection_made( # type: ignore
            self,
            transport: asyncio.Transport
        ):
            # SYN from upstream only, guarding SIGTERM boundary in dispatcher
            logger.debug(f"UpstreamUDPNode: New connection {self._connection}")
            self._node._connections[self._connection] = transport
        def data_received(self, data: bytes) -> None:
            self._node._send(0, self._connection, data)
        def connection_lost(self, exc: Exception | None) -> None:
            if exc:
                logger.error(f"DownstreamTCPNode: Received {exc} when closing connection")
            logger.debug(f"DownstreamTCPNode: Connection closed: {self._connection}")
            self._node._close(0, self._connection)
            self._node._connections.pop(self._connection, None)
            if self._node._signal == "SIGTERM" and not self._node._connections:
                self._node._controller.put_nowait("SIGKILL")

    async def _dispatch(self) -> None:
        try:
            while True:
                packet = cast(ProxyTCPPacket, await self._edges[0][0].get()) # type: ignore
                if packet.flag == "SYN":
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
                else:
                    transport: asyncio.Transport | None = self._connections.get(packet.bound)
                if not transport or transport.is_closing():
                    # Possible close race between remote and upstream
                    # In this case, connection_lost will send FIN
                    continue
                transport.write(packet.data)
                if packet.flag == "FIN":
                    # We'll send back a FIN anyway...
                    transport.close()
                    continue
        except asyncio.CancelledError:
            return

    async def run(self) -> ProxySignal | None:
        """
        Run `DownstreamTCPNode`.
        """
        if self._running:
            logger.critical("Attempted to run a running DownstreamTCPNode")
            return "SIGKILL"
        if len(self._edges) != 1 or not self._edges[0]:
            logger.critical("Running improperly connected DownstreamTCPNode")
            return "SIGKILL"
        logger.info("Running DownstreamTCPNode...")
        self._running = True
        self._connections: dict[ProxyTCPConnection, asyncio.Transport] = {}
        self._signal: ProxySignal | None = None
        while not self._controller.empty():
            self._controller.get_nowait()

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
            signal = cast(ProxySignal, done.pop().result())
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

class DownstreamUDPNode(ProxyNode):
    """
    Downstream network servant node.

    Has one `ProxyUDPPacket` upstream edge.
    """
    _version = "0.1.0"
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
        self._controller: Queue[ProxySignal] = Queue()
        self._edges: list[ProxyEdgeEnd | None] = [None]
        self._running: bool = False
        self._boundary: bool = boundary

    class _DownstreamUDPProtocol(asyncio.DatagramProtocol):
        __slots__ = (
            "_node",
        )
        def __init__(self, node: DownstreamUDPNode):
            self._node: DownstreamUDPNode = node
        def connection_made( # type: ignore
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
                packet = cast(ProxyUDPPacket, await self._edges[0][0].get()) # type: ignore
                if self._transport.is_closing():
                    raise ConnectionError("Unexpected transport close")
                if packet.flag == "SYN":
                    if self._signal == "SIGTERM" and self._boundary:
                        self._reject(0, packet)
                        continue
                    logger.debug(f"DownstreamUDPNode: New connection {packet.bound}")
                    self._connections[(packet.bound.host, packet.bound.port)] = packet.bound
                self._transport.sendto(packet.data, (packet.bound.host, packet.bound.port))
                if packet.flag == "FIN":
                    logger.debug(f"DownstreamUDPNode: Connection closed {packet.bound}")
                    self._connections.pop((packet.bound.host, packet.bound.port), None)
                    if self._signal == "SIGTERM" and not self._connections:
                        self._controller.put_nowait("SIGKILL")
                    continue
        except asyncio.CancelledError:
            return

    async def run(self) -> ProxySignal | None:
        """
        Run `DownstreamUDPNode`.
        """
        if self._running:
            logger.critical("Attempted to run a running DownstreamUDPNode")
            return "SIGKILL"
        if len(self._edges) != 1 or not self._edges[0]:
            logger.critical("Running improperly connected DownstreamUDPNode")
            return "SIGKILL"
        logger.info("Running DownstreamUDPNode...")
        self._running = True
        self._connections: dict[tuple[IPv4Address | IPv6Address, int], ProxyUDPConnection] = {}
        self._signal: ProxySignal | None = None
        while not self._controller.empty():
            self._controller.get_nowait()

        loop = asyncio.get_running_loop()
        transport, _ = await loop.create_datagram_endpoint(
            lambda: DownstreamUDPNode._DownstreamUDPProtocol(self)
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
            signal = cast(ProxySignal, done.pop().result())
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

class ExitNode(ProxyNode):
    """
    Exit server node that resolves proxy sessions locally.

    Has one `ProxyMessage` upstream and one `ProxyPacket` downstream.

    Resolves request domain name by local DNS. Consider adding
    a DNS middleware node if you want custom DNS resolution.

    Serves both TCP and UDP. Consider adding a demultiplexing node if you
    use both.
    """
    _version = "0.1.0"
    __slots__ = (
        "_boundary",
        "_controller",
        "_edges",
        "_map",
        "_running",
        "_signal",
    )
    def __init__(self, /, boundary: bool = False) -> None:
        self._controller: Queue[ProxySignal] = Queue()
        self._edges: list[ProxyEdgeEnd | None] = [None, None]
        self._running: bool = False
        self._boundary: bool = boundary

    async def run(self) -> ProxySignal | None:
        """
        Run `ExitNode`.
        """
        if self._running:
            logger.critical("Attempted to run a running ExitNode")
            return "SIGKILL"
        if len(self._edges) != 2 or not all(self._edges):
            logger.critical("Running improperly connected ExitNode")
            return "SIGKILL"
        logger.info("Running ExitNode...")
        self._running = True
        self._map: ProxyBidict[
            ProxyTCPSession | ProxyUDPSession,
            ProxyTCPConnection | ProxyUDPConnection
        ] = ProxyBidict()
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
                        message = cast(ProxyTCPMessage | ProxyUDPMessage, upstream.result())
                        if message.flag == "SYN":
                            if self._signal == "SIGTERM" and self._boundary:
                                self._reject(0, message)
                                upstream = create_task(self._edges[0][0].get()) # type: ignore
                                continue
                            logger.debug(f"ExitNode: New session to {message.bound.host}")
                            # DNS
                            if not await resolveDNS(message.bound):
                                logger.debug(f"ExitNode: Failed to resolve {message.bound.host}, rejecting upstream session")
                                self._reject(0, message)
                                upstream = create_task(self._edges[0][0].get()) # type: ignore
                                continue
                            host = cast(IPv4Address | IPv6Address, message.bound.host)
                            # Connection construction
                            if isinstance(message, ProxyTCPMessage):
                                connection = ProxyTCPConnection(host, message.bound.port)
                            else:
                                connection = ProxyUDPConnection(host, message.bound.port)
                            self._map.set(message.bound, connection)
                        else:
                            connection = self._map.xgety(message.bound)
                        if not connection:
                            self._reject(0, message)
                            upstream = create_task(self._edges[0][0].get()) # type: ignore
                            continue
                        elif isinstance(connection, ProxyTCPConnection):
                            self._edges[1][1].put_nowait( # type: ignore
                                ProxyTCPPacket(connection, message.data, message.flag)
                            )
                        else:
                            self._edges[1][1].put_nowait( # type: ignore
                                ProxyUDPPacket(connection, message.data, message.flag)
                            )
                        if message.flag == "FIN":
                            logger.debug(f"ExitNode: Session closed {message.bound}")
                            self._map.ydiscard(connection)
                            if self._signal == "SIGTERM" and self._map.empty():
                                logger.info("ExitNode: All connection served, quitting (SIGTERM)")
                                self._running = False
                                return
                        upstream = create_task(self._edges[0][0].get()) # type: ignore
                    case _ if task is downstream:
                        packet = cast(ProxyTCPPacket | ProxyUDPPacket, downstream.result())
                        if packet.flag == "SYN":
                            logger.error("ExitSereverNode: Received SYN packet from downstream")
                            self._reject(1, packet)
                            downstream = create_task(self._edges[1][0].get()) # type: ignore
                            continue
                        session = self._map.ygetx(packet.bound)
                        if not session:
                            self._reject(1, packet)
                            downstream = create_task(self._edges[1][0].get()) # type: ignore
                            continue
                        if isinstance(session, ProxyTCPSession):
                            self._edges[0][1].put_nowait( # type: ignore
                                ProxyTCPMessage(session, packet.data, packet.flag)
                            )
                        else:
                            self._edges[0][1].put_nowait( # type: ignore
                                ProxyUDPMessage(session, packet.data, packet.flag)
                            )
                        if packet.flag == "FIN":
                            self._map.ydiscard(packet.bound)
                            if self._signal == "SIGTERM" and self._map.empty():
                                logger.info("ExitNode: All connection served, quitting (SIGTERM)")
                                self._running = False
                                return
                        downstream = create_task(self._edges[1][0].get()) # type: ignore
                    case _: # controller
                        signal = cast(ProxySignal, controller.result())
                        logger.info(f"ExitNode: Received {signal} signal")
                        if signal == "SIGKILL":
                            self._running = False
                            return
                        if signal == "SIGTERM":
                            if self._map.empty():
                                logger.info("ExitNode: All connection served, quitting (SIGTERM)")
                                self._running = False
                                return
                            self._signal = "SIGTERM"
                        controller = create_task(self._controller.get())

class MuxTCPUDPNode(ProxyNode):
    """
    Node that multiplexes TCP and UDP traffic.

    Has a TCP upstream, a UDP upstream and a mixed downstream. Accepts any
    `ProxyTCPPacket`, `ProxyUDPPacket`, `ProxyTCPMessage` or
    `ProxyUDPMessage`. The node does not mutate traffic and acts simply as
    a router.
    """
    _version = "0.1.0"
    __slots__ = (
        "_boundary",
        "_controller",
        "_edges",
        "_pool",
        "_running",
        "_signal",
    )
    def __init__(self, /, boundary: bool = False) -> None:
        self._controller: Queue[ProxySignal] = Queue()
        self._edges: list[ProxyEdgeEnd | None] = [None, None, None]
        self._running: bool = False
        self._boundary: bool = boundary

    async def run(self) -> ProxySignal | None:
        """
        Run `MuxTCPUDPNode`.
        """
        if self._running:
            logger.critical("Attempted to run a running MuxTCPUDPNode")
            return "SIGKILL"
        if len(self._edges) != 3 or not all(self._edges):
            logger.critical("Running improperly connected MuxTCPUDPNode")
            return "SIGKILL"
        logger.info("Running MuxTCPUDPNode...")
        self._running = True
        self._pool: set[
            ProxyTCPConnection | ProxyUDPConnection | ProxyTCPSession | ProxyUDPSession
        ] = set()
        self._signal: ProxySignal | None = None
        while not self._controller.empty():
            self._controller.get_nowait()

        controller = create_task(self._controller.get())
        tcp = create_task(self._edges[0][0].get()) # type: ignore
        udp = create_task(self._edges[1][0].get()) # type: ignore
        mux = create_task(self._edges[2][0].get()) # type: ignore
        while True:
            done, _ = await asyncio.wait(
                (controller, tcp, udp, mux),
                return_when=asyncio.FIRST_COMPLETED
            )
            for task in done:
                match task:
                    case _ if task is tcp:
                        packet = cast(ProxyTCPPacket | ProxyTCPMessage, tcp.result())
                        tcp = create_task(self._edges[0][0].get()) # type: ignore
                    case _ if task is udp:
                        packet = cast(ProxyUDPPacket | ProxyUDPMessage, udp.result())
                        udp = create_task(self._edges[1][0].get()) # type: ignore
                    case _ if task is mux:
                        packet = cast(ProxyTCPPacket | ProxyUDPPacket | ProxyTCPMessage | ProxyUDPMessage, mux.result())
                        if packet.flag == "SYN":
                            # Never
                            logger.error("MuxTCPUDPNode: Received SYN request from downstream, rejecting")
                            self._reject(2, packet)
                            mux = create_task(self._edges[2][0].get()) # type: ignore
                            continue
                        self._forward(int(isinstance(packet, ProxyUDPPacket | ProxyUDPMessage)), packet)
                        if packet.flag == "FIN":
                            self._pool.discard(packet.bound)
                            if self._signal == "SIGTERM" and not self._pool:
                                logger.info("MuxTCPUDPNode: All connection served, quitting (SIGTERM)")
                                self._running = False
                                return
                        mux = create_task(self._edges[2][0].get()) # type: ignore
                        continue
                    case _: # controller
                        signal = cast(ProxySignal, controller.result())
                        logger.info(f"MuxTCPUDPNode: Received {signal} signal")
                        if signal == "SIGKILL":
                            self._running = False
                            return
                        if signal == "SIGTERM":
                            if not self._pool:
                                logger.info("MuxTCPUDPNode: All connection served, quitting (SIGTERM)")
                                self._running = False
                                return
                            self._signal = "SIGTERM"
                        controller = create_task(self._controller.get())
                        continue
                if packet.flag == "SYN":
                    if self._signal == "SIGTERM" and self._boundary:
                        self._reject(int(isinstance(packet, (ProxyUDPPacket, ProxyUDPMessage))), packet)
                        continue
                    self._pool.add(packet.bound)
                self._forward(2, packet)
                if packet.flag == "FIN":
                    self._pool.discard(packet.bound)
                    if self._signal == "SIGTERM" and not self._pool:
                        logger.info("MuxTCPUDPNode: All connection served, quitting (SIGTERM)")
                        self._running = False
                        return

class DemuxTCPUDPNode(ProxyNode):
    """
    Node that demultiplexes TCP and UDP traffic.

    Has a mixed upstream, a TCP downstream and a UDP downstream. Accepts any
    `ProxyTCPPacket`, `ProxyUDPPacket`, `ProxyTCPMessage` or `ProxyUDPMessage`.
    The node does not mutate traffic and acts simply as a router.
    """
    _version = "0.1.0"
    __slots__ = (
        "_boundary",
        "_controller",
        "_edges",
        "_pool",
        "_running",
        "_signal",
    )
    def __init__(self, boundary: bool = False) -> None:
        self._controller: Queue[ProxySignal] = Queue()
        self._edges: list[ProxyEdgeEnd | None] = [None, None, None]
        self._running: bool = False
        self._boundary: bool = boundary

    async def run(self) -> ProxySignal | None:
        """
        Run `DemuxTCPUDPNode`.
        """
        if self._running:
            logger.critical("Attempted to run a running DemuxTCPUDPNode")
            return "SIGKILL"
        if len(self._edges) != 3 or not all(self._edges):
            logger.critical("Running improperly connected DemuxTCPUDPNode")
            return "SIGKILL"
        logger.info("Running DemuxTCPUDPNode...")
        self._running = True
        self._pool: set[
            ProxyTCPConnection | ProxyUDPConnection | ProxyTCPSession | ProxyUDPSession
        ] = set()
        self._signal: ProxySignal | None = None
        while not self._controller.empty():
            self._controller.get_nowait()

        controller = create_task(self._controller.get())
        mux = create_task(self._edges[0][0].get()) # type: ignore
        tcp = create_task(self._edges[1][0].get()) # type: ignore
        udp = create_task(self._edges[2][0].get()) # type: ignore
        while True:
            done, _ = await asyncio.wait(
                (controller, mux, tcp, udp),
                return_when=asyncio.FIRST_COMPLETED
            )
            for task in done:
                match task:
                    case _ if task is mux:
                        packet = cast(ProxyTCPPacket | ProxyUDPPacket | ProxyTCPMessage | ProxyUDPMessage, mux.result())
                        if packet.flag == "SYN":
                            if self._signal == "SIGTERM" and self._boundary:
                                self._reject(0, packet)
                                mux = create_task(self._edges[0][0].get()) # type: ignore
                                continue
                            self._pool.add(packet.bound)
                        self._forward(1 + int(isinstance(packet, ProxyUDPPacket | ProxyUDPMessage)), packet)
                        if packet.flag == "FIN":
                            self._pool.discard(packet.bound)
                            if self._signal == "SIGTERM" and not self._pool:
                                logger.info("DemuxTCPUDPNode: All connection served, quitting (SIGTERM)")
                                self._running = False
                                return
                        mux = create_task(self._edges[0][0].get()) # type: ignore
                        continue
                    case _ if task is tcp or task is udp:
                        packet = cast(ProxyTCPPacket | ProxyTCPMessage, tcp.result())
                        tcp = create_task(self._edges[1][0].get()) # type: ignore
                    case _ if task is udp:
                        packet = cast(ProxyUDPPacket | ProxyUDPMessage, udp.result())
                        udp = create_task(self._edges[1][0].get()) # type: ignore
                    case _: # controller
                        signal = cast(ProxySignal, controller.result())
                        logger.info(f"DemuxTCPUDPNode: Received {signal} signal")
                        if signal == "SIGKILL":
                            self._running = False
                            return
                        if signal == "SIGTERM":
                            if not self._pool:
                                logger.info("DemuxTCPUDPNode: All connection served, quitting (SIGTERM)")
                                self._running = False
                                return
                            self._signal = "SIGTERM"
                        controller = create_task(self._controller.get())
                        continue
                if packet.flag == "SYN":
                    # Never
                    logger.error("DemuxTCPUDPNode: Received SYN request from downstream, rejecting")
                    self._reject(1 + isinstance(packet, (ProxyUDPPacket, ProxyUDPMessage)), packet)
                    continue
                self._forward(0, packet)
                if packet.flag == "FIN":
                    self._pool.discard(packet.bound)
                    if self._signal == "SIGTERM" and not self._pool:
                        logger.info("DemuxTCPUDPNode: All connection served, quitting (SIGTERM)")
                        self._running = False
                        return
