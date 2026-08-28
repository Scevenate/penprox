from __future__ import annotations
from .framework import *
import socket
from ipaddress import IPv4Address, IPv6Address
from asyncio import Queue, create_task
import asyncio
from typing import Optional, Literal
from logging import getLogger

logger = getLogger(__name__)

class UpstreamTCPNode(ProxyNode):
    """
    Upstream network node that listens a TCP port. Only claims property
    ownership when running.

    Has one `ProxyPacket` downstream edge.

    Listen to port `0` to get an ephemeral port at `self.address()[2]` at
    runtime.

    Only listens to `localhost` by default. Change this to `0.0.0.0` if you
    want access from remote host.

    For multiple upstream sources, consider add a multiplexer middleware
    node.
    """
    _version = "0.1.0"
    __slots__ = (
        "_controller",
        "_edges",
        "_running",
        "_address",
        "_connections",
        "_signal"
    )
    def __init__(
        self,
        port: int,
        ip: IPv4Address | IPv6Address = IPv4Address("127.0.0.1")
    ):
        self._controller: Queue[ProxySignal] = Queue()
        self._edges: list[Optional[ProxyEdgeEnd]] = [None]
        self._running: bool = False
        self._address: ProxyTCPAddress = (ip, "TCP", port)
    def running(self):
        """
        Returns true iff the node is running.
        """
        return self._running
    def edges(self):
        """
        Get edge ends of the node.

        Must have exactly one `ProxyPacket` downstream edge.
        """
        return self._edges
    def controller(self):
        """
        Get the controller end of the node.
        """
        return self._controller
    def address(self):
        """
        Get the address of the node.
        """
        return self._address
    class _UpstreamTCPProtocol(asyncio.Protocol):
        __slots__ = (
            "_node",
            "_connection"
        )
        def __init__(self, node: UpstreamTCPNode):
            self._node: UpstreamTCPNode = node
        def connection_made( # type: ignore
            self,
            transport: asyncio.Transport
        ):
            if self._node._signal == "SIGTERM":
                transport.close()
            remoteAddr = transport.get_extra_info("peername")
            connection = ProxyTCPConnection(
                transport,
                (
                    remoteAddr[0],
                    "TCP",
                    remoteAddr[1]
                )
            )
            self._connection: ProxyTCPConnection = connection
            self._node._connections.add(connection)
            self._node._edges[0][1].put_nowait( # type: ignore
                ProxyPacket(connection, b"", "SYN")
            )
        def data_received(self, data: bytes) -> None:
            self._node._edges[0][1].put_nowait( # type: ignore
                ProxyPacket(self._connection, data, None)
            ) 
        def connection_lost(self, exc: Exception | None) -> None:
            self._node._edges[0][1].put_nowait( # type: ignore
                ProxyPacket(self._connection, b"", "FIN")
            )
            self._node._connections.discard(self._connection)
            if self._node._signal == "SIGTERM" and not self._node._connections:
                self._node._controller.put_nowait("SIGKILL")

    async def _dispatch(self) -> None:
        try:
            while True:
                packet: ProxyPacket = await self._edges[0][0].get() # type: ignore
                if packet.connection.remoteAddress[1] != "TCP":
                    # This is clearly misconfiguration
                    # Instead of silently rejecting connection, we kill
                    raise ValueError("Invalid packet type")
                transport: asyncio.Transport = packet.connection.transport # type: ignore
                if transport.is_closing():
                    # Possible close race between remote and downstream
                    # In this case, connection_lost will send FIN
                    continue
                transport.write(packet.data)
                if packet.flag == "FIN":
                    # We'll leave the rest to connection_lost
                    transport.close()
                    continue
        except asyncio.CancelledError:
            return

    async def run(self) -> Optional[Literal['SIGKILL', 'SIGTERM']]:
        """
        Run `UpstreamTCPNode`.

        Immediately claims immutable ownership of its attributes.
        """
        if self._running:
            logger.critical("Attempted to run a running UpstreamTCPNode")
            return "SIGKILL"
        if len(self._edges) != 1 or not self._edges[0]:
            logger.critical("Running improperly connected UpstreamTCPNode")
            return "SIGKILL"
        logger.info("Running UpstreamTCPNode...")
        self._running = True
        self._connections: set[ProxyTCPConnection] = set()
        self._signal: Optional[ProxySignal] = None
        while not self._controller.empty():
            self._controller.get_nowait()

        address = self._address
        loop = asyncio.get_running_loop()
        sock = socket.socket(socket.AF_INET6 if isinstance(address[0],
            IPv6Address) else socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setblocking(False)
        if isinstance(address[0], IPv6Address):
            sock.bind((str(address[0]), address[2], 0, 0))
        else:
            sock.bind((str(address[0]), address[2]))
        if not address[2]:
            addr = sock.getsockname()
            self._address = (
                address[0],
                "TCP",
                addr[1]
            )
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
            signal = done.pop().result()
            if signal == "SIGKILL" or \
                signal == "SIGTERM" and not self._connections:
                server.cancel()
                dispatcher.cancel()
                self._running = False
                return
            self._signal = signal
            controller = create_task(self._controller.get())

class UpstreamUDPNode(ProxyNode):
    """
    Upstream network node that listens a UDP port. Only claims property
    ownership when running.

    Has one `ProxyPacket` downstream edge.

    Listen to port `0` to get an ephemeral port at `self.address()[2]` at
    runtime.

    Only listens to `localhost` by default. Change this to `0.0.0.0` if you
    want access from remote host.

    For multiple upstream sources, consider add a multiplexer middleware
    node.
    """
    _version = "0.1.0"
    __slots__ = (
        "_controller",
        "_edges",
        "_running",
        "_address",
        "_transport",
        "_connections",
        "_signal",
    )
    def __init__(
        self,
        port: int,
        ip: IPv4Address | IPv6Address = IPv4Address("127.0.0.1")
    ):
        self._controller: Queue[ProxySignal] = Queue()
        self._edges: list[Optional[ProxyEdgeEnd]] = [None]
        self._running: bool = False
        self._address: ProxyAddress = (ip, "UDP", port)
    def running(self):
        """
        Returns true iff the node is running.
        """
        return self._running
    def edges(self):
        """
        Get edge ends of the node.

        Must have exactly one `ProxyPacket` downstream edge.
        """
        return self._edges
    def controller(self):
        """
        Get the controller end of the node.
        """
        return self._controller
    def address(self):
        """
        Get the address of the node.
        """
        return self._address
    class _UpstreamUDPProtocol(asyncio.DatagramProtocol):
        __slots__ = (
            "_node",
        )
        def __init__(self, node: UpstreamUDPNode):
            self._node = node
        def connection_made(self, transport):
            self._node._transport = transport 
        def datagram_received(self, data: bytes, addr: tuple) -> None:
            node = self._node
            if node._signal == "SIGTERM":
                return
            remote = (addr[0], "UDP", addr[1])
            connection = self._node._connections.get(remote)
            if connection is None:
                connection = ProxyUDPConnection(
                    node._transport,
                    remoteAddress=remote
                )
                node._connections[remote] = connection
                node._edges[0][1].put_nowait( # type: ignore
                    ProxyPacket(connection, data, "SYN")
                )
            else:
                node._edges[0][1].put_nowait( # type: ignore
                    ProxyPacket(connection, data, None)
                )

    async def _dispatch(self) -> None:
        try:
            while True:
                packet: ProxyPacket = await self._edges[0][0].get() # type: ignore
                if packet.connection.remoteAddress[1] != "UDP":
                    raise ValueError("Invalid packet type")
                if self._transport.is_closing():
                    raise ConnectionError("Unexpected transport close")
                host, _, port = packet.connection.remoteAddress
                self._transport.sendto(packet.data, (host, port))
                if packet.flag == "FIN":
                    self._connections.pop(packet.connection.remoteAddress, None)
                    if self._signal == "SIGTERM" and not self._connections:
                        self._controller.put_nowait("SIGKILL")
                    continue
        except asyncio.CancelledError:
            return

    async def run(self) -> Optional[Literal['SIGKILL', 'SIGTERM']]:
        """
        Run `UpstreamUDPNode`.

        Immediately claims immutable ownership of its attributes.
        """
        if self._running:
            logger.critical("Attempted to run a running UpstreamUDPNode")
            return "SIGKILL"
        if len(self._edges) != 1 or not self._edges[0]:
            logger.critical("Running improperly connected UpstreamUDPNode")
            return "SIGKILL"
        logger.info("Running UpstreamUDPNode...")
        self._running = True
        self._connections: dict[ProxyUDPAddress, ProxyUDPConnection] = {}
        self._signal: Optional[ProxySignal] = None
        while not self._controller.empty():
            self._controller.get_nowait()

        address = self._address
        loop = asyncio.get_running_loop()
        sock = socket.socket(socket.AF_INET6 if isinstance(address[0],
            IPv6Address) else socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setblocking(False)
        if isinstance(address[0], IPv6Address):
            sock.bind((str(address[0]), address[2], 0, 0))
        else:
            sock.bind((str(address[0]), address[2]))
        if not address[2]:
            addr = sock.getsockname()
            self._address = (
                address[0],
                "UDP",
                addr[1]
            )

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
                dispatcher.cancel()
                self._transport.close()
                self._running = False
                return None if self._signal else "SIGKILL"
            signal = done.pop().result()
            if signal == "SIGKILL" or \
                signal == "SIGTERM" and not self._connections:
                dispatcher.cancel()
                self._transport.close()
                self._running = False
                return
            self._signal = signal
            controller = create_task(self._controller.get())


class DownstreamTCPNode(ProxyNode):
    """
    Downstream network servant node. Only claims property ownership
    when running.

    Has one `ProxyPacket` upstream edge.

    Accepts upstream constructed `ProxyConnection`.
    """
    _version = "0.1.0"
    __slots__ = (
        "_controller",
        "_edges",
        "_running",
        "_connections",
        "_signal",
    )
    def __init__(self):
        self._controller: Queue[ProxySignal] = Queue()
        self._edges: list[Optional[ProxyEdgeEnd]] = [None]
        self._running: bool = False
    def running(self):
        """
        Returns true iff the node is running.
        """
        return self._running
    def edges(self):
        """
        Get edge ends of the node.

        Must have exactly one `ProxyPacket` upstream edge.
        """
        return self._edges
    def controller(self):
        """
        Get the controller end of the node.
        """
        return self._controller
    class _DownstreamTCPProtocol(asyncio.Protocol):
        __slots__ = (
            "_node",
            "_connection"
        )
        def __init__(self, node: DownstreamTCPNode, connection: ProxyTCPConnection):
            self._node = node
            self._connection = connection
        def connection_made( # type: ignore
            self,
            transport: asyncio.Transport
        ):
            self._connection.transport = transport
            self._node._connections.add(self._connection)
        def data_received(self, data: bytes) -> None:
            self._node._edges[0][1].put_nowait( # type: ignore
                ProxyPacket(self._connection, data, None)
            )
        def connection_lost(self, exc: Exception | None) -> None:
            self._node._edges[0][1].put_nowait( # type: ignore
                ProxyPacket(self._connection, b"", "FIN")
            )
            self._node._connections.discard(self._connection)
            if self._node._signal == "SIGTERM" and not self._node._connections:
                self._node._controller.put_nowait("SIGKILL")

    async def _dispatch(self) -> None:
        try:
            while True:
                packet: ProxyPacket = await self._edges[0][0].get() # type: ignore
                connection: ProxyTCPConnection = packet.connection # type: ignore
                if connection.remoteAddress[1] != "TCP":
                    raise ValueError("Invalid packet type")
                if packet.flag == "SYN":
                    loop = asyncio.get_running_loop()
                    protocol = DownstreamTCPNode._DownstreamTCPProtocol(
                        self, connection
                    )
                    # We only await next packet after current iteration
                    # So the next packet would only be read after transport
                    # assignment
                    try:
                        transport, _ = await loop.create_connection(
                            lambda: protocol,
                            str(connection.remoteAddress[0]),
                            connection.remoteAddress[2],
                        )
                    except OSError:
                        self._edges[0][1].put_nowait(ProxyPacket( # type: ignore
                            connection,
                            b"",
                            "FIN"
                        ))
                        continue
                else:
                    transport: asyncio.Transport = connection.transport # type: ignore
                if transport.is_closing():
                    raise ConnectionError("Unexpected transport close")
                transport.write(packet.data)
                if packet.flag == "FIN":
                    # We'll leave the rest to connection_lost
                    transport.close()
                    continue
        except asyncio.CancelledError:
            return

    async def run(self) -> Optional[Literal['SIGKILL', 'SIGTERM']]:
        """
        Run `DownstreamTCPNode`.

        Immediately claims immutable ownership of its attributes.
        """
        if self._running:
            logger.critical("Attempted to run a running DownstreamTCPNode")
            return "SIGKILL"
        if len(self._edges) != 1 or not self._edges[0]:
            logger.critical("Running improperly connected DownstreamTCPNode")
            return "SIGKILL"
        logger.info("Running DownstreamTCPNode...")
        self._running = True
        self._connections: set[ProxyTCPConnection] = set()
        self._signal: Optional[ProxySignal] = None
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
                dispatcher.cancel()
                self._running = False
                return None if self._signal else "SIGKILL"
            signal = done.pop().result()
            if signal == "SIGKILL" or \
                signal == "SIGTERM" and not self._connections:
                for conn in self._connections:
                    conn.transport.close() # type: ignore
                dispatcher.cancel()
                self._running = False
                return
            self._signal = signal
            controller = create_task(self._controller.get())


class DownstreamUDPNode(ProxyNode):
    """
    Downstream network node that dials outbound UDP endpoints. Only
    claims property ownership when running.

    Has one `ProxyPacket` upstream edge.

    Accepts upstream constructed `ProxyConnection`.
    """
    _version = "0.1.0"
    __slots__ = (
        "_controller",
        "_edges",
        "_running",
        "_transport",
        "_connections",
        "_signal",
    )
    def __init__(self):
        self._controller: Queue[ProxySignal] = Queue()
        self._edges: list[Optional[ProxyEdgeEnd]] = [None]
        self._running: bool = False
        
    def running(self):
        """
        Returns true iff the node is running.
        """
        return self._running
    def edges(self):
        """
        Get edge ends of the node.

        Must have exactly one `ProxyPacket` upstream edge.
        """
        return self._edges
    def controller(self):
        """
        Get the controller end of the node.
        """
        return self._controller
    class _DownstreamUDPProtocol(asyncio.DatagramProtocol):
        __slots__ = (
            "_node",
        )
        def __init__(self, node: DownstreamUDPNode):
            self._node = node
        def connection_made(self, transport):
            self._node._transport = transport
        def datagram_received(self, data: bytes, addr: tuple) -> None:
            node = self._node
            if node._signal == "SIGTERM":
                return
            remote = (addr[0], "UDP", addr[1])
            connection = node._connections.get(remote)
            if connection is None:
                connection = ProxyUDPConnection(
                    node._transport,
                    remoteAddress=remote
                )
                node._connections[remote] = connection
                node._edges[0][1].put_nowait( # type: ignore
                    ProxyPacket(connection, data, "SYN")
                )
            else:
                node._edges[0][1].put_nowait( # type: ignore
                    ProxyPacket(connection, data, None)
                )

    async def _dispatch(self) -> None:
        try:
            while True:
                packet = await self._edges[0][0].get() # type: ignore
                connection: ProxyUDPConnection = packet.connection # type: ignore
                if connection.remoteAddress[1] != "UDP":
                    raise ValueError("Invalid packet type")
                if self._transport.is_closing():
                    raise ConnectionError("Unexpected transport close")
                if packet.flag == "SYN":
                    self._connections[connection.remoteAddress] = connection
                host, _, port = connection.remoteAddress
                self._transport.sendto(packet.data, (host, port))
                if packet.flag == "FIN":
                    self._connections.pop(connection.remoteAddress, None)
                    if self._signal == "SIGTERM" and not self._connections:
                        self._controller.put_nowait("SIGKILL")
                    continue
        except asyncio.CancelledError:
            return

    async def run(self) -> Optional[Literal['SIGKILL', 'SIGTERM']]:
        """
        Run `DownstreamUDPNode`.

        Immediately claims immutable ownership of its attributes.
        """
        if self._running:
            logger.critical("Attempted to run a running DownstreamUDPNode")
            return "SIGKILL"
        if len(self._edges) != 1 or not self._edges[0]:
            logger.critical("Running improperly connected DownstreamUDPNode")
            return "SIGKILL"
        logger.info("Running DownstreamUDPNode...")
        self._running = True
        self._connections: dict[ProxyUDPAddress, ProxyUDPConnection] = {}
        self._signal: Optional[ProxySignal] = None
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
                dispatcher.cancel()
                self._transport.close()
                self._running = False
                return None if self._signal else "SIGKILL"
            signal = done.pop().result()
            if signal == "SIGKILL" or \
                signal == "SIGTERM" and not self._connections:
                dispatcher.cancel()
                if self._transport:
                    self._transport.close()
                self._running = False
                return
            self._signal = signal
            controller = create_task(self._controller.get())


class ExitServerNode(ProxyNode):
    """
    Exit server node that resolves proxy request locally.

    Has one `ProxyMessage` upstream request end and one `ProxyPacket`
    downstream internet end.
    
    Resolves request domain name by system DNS. Consider adding
    a DNS middleware node if you want custom DNS resolution.

    Serves both TCP and UDP. Consider adding a demultiplexing node if you
    use both.
    """
    _version = "0.1.0"
    __slots__ = (
        "_controller",
        "_edges",
        "_running",
        "_map",
        "_signal",
    )
    def __init__(self):
        self._controller: Queue[ProxySignal] = Queue()
        self._edges: list[Optional[ProxyEdgeEnd]] = [None, None]
        self._running: bool = False
        
    def running(self):
        """
        Returns true iff the node is running.
        """
        return self._running
    def edges(self):
        """
        Get edge ends of the node.

        Must have one `ProxyMessage` request upstream and one
        `ProxyPacket` internet downstream edge.
        """
        return self._edges
    def controller(self):
        """
        Get the controller end of the node.
        """
        return self._controller
    async def run(self) -> Optional[Literal['SIGKILL', 'SIGTERM']]:
        """
        Run `ExitServerNode`.

        Immediately claims immutable ownership of its attributes.
        """
        if self._running:
            logger.critical("Attempted to run a running ExitServerNode")
            return "SIGKILL"
        if len(self._edges) != 2 or not all(self._edges):
            logger.critical("Running improperly connected ExitServerNode")
            return "SIGKILL"
        logger.info("Running ExitServerNode...")
        self._running = True
        self._map: ProxyBidict[ProxyRequest, ProxyConnection] = ProxyBidict()
        self._signal: Optional[ProxySignal] = None
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
                        message: ProxyMessage = upstream.result() # type: ignore
                        if message.flag == "SYN":
                            if self._signal == "SIGTERM":
                                self._edges[0][1].put_nowait(ProxyMessage( # type: ignore
                                    message.request,
                                    b"",
                                    "FIN"
                                ))
                                continue
                            # DNS
                            if isinstance(message.request.destination, str):
                                ip = socket.gethostbyname(message.request.destination)
                                message.request.destination = IPv4Address(ip)
                            # connection construction
                            if message.request.transport == "TCP":
                                connection = ProxyTCPConnection(
                                    None,
                                    (
                                        message.request.destination,
                                        "TCP",
                                        message.request.port
                                    )
                                )
                            else:
                                connection = ProxyUDPConnection(
                                    None,
                                    (
                                        message.request.destination,
                                        "UDP",
                                        message.request.port
                                    )
                                )
                            self._map.set(message.request, connection)
                        self._edges[1][1].put_nowait(ProxyPacket( # type: ignore
                            self._map.getx(message.request),
                            message.data,
                            message.flag
                        ))
                        if message.flag == "FIN":
                            self._map.discardx(message.request)
                            if self._signal == "SIGTERM" and self._map.empty():
                                return
                    case _ if task is downstream:
                        packet: ProxyPacket = downstream.result() # type: ignore
                        if packet.flag == "SYN":
                            # Never
                            logger.error("ExitServerNode received SYN request from downstream, rejecting")
                            self._edges[1][1].put_nowait(ProxyPacket( # type: ignore
                                packet.connection,
                                b"",
                                "FIN"
                            ))
                            continue
                        self._edges[0][1].put_nowait(ProxyMessage( # type: ignore
                            self._map.gety(packet.connection),
                            packet.data,
                            packet.flag
                        ))
                        if packet.flag == "FIN":
                            self._map.discardy(packet.connection)
                            if self._signal == "SIGTERM" and self._map.empty():
                                return
                    case _ if task is controller:
                        signal = controller.result()
                        if signal == "SIGKILL":
                            self._running = False
                            return
                        if signal == "SIGTERM":
                            if self._map.empty():
                                return
                            self._signal = "SIGTERM"


class MuxTCPUDPNode(ProxyNode):
    """
    Node that multiplexes TCP and UDP traffic. Most useful when listening
    both TCP and UDP upstreams.

    Has a TCP upstream, a UDP upstream and a mixed downstream. Accepts any
    `ProxyPacket` or `ProxyMessage`; It just separates them by TCP / UDP.

    The node does not mutate traffic and acts simply as a router.
    """
    _version = "0.1.0"
    __slots__ = (
        "_controller",
        "_edges",
        "_running",
        "_pool",
        "_signal",
    )
    def __init__(self):
        self._controller: Queue[ProxySignal] = Queue()
        self._edges: list[Optional[ProxyEdgeEnd]] = [None, None, None]
        self._running: bool = False
        
    def running(self):
        """
        Returns true iff the node is running.
        """
        return self._running
    def edges(self):
        """
        Get edge ends of the node.

        Must have a TCP upstream, a UDP upstream and a mixed downstream.
        """
        return self._edges
    def controller(self):
        """
        Get the controller end of the node.
        """
        return self._controller
    def _reject(self, index: int, result: ProxyPacket | ProxyMessage) -> None:
        """
        Reject new `ProxyPacket` or `ProxyMessage` SYN back.
        """
        if isinstance(result, ProxyPacket):
            self._edges[index][1].put_nowait(ProxyPacket( # type: ignore
                result.connection,
                b"",
                "FIN"
            ))
        else:
            self._edges[index][1].put_nowait(ProxyMessage( # type: ignore
                result.request,
                b"",
                "FIN"
            ))
    def _forward(self, index: int, result: ProxyPacket | ProxyMessage) -> bool:
        """
        `tcp` & `udp` forward routing.

        `True` iff run should terminate.
        """
        if result.flag == "SYN":
            if self._signal == "SIGTERM":
                self._reject(index, result)
                return False
            self._pool.add(result.connection if isinstance(result, ProxyPacket) else result.request)
        self._edges[2][1].put_nowait(result) # type: ignore
        if result.flag == "FIN":
            self._pool.discard(result.connection if isinstance(result, ProxyPacket) else result.request)
            if self._signal == "SIGTERM" and not self._pool:
                return True
        return False
    def _backward(self, result: ProxyPacket | ProxyMessage) -> bool:
        """
        `mux` backward routing.

        `True` iff run should terminate.
        """
        if result.flag == "SYN":
            # Never
            logger.error("MuxTCPUDPNode received SYN request from downstream, rejecting")
            self._reject(2, result)
            return False
        if isinstance(result, ProxyPacket):
            index = 0 if result.connection.remoteAddress[1] == "TCP" else 1
        else:
            index = 0 if result.request.transport == "TCP" else 1
        self._edges[index][1].put_nowait(result) # type: ignore
        if result.flag == "FIN":
            self._pool.discard(result.connection if isinstance(result, ProxyPacket) else result.request)
            if self._signal == "SIGTERM" and not self._pool:
                return True
        return False
    async def run(self) -> Optional[Literal['SIGKILL', 'SIGTERM']]:
        """
        Run `MuxTCPUDPNode`.

        Immediately claims immutable ownership of its attributes.
        """
        if self._running:
            logger.critical("Attempted to run a running MuxTCPUDPNode")
            return "SIGKILL"
        if len(self._edges) != 3 or not all(self._edges):
            logger.critical("Running improperly connected MuxTCPUDPNode")
            return "SIGKILL"
        logger.info("Running MuxTCPUDPNode...")
        self._running = True
        self._pool: set[ProxyConnection | ProxyRequest] = set()
        self._signal: Optional[ProxySignal] = None
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
                        if self._forward(0, tcp.result()):
                            self._running = False
                            return
                        tcp = create_task(self._edges[0][0].get()) # type: ignore
                    case _ if task is udp:
                        if self._forward(1, udp.result()):
                            self._running = False
                            return
                        udp = create_task(self._edges[1][0].get()) # type: ignore
                    case _ if task is mux:
                        if self._backward(mux.result()):
                            self._running = False
                            return
                        mux = create_task(self._edges[2][0].get()) # type: ignore
                    case _ if task is controller:
                        signal = controller.result()
                        if signal == "SIGKILL":
                            self._running = False
                            return
                        if signal == "SIGTERM":
                            if not self._pool:
                                self._running = False
                                return
                            self._signal = "SIGTERM"
                            controller = create_task(self._controller.get())

class DemuxTCPUDPNode(ProxyNode):
    """
    Node that demultiplexes TCP and UDP traffic.

    Has a mixed upstream, a TCP downstream and a UDP downstream. Accepts any
    `ProxyPacket` or `ProxyMessage`; It just separates them by TCP / UDP.

    The node does not mutate traffic and acts simply as a router.
    """
    _version = "0.1.0"
    __slots__ = (
        "_controller",
        "_edges",
        "_running",
        "_pool",
        "_signal",
    )
    def __init__(self):
        self._controller: Queue[ProxySignal] = Queue()
        self._edges: list[Optional[ProxyEdgeEnd]] = [None, None, None]
        self._running: bool = False

    def running(self):
        """
        Returns true iff the node is running.
        """
        return self._running
    def edges(self):
        """
        Get edge ends of the node.

        Must have a mixed upstream, a TCP downstream and a UDP downstream.
        """
        return self._edges
    def controller(self):
        """
        Get the controller end of the node.
        """
        return self._controller
    def _reject(self, index: int, result: ProxyPacket | ProxyMessage) -> None:
        """
        Reject new `ProxyPacket` or `ProxyMessage` SYN back.
        """
        if isinstance(result, ProxyPacket):
            self._edges[index][1].put_nowait(ProxyPacket( # type: ignore
                result.connection,
                b"",
                "FIN"
            ))
        else:
            self._edges[index][1].put_nowait(ProxyMessage( # type: ignore
                result.request,
                b"",
                "FIN"
            ))
    def _forward(self, index: int, result: ProxyPacket | ProxyMessage) -> bool:
        """
        `mux` forward routing.

        `True` iff run should terminate.
        """
        if result.flag == "SYN":
            if self._signal == "SIGTERM":
                self._reject(index, result)
                return False
            self._pool.add(result.connection if isinstance(result, ProxyPacket) else result.request)
        if isinstance(result, ProxyPacket):
            target = 1 if result.connection.remoteAddress[1] == "TCP" else 2
        else:
            target = 1 if result.request.transport == "TCP" else 2
        self._edges[target][1].put_nowait(result) # type: ignore
        if result.flag == "FIN":
            self._pool.discard(result.connection if isinstance(result, ProxyPacket) else result.request)
            if self._signal == "SIGTERM" and not self._pool:
                return True
        return False
    def _backward(self, index: int, result: ProxyPacket | ProxyMessage) -> bool:
        """
        `tcp` & `udp` backward routing.

        `True` iff run should terminate.
        """
        if result.flag == "SYN":
            # Never
            logger.error("DemuxTCPUDPNode received SYN request from downstream, rejecting")
            self._reject(index, result)
            return False
        self._edges[0][1].put_nowait(result) # type: ignore
        if result.flag == "FIN":
            self._pool.discard(result.connection if isinstance(result, ProxyPacket) else result.request)
            if self._signal == "SIGTERM" and not self._pool:
                return True
        return False
    async def run(self) -> Optional[Literal['SIGKILL', 'SIGTERM']]:
        """
        Run `DemuxTCPUDPNode`.

        Immediately claims immutable ownership of its attributes.
        """
        if self._running:
            logger.critical("Attempted to run a running DemuxTCPUDPNode")
            return "SIGKILL"
        if len(self._edges) != 3 or not all(self._edges):
            logger.critical("Running improperly connected DemuxTCPUDPNode")
            return "SIGKILL"
        logger.info("Running DemuxTCPUDPNode...")
        self._running = True
        self._pool: set[ProxyConnection | ProxyRequest] = set()
        self._signal: Optional[ProxySignal] = None
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
                        if self._forward(0, mux.result()):
                            self._running = False
                            return
                        mux = create_task(self._edges[0][0].get()) # type: ignore
                    case _ if task is tcp:
                        if self._backward(1, tcp.result()):
                            self._running = False
                            return
                        tcp = create_task(self._edges[1][0].get()) # type: ignore
                    case _ if task is udp:
                        if self._backward(2, udp.result()):
                            self._running = False
                            return
                        udp = create_task(self._edges[2][0].get()) # type: ignore
                    case _ if task is controller:
                        signal = controller.result()
                        if signal == "SIGKILL":
                            self._running = False
                            return
                        if signal == "SIGTERM":
                            if not self._pool:
                                self._running = False
                                return
                            self._signal = "SIGTERM"
                            controller = create_task(self._controller.get())
