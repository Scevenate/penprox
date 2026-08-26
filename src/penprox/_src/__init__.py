from __future__ import annotations
from abc import ABC, abstractmethod
from dataclasses import dataclass
import socket
from ipaddress import IPv4Address, IPv6Address
from asyncio import Queue
import asyncio
from culsans import AsyncQueue
from typing import Optional, Literal
from logging import getLogger
from itertools import chain

logger = getLogger(__name__)

ProxyTCPAddress = tuple[
    IPv4Address | IPv6Address,
    Literal["TCP"],
    int
]

ProxyUDPAddress = tuple[
    IPv4Address | IPv6Address,
    Literal["UDP"],
    int
]

ProxyAddress = ProxyTCPAddress | ProxyUDPAddress

@dataclass(eq=False, slots=True)
class ProxyTCPConnection:
    """
    A conceptual TCP connection. Mostly being identity compared as
    `ProxyConnection`.

    Transport is `None` Only when being passed in a downstream SYN packet.
    """
    transport: Optional[asyncio.Transport]
    remoteAddress: ProxyTCPAddress

@dataclass(eq=False, slots=True)
class ProxyUDPConnection:
    """
    A conceptual UDP connection. Mostly being identity compared as
    `ProxyConnection`.
    
    All UDP traffic using one endpoint share the same
    transport, and local nodes are always responsible for closing the
    connection.

    Transport is `None` Only when being passed in a downstream SYN packet.
    """
    transport: Optional[asyncio.DatagramTransport]
    remoteAddress: ProxyUDPAddress

ProxyConnection = ProxyTCPConnection | ProxyUDPConnection

@dataclass(eq=False, slots=True)
class ProxyPacket:
    """
    A conceptual network packet. Nodes should respect packet atomicity
    unless otherwise documented.

    Outbound connections are instantiated by the most upstream node,
    then run downstream by sending it in a SYN notification; Other than
    this exception, connections can only be used for identity comparison.
    """
    connection: ProxyConnection
    data: bytes
    flag: Optional[Literal["SYN", "FIN"]]

@dataclass(eq=False, slots=True)
class ProxyRequest:
    """
    A semantic proxy request. Always constructed by upstream proxy server.

    Different from `ProxyConnection`, domain names are allowed, and downstream
    nodes are allowed to resolve & mutate destination domain in async runtime.
    """
    destination: IPv4Address | IPv6Address | str
    transport: Literal["TCP", "UDP"]
    port: int

@dataclass(eq=False, slots=True)
class ProxyMessage:
    """
    A conceptual message in `ProxyRequest`. Nodes should respect
    message atomicity unless otherwise documented.

    `SYN` message always comes from upstream; Downstream may push
    `FIN` messages back.
    """
    connection: ProxyRequest
    data: bytes
    flag: Optional[Literal["SYN", "FIN"]]

# A list of unidirectional signals.
# Caution: implementor must carefully review existing signal handlers
# if they want to extend this list.
ProxySignal = Literal[
    # Asks a node to stop serving new proxy requests and quit after
    # serving current ones
    # Notice that this onlyl gatekeeps upstream network nodes to prevent
    # data races; Other nodes keeps serving as usual until their states
    # are fully cleared.
    "SIGTERM",
    # Asks a node to immediately clear up its resource and return
    # Effort to maintain a consistent graph is not required
    # This signal overwrites SIGTERM
    "SIGKILL" 
]

ProxyEdgeEnd = tuple[
    Queue[ProxyPacket | ProxyMessage], 
    Queue[ProxyPacket | ProxyMessage]
]

def ProxyEdge() -> tuple[ProxyEdgeEnd, ProxyEdgeEnd]:
    """
    A bidirectional async pipe for `ProxyPacket` or `ProxyMessage`.

    The first queue in an end is the consumer; The second is producer.
    """
    q1, q2 = Queue(), Queue()
    return (
        (q1, q2),
        (q2, q1)
    )

class ProxyNode(ABC):
    """
    ABC for all nodes.

    This class declares abstract ProxyNode interface and
    some common syntactic sugar on top of it.

    Implementor should define class __slots__ and _version,
    then concrete abstract methods.
    """
    __slots__ = ()

    _version = "" # Don't fallback to an innocent version number
    @classmethod
    def version(cls) -> str:
        """
        Implementor must define a deterministic version string.

        There is no retrictions on formats whatsoever,
        but following upstream version conventions or
        semantic versioning is recommended.
        """
        return cls._version
    @abstractmethod
    def edges(self) -> list[Optional[ProxyEdgeEnd]]:
        """
        Get the node's edges. The plugging order should be documented.

        Do not mutate when running.
        """
        ...
    @abstractmethod
    def controller(self) -> Queue[ProxySignal]:
        """
        Get the node's controller end. (mpsc)
        """
        ...
    @abstractmethod
    def running(self) -> bool:
        """
        Returns `True` iff the node is running.
        """
    @abstractmethod
    async def run(self) -> Optional[ProxySignal]:
        """
        Run the node. Raises `RuntimeError` if the node is already running,
        raises `ValueError` if the node is misconfigured.

        The node may return a signal to be broadcasted. The node may also
        just propagate an exception to `ProxyGraph`, which will broadcast
        `SIGKILL`.

        For Implementors: `SIGKILL` is the preferred signal on exception
        to prevent active probing.
        """
        ...
    def __add__(self, other: ProxyNode | ProxyGraph) -> ProxyGraph:
        """
        Syntactic sugar for putting nodes into graphs.

        Raises `RuntimeError` if anything is running.
        """
        if self.running() or other.running():
            raise RuntimeError("Cannot add while running")
        if isinstance(other, ProxyNode):
            return ProxyGraph(self, other)
        other.nodes().append(self)
        return other
    def __gt__(self, other: ProxyNode | ProxyGraph) -> ProxyGraph:
        """
        Syntactic sugar for connecting nodes & graphs.

        Connects LHS `None` edge slots with RHS `None` edge slots
        in iteration order, until either side is full.

        Raises `RuntimeError` if anything is running.
        """
        # LHS and RHS are completely symmetric, so we only impl __gt__
        if self.running() or other.running():
            raise RuntimeError("Cannot add while running")
        lhs = enumerate(self.edges())
        if isinstance(other, ProxyNode):
            rhs = enumerate(other.edges())
        else:
            rhs = enumerate(chain.from_iterable(
                node.edges() for node in other.nodes()
            ))
        try:
            while True:
                while True:
                    indexLhsSlot, lhsSlot = next(lhs)
                    if lhsSlot == None:
                        break
                while True:
                    indexRhsSlot, rhsSlot = next(rhs)
                    if rhsSlot == None:
                        break
                edge = ProxyEdge()
                self.edges()[indexLhsSlot] = edge[0]
                if isinstance(other, ProxyNode):
                    other.edges()[indexRhsSlot] = edge[1]
                else:
                    nodes = iter(other.nodes())
                    node = next(nodes)
                    while indexRhsSlot >= len(node.edges()):
                        indexRhsSlot -= len(node.edges())
                        node = next(nodes)
                    node.edges()[indexRhsSlot] = edge[1]
        except StopIteration:
            if isinstance(other, ProxyNode):
                return ProxyGraph(self, other)
            return self + other

class ProxyGraph:
    """
    A referential list that groups node together. Only claims node ownership
    iff the graph is run.

    Used for connecting nodes and managing async runtime.
    """
    __slots__ = (
        "_nodes",
        "_running",
        "_controller"
    )
    def __init__(self, *nodes: ProxyNode):
        self._nodes: list[ProxyNode] = list(nodes)
        self._running: bool = False
        self._controller: Optional[AsyncQueue[ProxySignal]] = None

    def nodes(self) -> list[ProxyNode]:
        """
        Get nodes in the graph.

        Do not mutate when the graph is running.
        """
        return self._nodes

    def running(self) -> bool:
        """
        Returns `True` iff the graph is running.
        """
        return self._running

    @property
    def controller(self) -> Optional[AsyncQueue[ProxySignal]]:
        """
        The sync / async control handler of the graph.

        Use to broadcast control signal to nodes in the async runtime.

        Attempt to mutate the handle when the graph is running raises
        `RuntimeError`.

        Users must manage `Queue` lifetime by themselves.
        """
        return self._controller
    @controller.setter
    def controller(self, value: Optional[AsyncQueue[ProxySignal]]):
        if self._running:
            return RuntimeError("Mutation of controller handle during async runtime is not allowed")
        self._controller = value

    def __add__(self, other: ProxyNode | ProxyGraph) -> ProxyGraph:
        """
        Syntactic sugar for adding nodes or merging graphs.

        Raises `RuntimeError` if anything is running.

        Raises `ValueError` if both graphs have different control
        `AsyncQueue` set.
        """
        if self.running() or other.running():
            raise RuntimeError("Cannot add while running")
        if isinstance(other, ProxyNode):
            self._nodes.append(other)
            return self
        if other.running:
            raise RuntimeError("Cannot add with a running graph")
        if self.controller and other.controller and \
            not self.controller is other.controller:
            raise ValueError("Two added graphs have different control queues set")
        if not self._controller:
            self._controller = other._controller
        self._nodes += other._nodes
        return self

    def __gt__(self, other: ProxyNode | ProxyGraph):
        """
        Syntactic sugar for connecting nodes & graphs.

        Connects LHS `None` edge slots with RHS `None` edge slots
        in iteration order, until either side is full.

        Raises `RuntimeError` if anything is running.
        """
        # LHS and RHS are completely symmetric, so we only impl __gt__
        if self.running() or other.running():
            raise RuntimeError("Cannot connect while running")
        lhs = enumerate(chain.from_iterable(
                node.edges() for node in self.nodes()
            ))
        if isinstance(other, ProxyNode):
            rhs = enumerate(other.edges())
        else:
            rhs = enumerate(chain.from_iterable(
                node.edges() for node in other.nodes()
            ))
        try:
            while True:
                while True:
                    indexLhsSlot, lhsSlot = next(lhs)
                    if lhsSlot == None:
                        break
                while True:
                    indexRhsSlot, rhsSlot = next(rhs)
                    if rhsSlot == None:
                        break
                edge = ProxyEdge()
                nodes = iter(self.nodes())
                node = next(nodes)
                while indexLhsSlot >= len(node.edges()):
                    indexLhsSlot -= len(node.edges())
                    node = next(nodes)
                node.edges()[indexLhsSlot] = edge[0]
                if isinstance(other, ProxyNode):
                    other.edges()[indexRhsSlot] = edge[1]
                else:
                    nodes = iter(other.nodes())
                    node = next(nodes)
                    while indexRhsSlot >= len(node.edges()):
                        indexRhsSlot -= len(node.edges())
                        node = next(nodes)
                    node.edges()[indexRhsSlot] = edge[1]
        except StopIteration:
            return self + other

    async def run(self) -> Optional[Exception]:
        """
        Run the graph.

        Returns last error.

        To stop the graph, send a control signal.
        """
        if self._running or any(node.running() for node in self._nodes):
            return RuntimeError("Something is already running")
        self._running = True

        pending = {asyncio.create_task(node.run()) for node in self._nodes}
        listener = None
        error = None
        if self._controller:
            listener = asyncio.create_task(self._controller.get())
            pending.add(listener)
        while pending:
            done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
            for task in done:
                try:
                    result = task.result()
                    if result:
                        for node in self._nodes:
                            node.controller().put_nowait(result)
                        if task is listener:
                            # Runtime self._controller modification is impossible
                            listener = asyncio.create_task(self._controller.get()) # type: ignore
                            pending.add(listener)
                        else:
                            error = RuntimeError(f"Received {result} from graph nodes")
                except Exception as e:
                    error = e
                    for node in self._nodes:
                        node.controller().put_nowait("SIGKILL")
        self._running = False
        return error

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
            self._node._connections.remove(self._connection)
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

        Running a already running or improperly connected `UpstreamTCPNode`
        returns `SIGKILL`.
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

        server = asyncio.create_task((await loop.create_server(
            lambda: UpstreamTCPNode._UpstreamTCPProtocol(self), sock=sock
        )).serve_forever())
        dispatcher = asyncio.create_task(self._dispatch())
        controller = asyncio.create_task(self._controller.get())
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
            controller = asyncio.create_task(self._controller.get())

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
                    del self._connections[packet.connection.remoteAddress]
                    if self._signal == "SIGTERM" and not self._connections:
                        self._controller.put_nowait("SIGKILL")
                    continue
        except asyncio.CancelledError:
            return

    async def run(self) -> Optional[Literal['SIGKILL', 'SIGTERM']]:
        """
        Run `UpstreamUDPNode`.

        Immediately claims immutable ownership of its attributes.

        Running a already running or improperly connected `UpstreamUDPNode`
        returns `SIGKILL`.
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
        dispatcher = asyncio.create_task(self._dispatch())
        controller = asyncio.create_task(self._controller.get())
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
            controller = asyncio.create_task(self._controller.get())


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
            self._node._connections.remove(self._connection)
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

        Running a already running or improperly connected
        `DownstreamTCPNode` returns `SIGKILL`.
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

        dispatcher = asyncio.create_task(self._dispatch())
        controller = asyncio.create_task(self._controller.get())
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
            controller = asyncio.create_task(self._controller.get())


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

        Running a already running or improperly connected
        `DownstreamUDPNode` returns `SIGKILL`.
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
        dispatcher = asyncio.create_task(self._dispatch())
        controller = asyncio.create_task(self._controller.get())
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
            controller = asyncio.create_task(self._controller.get())


class ExitServerNode(ProxyNode):
    """
    Exit server node that resolves proxy request locally.

    Takes exactly 3 consumers and 3 producers. First pair is `ProxyMessage`
    request upstream, second pair is `ProxyPacket` TCP downstream,
    third pair is `ProxyPacket` UDP downstream.

    Uses system DNS to resolve by default.
    """
    ...

            
class DemultiplexTCPUDPNode(ProxyNode):
    ...


class MultiplexTCPUDPNode(ProxyNode):
    ...






