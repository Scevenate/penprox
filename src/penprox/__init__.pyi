from collections.abc import Awaitable, Callable
from enum import Enum, auto
from ipaddress import IPv4Address, IPv6Address
from os import PathLike
from typing import Literal, TextIO

PACKET_DATA_SIZE: int

class LogLevel(Enum):
    """
    Logging verbosity level.
    """
    TRACE = auto()
    DEBUG = auto()
    INFO = auto()
    WARN = auto()
    ERROR = auto()

def set_logger(
        dest: TextIO | str | PathLike[str],
        level: LogLevel = LogLevel.INFO
    ) -> None:
    """
    Install the global logger.

    `dest` may be `sys.stdout`, `sys.stderr`, or a file path.
    Can only be set once per process.
    """

class Connection:
    """
    A conceptual, immutable connection.
    """
    host: str | IPv4Address | IPv6Address
    transport: Literal["TCP", "UDP"]
    port: int
    def __init__(
        self,
        host: str | IPv4Address | IPv6Address,
        transport: Literal["TCP", "UDP"],
        port: int
    ):
        """
        Initialize a new connection.

        Once initialized, the connection is immutable other than DNS resolution.
        """
    def resolve(self, ip: IPv4Address | IPv6Address):
        """
        Idempotently resolve the connection host into an IP.

        Fails silently if the connection domain is already resolved.
        """

type PacketType = Literal["Detached", "Upward", "Downward"]

type PacketPayload = Literal["SYN", "FIN"] | bytes

class Packet:
    """
    Packet, bound to a connection, carrying a flag or data.

    Paylad is at most `PACKET_DATA_SIZE` bytes.

    Type is virtually a trivial marker, except that:
    1. An attached packet has an immutable connection.
    2. An attached data packet needs a connection-direction buffer slot.
    """
    type: PacketType
    connection: Connection
    payload: PacketPayload
    def is_attached_data(self) -> bool:
        """
        Shortcut for peeking if packet carries a buffer count
        """
    async def set_type(self, type: PacketType):
        """
        Async version of the type setter, additionally handles the case when
        attaching a data packet.

        When one thread is awaiting this action, accessing the packet from another
        thread will raise.
        """
    async def set_payload(self, payload: PacketPayload):
        """
        Async version of the payload setter, additionally handles the case when
        putting data into an attached flag packet.

        When one thread is awaiting this action, accessing the packet from another
        thread will raise.
        """


type Signal = Literal["SIGTERM", "SIGUSR1", "SIGUSR2"]

class NodeUpstreamEnd:
    """
    A pluggable upstream slot on the node for connecting edges.
    """
    def connected(self) -> bool:
        """
        `True` iff the end is connected.
        """
    def put_nowait(self, packet: Packet) -> None:
        """
        Put a packet into the edge the node end is connected to,
        leaving the argument a detached copy.

        Raises exception if the end is disconnected, full, closed, 
        or putting non-upward data packet while connection is full (back pressured).
        """
    async def put(self, packet: Packet) -> None:
        """
        Put a packet into the edge the node end is connected to,
        leaving the argument a detached copy.

        Raises exception if the end is disconnected closed.
        """
    def __sub__(self, other: NodeDownstreamEnd) -> None:
        """
        Connect the two node ends. (overwrites)
        """

class NodeDownstreamEnd:
    """
    A pluggable downstream slot on the node for connecting edges.
    """
    def connected(self) -> bool:
        """
        `True` iff the end is connected.
        """
    def put_nowait(self, packet: Packet) -> None:
        """
        Put a packet into the edge the node end is connected to,
        leaving the argument a detached copy.

        Raises exception if the end is disconnected, full, closed, 
        or putting non-upward data packet while connection is full (back pressured).
        """
    async def put(self, packet: Packet) -> None:
        """
        Put a packet into the edge the node end is connected to,
        leaving the argument a detached copy.

        Raises exception if the end is disconnected closed.
        """
    def __sub__(self, other: NodeUpstreamEnd) -> None:
        """
        Connect the two node ends. (overwrites)
        """

class NodeUpstreamInterface:
    """
    An upstream interface of a node, conceptually an immutable list of `NodeUpstreamEnd`s.
    """
    def __getitem__(self, index: int) -> NodeUpstreamEnd:
        ...
    def __len__(self) -> int:
        ...
    def __sub__(self, other: NodeDownstreamInterface) -> None:
        """
        Connects disconnected upstream slots to disconnected downstream slots in order,
        until either side is full.

        Does not overwrite existing connections.
        """

class NodeDownstreamInterface:
    """
    An downstream interface of a node, conceptually an immutable list of `NodeDownstreamEnd`s.
    """
    def __getitem__(self, index: int) -> NodeDownstreamEnd:
        ...
    def __len__(self) -> int:
        ...
    def __sub__(self, other: NodeUpstreamInterface) -> None:
        """
        Connects disconnected downstream slots to disconnected upstream slots in order,
        until either side is full.

        Does not overwrite existing connections.
        """

class Node:
    """
    An async runtime service managed by the graph.

    All properties of this object gets a copied list.
    """
    upstreams: NodeUpstreamInterface
    downstreams: NodeDownstreamInterface
    def signal(self, signal: Signal):
        """
        Signal the node.
        """
    def spawn(self) -> Signal | None:
        """
        Hand over thread, spawn runtime and run blocked.
        """
    def __rshift__(self, other: Node) -> Node:
        """
        Connect self downstreams to other upstreams, then merge.
        """
    def __lshift__(self, other: Node) -> Node:
        """
        Connect self upstreams to other downstreams, then merge.
        """
    def __add__(self, other: Node) -> Node:
        """
        Construct a graph of the two nodes,
        or put a node into a graph,
        or merge the two graphs.
        """
    def __sub__(self, other: Node):
        """
        Connect self downstream interface to other upstream interface.
        """

def GraphNode() -> Node:
    """
    Graph, a special node. Runtime node service manager.

    Nodes in a graph is ordered in a list. The upstream / downstream interface
    of this node is a flattened list of ends of its nodes (thus mutable).
    """

def TCPNode(address: tuple[IPv4Address | IPv6Address, int] | None = None) -> Node:
    """
    Node for TCP, may listen a port. Doesn't support DNS.
    
    When provided `(ip, port)`, the node is in upstream mode:
    - The node listens to the port.
    - It has one downstream, no upstream.
    - It does not support downstream SYNs.
     
    When provided `None`, the node is in downstream mode:
    - It has one upstream, no downstream.
    """

def UDPNode(address: 
        tuple[IPv4Address | IPv6Address, int] | Literal["V4", "V6", "V4V6", "V6V4"] = "V4V6"
    ) -> Node:
    """
    Node for UDP, may bind a port. Doesn't support DNS.
    
    When provided `(ip, port)`, the node is in upstream mode:
    - The node listens to the port.
    - It has one downstream, no upstream.
    - It does not support downstream SYNs.
    
    When provided `V4V6 | V6V4 | V4 | V6`, the node is in downstream mode:
    - It binds ephemeral v4 | v6 | v4&v6 port(s). (`V4V6` and `V6V4` are treated the same here).
    - It has one upstream, no downstream.
    """

type PythonNodeCallbackArg = tuple[Signal, Literal[0]] | tuple[Packet, int]

type PythonNodeCallbackReturn = bool | Signal

type PythonNodeCallback = Callable[[PythonNodeCallbackArg], PythonNodeCallbackReturn | Awaitable[PythonNodeCallbackReturn]]

def PythonNode(
        callback: PythonNodeCallback,
        upstreams: int,
        downstreams: int
    ) -> Node:
    """
    A python node. This node can be used to simply attach a python service to
    a graph, or listen to edge incoming packets. Both sync and asyncio functions
    are supported.

    The callback is invoked when a signal or packet arrives.
    - If it returns a signal, the node quits and propagates the signal.
    - If it returns `True`, the node returns silently.
    - If it returns `False`, the node continues listening. (This is analogous to return 0.)

    The node must be properly connected as usual, and `SIGTERM` 
    quits directly than invoking the callback.
    """

def DNSNode(
        resolver: str | IPv4Address | IPv6Address = IPv4Address("1.1.1.1"),  # noqa: B008
        middleware: bool = True,
        size: int = 5000,
        ttl: float = 300,
        *args,
        mode: Literal["V4", "V6", "V4V6", "V6V4"] = "V4",
        port: int = 53
    ) -> Node:
    """
    Node for DNS. Intercepts & blocks new connections with unresolved domain,
    releasing after resolution.
    
    When `middleware` is true, the node runs in middleware mode. The node
    will have one upstream and one downstream, acts purely as a middleware
    that resolves DNS locally.
    
    When `middleware` is false, the node runs in explicit mode. The node
    will have one upstream and two downstreams, in which the additional
    downstream is for DNS traffic.
    
    When operating with `V4` / `V6` address mode, DNSNode only tries to resolve
    into the given address family. `V4V6` / `V6V4` are treated the same here.
    
    User may specify the size and TTL of the node-local DNS cache.
    """

def TLSNode(
        cert_and_key: tuple[str | PathLike[str], str | PathLike[str]] | None = None
    ) -> Node:
    """
    TLS node, could act as client middleware or server middleware.

    When `cert_and_key` is provided, the node unwraps server connections.
    Certificate may contain the whole chain; PKCS#1, PKCS#8 and SEC1 keys
    are supported.

    When not provided, the node wraps client connections. `DNSNode` should be
    put after this node as it resolves the domain.
    """

def SOCKS5Node(server: tuple[str | IPv4Address | IPv6Address, int] | None = None) -> Node:
    """
    SOCKS5 node. Only supports `CONNECT`; Does not support authentication.

    When provided `(host, port)`, the node is in client mode:
    - Reads the proxied session from one upstream.
    - Initiates the SOCKS5 connection with the remote server through one downstream.

    When provided `None`, the node is in server mode:
    - Accepts one upstream SOCKS5 client request.
    - Sends the proxied session to one downstream.

    The host of an inbound SOCKS5 request is faithfully translated into the
    session host without bothering DNS.
    """
