from enum import Enum, auto
from ipaddress import IPv4Address, IPv6Address
from os import PathLike
from typing import Literal, TextIO

"""
The amount of bytes a packet payload may carry.
"""
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
        level: LogLevel = LogLevel.WARN
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
    tranport: Literal["TCP", "UDP"]
    port: int
    def __init__(
        self,
        host: str | IPv4Address | IPv6Address,
        transport: Literal["TCP, UDP"],
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

class Packet:
    """
    A conceptual packet.

    The max amount of bytes a packet may contain is bounded by `PACKET_DATA_SIZE`.
    """
    connection: Connection
    payload: Literal["SYN", "FIN"] | bytes

type Signal = Literal["SIGTERM", "SIGUSR1", "SIGUSR2"]

class NodeEnd:
    """
    A pluggable slot on the node for connecting edges.
    """
    def connected(self) -> bool:
        """
        `True` iff the end is connected.
        """
    def put_nowait(self, packet: Packet) -> None:
        """
        Put a packet into the edge the node end is connected to.

        Raises exception if the end is empty, full, closed, 
        or if connection is full (back pressured).
        """
    async def put(self, packet: Packet) -> None:
        """
        Put a packet into the edge the node end is connected to.

        Raises exception if the end is empty or closed.
        """
    def __sub__(self, other: NodeEnd) -> None:
        """
        Connect the two node ends. (overwrites)
        """

class NodeInterface:
    """
    An upstream or downstream interface of a node.
    
    Conceptually an immutable list of `NodeEnd`s.
    """
    def __getitem__(self, index: int) -> NodeEnd:
        ...
    def __len__(self) -> int:
            ...
    def __sub__(self, other: NodeInterface) -> None:
        """
        Connects self disconnected slots to other disconnected slots in order,
        until either side is full.

        Does not overwrite existing connections.
        """

class Node:
    """
    An async runtime service managed by the graph.

    All properties of this object gets a copied list.
    """
    upstreams: list[NodeEnd]
    downstreams: list[NodeEnd]
    def signal(self, signal: Signal):
        """
        Signal the node.
        """
    def spawn(self):
        """
        Hand over thread, spawn runtime and run blocked.
        """
    def __rshift__(self, other: Node) -> Node:
        """
        Connect self downstreams to other upstreams,
        then merges.
        """
    def __lshift__(self, other: Node) -> Node:
        """
        The symmetric operation of `__rshift__`
        """
    def __add__(self, other: Node) -> Node:
        """
        Constructs a graph of the two nodes,
        or put a node into a graph,
        or merge the two graphs.
        """
    def __sub__(self, other: Node):
        """
        Connects self downstream interface to other upstream interface.
        """

def GraphNode() -> Node:
    """
    Graph, a special node. Runtime node service manager.

    The upstream / downstream interface of this node is a list of the aggregated ends
    of its nodes.
    """
