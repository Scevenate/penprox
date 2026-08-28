from __future__ import annotations
from abc import ABC, abstractmethod
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address
from asyncio import Queue, create_task
import asyncio
from culsans import Queue as HybridQueue
from typing import Optional, Literal
from logging import getLogger
from itertools import chain
from threading import Lock

logger = getLogger(__name__)

class _RunningGraphs:
    __slots__ = (
        "_lock",
        "_set"
    )
    def __init__(self):
        self._lock: Lock = Lock()
        self._set: set[ProxyGraph] = set()
    def add(self, item: ProxyGraph):
        with self._lock:
            self._set.add(item)
    def remove(self, item: ProxyGraph):
        with self._lock:
            self._set.remove(item)
    def __iter__(self):
        self._lock.acquire()
        return iter(self._set)
    def iter_ok(self):
        self._lock.release()

_penprox_running_graphs: _RunningGraphs = _RunningGraphs()

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

    Transport is `None` Only when being passed in a downstream SYN packet,
    which is populated by downstream network endpoint node. Otherwise the
    object is immutable.
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

    Transport is `None` Only when being passed in a downstream SYN packet,
    which is populated by downstream network endpoint node. Otherwise the
    object is immutable.
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
    Otherwise the object is immutable.
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
    request: ProxyRequest
    data: bytes
    flag: Optional[Literal["SYN", "FIN"]]

class ProxyBidict[X, Y]:
    """
    1-to-1 relation indexed on both side. Not thread safe.

    Most commonly used for `ProxyConnection` and `ProxyRequest` mapping.
    """
    __slots__ = (
        "_x",
        "_y"
    )
    def __init__(self):
        self._x: dict[X, Y] = {}
        self._y: dict[Y, X] = {}
    def set(self, x: X, y: Y):
        """
        Set a new relation.

        Deletes existing relations involving `x` and `y`.
        """
        if x in self._x:
            del self._y[self._x[x]]
        if y in self._y:
            del self._x[self._y[y]]
        self._x[x] = y
        self._y[y] = x
    def getx(self, x: X) -> Y:
        """
        Get relation by `X`.

        `KeyError` if not exist.
        """
        return self._x[x]
    def gety(self, y: Y) -> X:
        """
        Get relation by `Y`.

        `KeyError` if not exist.
        """
        return self._y[y]
    def discardx(self, x: X):
        """
        Idempotently delete relation by X.
        """
        y = self._x.pop(x, None)
        if y:
            del self._y[y]
    def discardy(self, y: Y):
        """
        Idempotently delete relation by Y.
        """
        x = self._y.pop(y, None)
        if x:
            del self._x[x]
    def empty(self):
        """
        `True` iff empty.
        """
        return not self._x

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
        self._controller: HybridQueue[ProxySignal] = HybridQueue()

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
    def controller(self) -> HybridQueue[ProxySignal]:
        """
        Get controller end of graph. Supports both async / sync mpsc pushing.

        Use to broadcast control signal to nodes in the graph.
        """
        return self._controller
    def __del__(self):
        self._controller.shutdown()
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
        _penprox_running_graphs.add(self)

        pending = {create_task(node.run()) for node in self._nodes}
        controller = create_task(self._controller.async_get())
        pending.add(controller)
        error = None
        
        while pending:
            done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
            for task in done:
                try:
                    result = task.result()
                    if result:
                        for node in self._nodes:
                            node.controller().put_nowait(result)
                        if task is controller:
                            controller = create_task(self._controller.async_get())
                            pending.add(controller)
                        else:
                            error = RuntimeError(f"Received {result} from graph nodes")
                except Exception as e:
                    error = e
                    for node in self._nodes:
                        node.controller().put_nowait("SIGKILL")
        self._running = False
        _penprox_running_graphs.remove(self)
        return error
