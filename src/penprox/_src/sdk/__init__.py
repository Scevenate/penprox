from __future__ import annotations

import asyncio
import socket  # noqa: F401
from abc import ABC, abstractmethod
from asyncio import Queue, create_task
from collections import OrderedDict
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address
from logging import getLogger
from threading import Lock
from time import time
from typing import Literal, cast

from janus import Queue as HybridQueue

logger = getLogger("penprox")

class RunningGraphs:
    __slots__ = (
        "_lock",
        "_set"
    )
    def __init__(self):
        self._lock: Lock = Lock()
        self._set: set[Graph] = set()
    def add(self, item: Graph):
        with self._lock:
            self._set.add(item)
    def remove(self, item: Graph):
        with self._lock:
            self._set.remove(item)
    def __iter__(self):
        self._lock.acquire()
        return iter(self._set)
    def iter_ok(self):
        self._lock.release()

running_graphs: RunningGraphs = RunningGraphs()

def id_hash(cls):
    def hash(self):
        return id(self)
    cls.__hash__ = hash
    return cls

@id_hash
@dataclass(eq=False, slots=True, frozen=True)
class TCPConnection:
    """
    A conceptual TCP connection.
    """
    host: IPv4Address | IPv6Address
    port: int

@id_hash
@dataclass(eq=False, slots=True, frozen=True)
class TCPPacket:
    """
    A conceptual TCP packet in `TCPConnection`.
    """
    bound: TCPConnection
    payload: Literal["SYN", "FIN"] | bytes

@id_hash
@dataclass(eq=False, slots=True, frozen=True)
class UDPConnection:
    """
    A conceptual UDP connection.
    """
    host: IPv4Address | IPv6Address
    port: int

@id_hash
@dataclass(eq=False, slots=True, frozen=True)
class UDPPacket:
    """
    A conceptual UDP packet in `UDPConnection`.
    """
    bound: UDPConnection
    payload: Literal["SYN", "FIN"] | bytes

@id_hash
@dataclass(eq=False, slots=True)
class TCPSession:
    """
    A semantic TCP proxy session.

    Notice that host may be `str` (domain name), which is allowed to be
    asynchronously resolved & mutated into IP address.
    """
    host: IPv4Address | IPv6Address | str
    port: int

@id_hash
@dataclass(eq=False, slots=True, frozen=True)
class TCPMessage:
    """
    A conceptual TCP message in `TCPSession`.
    """
    bound: TCPSession
    payload: Literal["SYN", "FIN"] | bytes

@id_hash
@dataclass(eq=False, slots=True)
class UDPSession:
    """
    A semantic UDP proxy session.

    Notice that host may be `str` (domain name), which is allowed to be
    asynchronously resolved & mutated into IP address.
    """
    host: IPv4Address | IPv6Address | str
    port: int

@id_hash
@dataclass(eq=False, slots=True, frozen=True)
class UDPMessage:
    """
    A conceptual TCP message in `UDPSession`.
    """
    bound: UDPSession
    payload: Literal["SYN", "FIN"] | bytes

class LRUTTLDict[Key, Value]:
    """
    A dict that orders items by most recent `get` and evits on `set`.

    Not perfectly LRUTTL. Only evaluates TTL on retrival (Unretrieved old records
    will eventually be evited by LRU).
    """
    __slots__ = (
        "_dict",
        "_size",
        "_ttl",
    )
    __sentinel = object()
    # Internal dict type: (value, setTime)
    def __init__(self, size: int, ttl: float):
        assert size > 0
        assert ttl > 0
        self._size: int = size
        self._ttl: float = ttl
        self._dict: OrderedDict[Key, tuple[Value, float]] = OrderedDict()
    def get[Default](self, key: Key, default: Default = None) -> Value | Default:
        """
        Get item. Updates LRU.
        """
        value = self._dict.get(key, self.__sentinel)
        if value is not self.__sentinel:
            if value[1] > time() - self._ttl: # pyright: ignore[reportIndexIssue]
                return value[0] # pyright: ignore[reportIndexIssue]
            self._dict.pop(key)
        return default
    def set(self, key: Key, value: Value) -> None:
        """
        Set item. Updates old one or inserts a new one.
        
        Updates LRU. Might evit LRU on insert.
        """
        self._dict[key] = (value, time())
        self._dict.move_to_end(key)
        if len(self._dict) > self._size:
            self._dict.popitem(last=False)

class Bidict[X, Y]:
    """
    1-to-1 storage indexed on both sides.
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
    def xgety[Default](self, x: X, default:Default=None) -> Y | Default:
        """
        Get relation by `X`.
        """
        return self._x.get(x, default)
    def ygetx[Default](self, y: Y, default:Default=None) -> X | Default:
        """
        Get relation by `Y`.
        """
        return self._y.get(y, default)
    def xdiscard(self, x: X):
        """
        Idempotently remove by X.
        """
        y = self._x.pop(x, None)
        if y:
            del self._y[y]
    def ydiscard(self, y: Y):
        """
        Idempotently remove by Y.
        """
        x = self._y.pop(y, None)
        if x:
            del self._x[x]
    def empty(self):
        """
        `True` iff empty.
        """
        return not self._x

class BidictAD[X, Y, D]:
    """
    1-to-1 storage indexed on both sides, with associated data.
    """
    __slots__ = (
        "_d",
        "_x",
        "_y"
    )
    __sentinel = object()
    def __init__(self):
        self._x: dict[X, Y] = {}
        self._y: dict[Y, X] = {}
        self._d: dict[X, D] = {}
    def set(self, x: X, y: Y, d: D):
        """
        Set a new relation.

        Deletes existing relations involving `x` and `y`.
        """
        if x in self._x:
            del self._y[self._x[x]]
        elif y in self._y:
            del self._x[self._y[y]]
            del self._d[self._y[y]]
        self._x[x] = y
        self._y[y] = x
        self._d[x] = d
    def xgety[Default](self, x: X, default:Default=None) -> Y | Default:
        """
        Get relation by `X`.
        """
        return self._x.get(x, default)
    def ygetx[Default](self, y: Y, default:Default=None) -> X | Default:
        """
        Get relation by `Y`.
        """
        return self._y.get(y, default)
    def xgetd[Default](self, x: X, default:Default=None) -> D | Default:
        """
        Get associated data by `X`.
        """
        return self._d.get(x, default)
    def ygetd[Default](self, y: Y, default:Default=None) -> D | Default:
        """
        Get associated data by `Y`.
        """
        x = self._y.get(y, self.__sentinel)
        if x is not self.__sentinel:
            return self._d.get(x, default) # pyright: ignore[reportArgumentType, reportCallIssue]
        else:
            return default
    def xdiscard(self, x: X):
        """
        Idempotently remove by X.
        """
        self._d.pop(x, None)
        y = self._x.pop(x, None)
        if y:
            del self._y[y]
    def ydiscard(self, y: Y):
        """
        Idempotently remove by Y.
        """
        x = self._y.pop(y, None)
        if x:
            del self._x[x]
            del self._d[x]
    def empty(self):
        """
        `True` iff empty.
        """
        return not self._x

# Unidirectional control signals.
Signal = Literal[
    # Asks a node to immediately clear up its resource and return
    # Effort to maintain a consistent state is not required
    "SIGKILL",
    # For nodes on SIGTERM boundary, stop accepting new connections.
    # For all nodes, return after all existing connections are closed.
    "SIGTERM",
]

EdgeEnd = tuple[Queue, Queue]

def Edge() -> tuple[EdgeEnd, EdgeEnd]:
    """
    A bidirectional async pipe for `Packet` or `Message`.

    The first queue in an end is the consumer; The second is producer.
    """
    q1, q2 = Queue(), Queue()
    return (
        (q1, q2),
        (q2, q1)
    )

class BaseNode(ABC):
    """
    ABC for all nodes.

    A node is a async runtime service managed by `Graph`.

    This class includes:
    - Declaration of an abstract node interface
    - Some utils for implementor use
    - Some syntactic sugar on node interface 
    """
    __slots__ = ()
    __sentinel = object()
    @abstractmethod
    def edges(self) -> list[EdgeEnd | None]:
        """
        Get the node's edges.

        Unless otherwise documented, do not mutate while running.
        """
    @abstractmethod
    def controller(self) -> Queue[Signal]:
        """
        Get the node's controller end. (mpsc)
        """
    @abstractmethod
    def running(self) -> bool:
        """
        Returns `True` iff the node is running.

        A running node is considered immutable unless explicitly documented.
        """
    @abstractmethod
    def boundary(self) -> bool:
        """
        Returns `True` iff the node is a SIGTERM boundary node.
        """
    @abstractmethod
    async def run(self) -> Signal | None:
        """
        Entry point of the node.

        This is usually managed by a `Graph`, but advanced users may
        orchestrate their own solution.

        The node may return a signal to be broadcasted. The node may also
        just propagate an exception (which in a Graph, will kill the graph).

        Should `RuntimeError` if the node is already running, raises
        `ValueError` if the node is misconfigured.
        """
        ...
    @abstractmethod
    def upstreams(self) -> tuple[int, ...]:
        """
        Get the node's upstream edge indexes.

        This information is used for helper methods that connects nodes.
        """
    @abstractmethod
    def downstreams(self) -> tuple[int, ...]:
        """
        Get the node's downstream edge indexes.

        This information is used for helper methods that connects nodes.
        """
    def _open(self, edge: int, obj: TCPConnection | UDPConnection | TCPSession | UDPSession):
        """
        Helper method for pushing a SYN for a newly constructed connection or session.
        """
        if isinstance(obj, TCPConnection):
            self.edges()[edge][1].put_nowait(TCPPacket(obj, "SYN")) # pyright: ignore[reportOptionalSubscript]
        elif isinstance(obj, TCPSession):
            self.edges()[edge][1].put_nowait(TCPMessage(obj, "SYN")) # pyright: ignore[reportOptionalSubscript]
        elif isinstance(obj, UDPConnection):
            self.edges()[edge][1].put_nowait(UDPPacket(obj, "SYN")) # pyright: ignore[reportOptionalSubscript]
        else:
            self.edges()[edge][1].put_nowait(UDPMessage(obj, "SYN")) # pyright: ignore[reportOptionalSubscript]
    def _send(self, edge: int, obj: TCPConnection | UDPConnection | TCPSession | UDPSession, data: bytes):
        """
        Helper method for sending data bound to a connection or session.
        """
        if isinstance(obj, TCPConnection):
            self.edges()[edge][1].put_nowait(TCPPacket(obj, data)) # pyright: ignore[reportOptionalSubscript]
        elif isinstance(obj, TCPSession):
            self.edges()[edge][1].put_nowait(TCPMessage(obj, data)) # pyright: ignore[reportOptionalSubscript]
        elif isinstance(obj, UDPConnection):
            self.edges()[edge][1].put_nowait(UDPPacket(obj, data)) # pyright: ignore[reportOptionalSubscript]
        else:
            self.edges()[edge][1].put_nowait(UDPMessage(obj, data)) # pyright: ignore[reportOptionalSubscript]
    def _close(self, edge: int, obj: TCPConnection | UDPConnection | TCPSession | UDPSession):
        """
        Helper method for pushing a FIN for a closing connection or session.
        """
        if isinstance(obj, TCPConnection):
            self.edges()[edge][1].put_nowait(TCPPacket(obj, "FIN")) # pyright: ignore[reportOptionalSubscript]
        elif isinstance(obj, TCPSession):
            self.edges()[edge][1].put_nowait(TCPMessage(obj, "FIN")) # pyright: ignore[reportOptionalSubscript]
        elif isinstance(obj, UDPConnection):
            self.edges()[edge][1].put_nowait(UDPPacket(obj, "FIN")) # pyright: ignore[reportOptionalSubscript]
        else:
            self.edges()[edge][1].put_nowait(UDPMessage(obj, "FIN")) # pyright: ignore[reportOptionalSubscript]
    def _reject(self, edge: int, obj: TCPPacket | UDPPacket | TCPMessage | UDPMessage):
        """
        Reject packet or message by pushing a FIN back.
        """
        if isinstance(obj, TCPPacket):
            self.edges()[edge][1].put_nowait(TCPPacket(obj.bound, "FIN")) # pyright: ignore[reportOptionalSubscript]
        elif isinstance(obj, TCPMessage):
            self.edges()[edge][1].put_nowait(TCPMessage(obj.bound, "FIN")) # pyright: ignore[reportOptionalSubscript]
        elif isinstance(obj, UDPPacket):
            self.edges()[edge][1].put_nowait(UDPPacket(obj.bound, "FIN")) # pyright: ignore[reportOptionalSubscript]
        else:
            self.edges()[edge][1].put_nowait(UDPMessage(obj.bound, "FIN")) # pyright: ignore[reportOptionalSubscript]
    def _forward(self, edge: int, obj: TCPPacket | UDPPacket | TCPMessage | UDPMessage):
        """
        Forward a packet.
        """
        self.edges()[edge][1].put_nowait(obj) # pyright: ignore[reportOptionalSubscript]
    def __add__(self, other: BaseNode | Graph) -> Graph:
        """
        Syntactic sugar for putting nodes into graphs.

        Raises `RuntimeError` if anything is running.
        """
        if self.running() or other.running():
            raise RuntimeError("Cannot add while running")
        if isinstance(other, BaseNode):
            return Graph(self, other)
        other.nodes().append(self)
        return other
    def __rshift__(self, other: BaseNode | Graph) -> Graph:
        """
        Syntactic sugar for connecting nodes & graphs.

        Connects LHS `None` downstreams to RHS `None` upstreams in iteration order,
        until either side is full.

        Raises `RuntimeError` if anything is running.
        """
        if self.running() or other.running():
            raise RuntimeError("Cannot add while running")
        if isinstance(other, BaseNode):
            upstreams = (
                (other, upstream)
                for upstream in other.upstreams()
            )
        else:
            upstreams = (
                (node, upstream)
                for node in other.nodes()
                for upstream in node.upstreams()
            )
        for downstream in self.downstreams():
            if self.edges()[downstream]:
                continue
            while True:
                rhs = next(upstreams, self.__sentinel)
                if rhs is self.__sentinel:
                    return self + other
                rhsNode, upstream = cast(tuple[BaseNode, int], rhs)
                if rhsNode.edges()[upstream]:
                    continue
                break
            edge = Edge()
            self.edges()[downstream] = edge[0]
            rhsNode.edges()[upstream] = edge[1]
        return self + other
    def __lshift__(self, other):
        """
        Symmetric operation
        """
        return other >> self

class Graph:
    """
    Struct. A referential list that groups node together.
    
    Also async runtime manager, and used for connecting nodes.
    """
    __slots__ = (
        "__controller",
        "__nodes",
        "__running"
    )
    __sentinel = object()
    def __init__(self, *nodes: BaseNode):
        self.__nodes: list[BaseNode] = list(nodes)
        self.__running: bool = False
        self.__controller: HybridQueue[Signal] = HybridQueue()

    def nodes(self) -> list[BaseNode]:
        """
        Get nodes in the graph.

        Unless otherwise documented, do not mutate while running.
        """
        return self.__nodes
    def running(self) -> bool:
        """
        Returns `True` iff the graph is running.

        A running graph is considered immutable unless explicitly documented.
        """
        return self.__running
    def controller(self) -> HybridQueue[Signal]:
        """
        Get controller end of graph. Supports both async / sync mpsc pushing.

        Use to broadcast control signal to ALL nodes in the graph.
        """
        return self.__controller
    def __del__(self):
        """
        Controller queue lifetime manager.
        """
        self.__controller.shutdown()
    def __add__(self, other: BaseNode | Graph) -> Graph:
        
        """
        Syntactic sugar for adding nodes or merging graphs.

        Raises `RuntimeError` if anything is running.

        Raises `ValueError` if any of the two graphs has queued control signals.
        """
        if self.running() or other.running():
            raise RuntimeError("Cannot add while running")
        if isinstance(other, BaseNode):
            self.__nodes.append(other)
            return self
        if not self.controller().sync_q.empty() or not other.controller().sync_q.empty():
            raise ValueError("Cannot add graphs with queued control signals")
        self.__nodes += other.__nodes
        return self

    def __rshift__(self, other: BaseNode | Graph):
        """
        Syntactic sugar for connecting nodes & graphs.

        Connects LHS `None` downstreams to RHS `None` upstreams in iteration order,
        until either side is full.

        Raises `RuntimeError` if anything is running.
        """
        if self.running() or other.running():
            raise RuntimeError("Cannot add while running")
        downstreams = (
            (node, downstream)
            for node in self.nodes()
            for downstream in node.downstreams()
        )
        if isinstance(other, BaseNode):
            upstreams = (
                (other, upstream)
                for upstream in other.upstreams()
            )
        else:
            upstreams = (
                (node, upstream)
                for node in other.nodes()
                for upstream in node.upstreams()
            )
        for lhsNode, downstream in downstreams:
            if lhsNode.edges()[downstream]:
                continue
            while True:
                rhs = next(upstreams, self.__sentinel)
                if rhs is self.__sentinel:
                    return self + other
                rhsNode, upstream = cast(tuple[BaseNode, int], rhs)
                if rhsNode.edges()[upstream]:
                    continue
                break
            edge = Edge()
            lhsNode.edges()[downstream] = edge[0]
            rhsNode.edges()[upstream] = edge[1]
        return self + other
    def __lshift__(self, other):
        """
        Symmetric operation
        """
        return other >> self

    async def run(self):
        """
        Run the graph.

        Raises `RuntimeError` instead if anything is already running.
        """
        if self.__running or any(node.running() for node in self.__nodes):
            raise RuntimeError("Something is already running")
        self.__running = True
        running_graphs.add(self)
        while not self.__controller.sync_q.empty():
            self.__controller.sync_q.get_nowait()

        taskTrace: dict[asyncio.Task, BaseNode | Literal["controller"]] = {}
        for node in self.__nodes:
            taskTrace[create_task(node.run())] = node
        taskTrace[create_task(self.__controller.async_q.get())] = "controller"
        while True:
            done, _ = await asyncio.wait(taskTrace.keys(), return_when=asyncio.FIRST_COMPLETED)
            for task in done:
                try:
                    result = cast(Signal | None, task.result())
                except Exception:
                    node = taskTrace.pop(task)
                    logger.exception(f"Graph: Received exception from {node.__class__.__name__}, broadcasting SIGKILL")
                    for node in taskTrace.values():
                        if node != "controller":
                            node.controller().put_nowait("SIGKILL")
                    continue
                if result is None: # Not controller
                    node = taskTrace.pop(task)
                    logger.info(f"Graph: Node {node.__class__.__name__} exited silently")
                    continue
                if taskTrace[task] == "controller":
                    del taskTrace[task]
                    logger.info(f"Graph: Received control signal {result}, broadcasting")
                    for node in taskTrace.values():
                        cast(BaseNode, node).controller().put_nowait(result)
                    taskTrace[create_task(self.__controller.async_q.get())] = "controller"
                    continue
                else:
                    node = taskTrace.pop(task)
                    logger.info(f"Graph: Node {node.__class__.__name__} exited with signal {result}, broadcasting")
                    for node in taskTrace.values():
                        if node != "controller":
                            node.controller().put_nowait(result)
                    continue
            if len(taskTrace) == 1 and next(iter(taskTrace.values())) == "controller":
                break
        self.__running = False
        running_graphs.remove(self)
        logger.info("Graph: All finished, quitting")

class Node(BaseNode, ABC):
    """
    A template suitable for most standard nodes. Implements the `BaseNode` node interface.

    Implentor must implement:
    - Class config variables:
        - `_edges`: Integer, amount of edges
        - `_upstreams`: Tuple of upstream edge indexes
        - `_downstreams`: Tuple of downstream edge indexes
    - Recv callback: `async def _onGet(self, edge: int, obj: TCPPacket | UDPPacket | TCPMessage | UDPMessage)`

    Implementor may implement:
    - `run` callback: `async def _run(self)`
    - `__init__`: Implementor must still call `super().__init__(self, boundary)`.

    The `_onGet` or `_run` callback may return a signal or raise an error. It will propagate transparently.
    """
    __slots__ = (
        "__boundary",
        "__controller",
        "__edges",
        "__running"
    )
    _edges: int
    _upstreams: tuple[int, ...]
    _downstreams: tuple[int, ...]
    def __init__(self, /, boundary: bool = False):
        self.__boundary: bool = boundary
        self.__controller: Queue[Signal] = Queue()
        self.__edges: list[EdgeEnd | None] = [None] * self.__class__._edges
        self.__running: bool = False
    def boundary(self) -> bool:
        return self.__boundary
    def controller(self) -> Queue[Signal]:
        return self.__controller
    def edges(self) -> list[EdgeEnd | None]:
        return self.__edges
    def running(self) -> bool:
        return self.__running
    def upstreams(self) -> tuple[int, ...]:
        return self.__class__._upstreams
    def downstreams(self) -> tuple[int, ...]:
        return self.__class__._downstreams
    async def run(self) -> Signal | None:
        if self.__running:
            raise RuntimeError("Node is already running")
        if len(self.__edges) != self.__class__._edges or not all(self.__edges):
            raise ValueError("Node is improperly connected")
        signal = await self._run()
        if signal:
            return signal
        while not self.__controller.empty():
            self.__controller.get_nowait()
        logger.info(f"{self.__class__.__name__} is running...")
        self.__running = True

        pool: set[TCPConnection | UDPConnection | TCPSession | UDPSession] = set()
        signal: Signal | None = None

        controller = create_task(self.__controller.get())
        edges = [create_task(edge[0].get()) for edge in self.__edges] # pyright: ignore[reportOptionalSubscript]
        while True:
            done, _ = await asyncio.wait(
                edges + [controller],
                return_when=asyncio.FIRST_COMPLETED
            )
            for task in done:
                if task is controller:
                    controller = create_task(self.__controller.get())
                    _signal = cast(Signal, task.result())
                    logger.info(f"{self.__class__.__name__}: Received {_signal} signal")
                    if _signal == "SIGKILL":
                        logger.info(f"{self.__class__.__name__}: Killed")
                        self.__running = False
                        return
                    if _signal == "SIGTERM":
                        if not pool:
                            logger.info(f"{self.__class__.__name__}: All connection served, quitting (SIGTERM)")
                            self.__running = False
                            return
                        signal = "SIGTERM"
                    continue
                edge = edges.index(task)
                edges[edge] = create_task(self.__edges[edge][0].get()) # pyright: ignore[reportOptionalSubscript]
                obj = cast(TCPPacket | UDPPacket | TCPMessage | UDPMessage, task.result())
                if obj.payload == "SYN":
                    if signal == "SIGTERM":
                        self._reject(edge, obj)
                        continue
                    pool.add(obj.bound)
                try:
                    _signal = await self._onGet(edge, obj)
                    if _signal:
                        self.__running = False
                        return _signal
                except Exception as e:
                    self.__running = False
                    raise e  # noqa: TRY201
                if obj.payload == "FIN":
                    pool.discard(obj.bound)
                    if signal == "SIGTERM" and not pool:
                        logger.info(f"{self.__class__.__name__}: All connection served, quitting (SIGTERM)")
                        self.__running = False
                        return
    async def _run(self) -> Signal | None:
        return
    @abstractmethod
    async def _onGet(
        self,
        edge: int,
        obj: TCPPacket | UDPPacket | TCPMessage | UDPMessage
    ) -> Signal | None:
        ...
