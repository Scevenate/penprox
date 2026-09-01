"""
penprox SDK single source of truth. Also exported as penprox library API.
"""

from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from asyncio import Queue, create_task
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address
from itertools import chain
from logging import getLogger
from threading import Lock
from typing import Literal

import aiodns
from culsans import Queue as HybridQueue

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

_dnsResolver = aiodns.DNSResolver()

async def queryDNS(domain: str) -> IPv4Address | IPv6Address | None:
    result = await _dnsResolver.query_dns(domain, "A")
    if result.answer: 
        return IPv4Address(result.answer[0].data.addr) # type: ignore
    result = await _dnsResolver.query_dns(domain, "AAAA")
    if result.answer:
        return IPv6Address(result.answer[0].data.addr) # type: ignore

@dataclass(eq=False, slots=True, frozen=True)
class ProxyTCPConnection:
    """
    A conceptual TCP connection.
    """
    host: IPv4Address | IPv6Address
    port: int

@dataclass(eq=False, slots=True, frozen=True)
class ProxyTCPPacket:
    """
    A conceptual TCP packet in `ProxyTCPConnection`.
    """
    bound: ProxyTCPConnection
    data: bytes
    flag: Literal["SYN", "FIN"] | None

@dataclass(eq=False, slots=True, frozen=True)
class ProxyUDPConnection:
    """
    A conceptual UDP connection.
    """
    host: IPv4Address | IPv6Address
    port: int

@dataclass(eq=False, slots=True, frozen=True)
class ProxyUDPPacket:
    """
    A conceptual UDP packet in `ProxyUDPConnection`.
    """
    bound: ProxyUDPConnection
    data: bytes
    flag: Literal["SYN", "FIN"] | None

@dataclass(eq=False, slots=True)
class ProxyTCPSession:
    """
    A semantic TCP proxy session.

    Notice that host may be `str` (domain name), which is allowed to be
    asynchronously resolved & mutated into IP address.
    """
    host: IPv4Address | IPv6Address | str
    port: int

@dataclass(eq=False, slots=True, frozen=True)
class ProxyTCPMessage:
    """
    A conceptual TCP message in `ProxyTCPSession`.
    """
    bound: ProxyTCPSession
    data: bytes
    flag: Literal["SYN", "FIN"] | None

@dataclass(eq=False, slots=True)
class ProxyUDPSession:
    """
    A semantic UDP proxy session.

    Notice that host may be `str` (domain name), which is allowed to be
    asynchronously resolved & mutated into IP address.
    """
    host: IPv4Address | IPv6Address | str
    port: int

@dataclass(eq=False, slots=True, frozen=True)
class ProxyUDPMessage:
    """
    A conceptual TCP message in `ProxyUDPSession`.
    """
    bound: ProxyUDPSession
    data: bytes
    flag: Literal["SYN", "FIN"] | None

class ProxyBidict[X, Y]:
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
    def xgety(self, x: X) -> Y:
        """
        Get relation by `X`.

        `KeyError` if not exist.
        """
        return self._x[x]
    def ygetx(self, y: Y) -> X:
        """
        Get relation by `Y`.

        `KeyError` if not exist.
        """
        return self._y[y]
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

# Unidirectional control signals.
ProxySignal = Literal[
    # Asks a node to immediately clear up its resource and return
    # Effort to maintain a consistent state is not required
    "SIGKILL",
    # For nodes on SIGTERM boundary, stop accepting new connections.
    # For all nodes, return after all existing connections are closed.
    "SIGTERM",
]

ProxyEdgeEnd = tuple[Queue, Queue]

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
    ABC for all `ProxyNode`.

    A `ProxyNode` is a async runtime service managed by `ProxyGraph`.

    This class declares abstract ProxyNode interface and some syntactic
    sugar.

    Implementor should at least define class __slots__ and _version,
    instance _edges, _running, _controller, _boundary in __init__,
    then define a concrete self.run().
    """
    __slots__ = ()

    _version = "" # Don't fallback to an innocent version number
    @classmethod
    def version(cls) -> str:
        """
        Get the version of the node. Formats may differ between nodes.
        """
        return cls._version
    @abstractmethod
    def edges(self) -> list[ProxyEdgeEnd | None]:
        """
        Get the node's edges.

        Unless otherwise documented, do not mutate while running.
        """
        return self._edges # type: ignore
    @abstractmethod
    def controller(self) -> Queue[ProxySignal]:
        """
        Get the node's controller end. (mpsc)
        """
        return self._controller # type: ignore
    def running(self) -> bool:
        """
        Returns `True` iff the node is running.
        """
        return self._running # type: ignore
    @abstractmethod
    def boundary(self) -> bool:
        """
        Returns `True` iff the node is a SIGTERM boundary node.
        """
        return self._boundary # type: ignore
    @abstractmethod
    async def run(self) -> ProxySignal | None:
        """
        Run the node.

        This is usually managed by a `ProxyGraph`, but advanced users may
        orchestrate their own solution.

        The node may return a signal to be broadcasted. The node may also
        just propagate an exception.

        Raises `RuntimeError` if the node is already running, raises
        `ValueError` if the node is misconfigured.

        For Implementors: `SIGKILL` is the preferred signal on exception
        to prevent active probing.
        """
        ...
    def _open(self, edge: int, obj: ProxyTCPConnection | ProxyUDPConnection | ProxyTCPSession | ProxyUDPSession):
        """
        Push a SYN for a newly constructed connection or session.
        """
        if isinstance(obj, ProxyTCPConnection):
            self._edges[edge][1].put_nowait(ProxyTCPPacket(obj, b"", "SYN")) # type: ignore
        elif isinstance(obj, ProxyTCPSession):
            self._edges[edge][1].put_nowait(ProxyTCPMessage(obj, b"", "SYN")) # type: ignore
        elif isinstance(obj, ProxyUDPConnection):
            self._edges[edge][1].put_nowait(ProxyUDPPacket(obj, b"", "SYN")) # type: ignore
        else:
            self._edges[edge][1].put_nowait(ProxyUDPMessage(obj, b"", "SYN")) # type: ignore
    def _send(self, edge: int, obj: ProxyTCPConnection | ProxyUDPConnection | ProxyTCPSession | ProxyUDPSession, data: bytes):
        """
        Send data to connection or session.
        """
        if isinstance(obj, ProxyTCPConnection):
            self._edges[edge][1].put_nowait(ProxyTCPPacket(obj, data, None)) # type: ignore
        elif isinstance(obj, ProxyTCPSession):
            self._edges[edge][1].put_nowait(ProxyTCPMessage(obj, data, None)) # type: ignore
        elif isinstance(obj, ProxyUDPConnection):
            self._edges[edge][1].put_nowait(ProxyUDPPacket(obj, data, None)) # type: ignore
        else:
            self._edges[edge][1].put_nowait(ProxyUDPMessage(obj, data, None)) # type: ignore
    def _close(self, edge: int, obj: ProxyTCPConnection | ProxyUDPConnection | ProxyTCPSession | ProxyUDPSession):
        """
        Push a FIN for a closing connection or session.
        """
        if isinstance(obj, ProxyTCPConnection):
            self._edges[edge][1].put_nowait(ProxyTCPPacket(obj, b"", "FIN")) # type: ignore
        elif isinstance(obj, ProxyTCPSession):
            self._edges[edge][1].put_nowait(ProxyTCPMessage(obj, b"", "FIN")) # type: ignore
        elif isinstance(obj, ProxyUDPConnection):
            self._edges[edge][1].put_nowait(ProxyUDPPacket(obj, b"", "FIN")) # type: ignore
        else:
            self._edges[edge][1].put_nowait(ProxyUDPMessage(obj, b"", "FIN")) # type: ignore
    def _reject(self, edge: int, obj: ProxyTCPPacket | ProxyUDPPacket | ProxyTCPMessage | ProxyUDPMessage):
        """
        Reject packet or message by pushing a FIN back.
        """
        if isinstance(obj, ProxyTCPPacket):
            self._edges[edge][1].put_nowait(ProxyTCPPacket(obj.bound, b"", "FIN")) # type: ignore
        elif isinstance(obj, ProxyTCPMessage):
            self._edges[edge][1].put_nowait(ProxyTCPMessage(obj.bound, b"", "FIN")) # type: ignore
        elif isinstance(obj, ProxyUDPPacket):
            self._edges[edge][1].put_nowait(ProxyUDPPacket(obj.bound, b"", "FIN")) # type: ignore
        else:
            self._edges[edge][1].put_nowait(ProxyUDPMessage(obj.bound, b"", "FIN")) # type: ignore
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
    Async runtime manager; A referential list that groups node together.
    Also used for connecting nodes.
    """
    __slots__ = (
        "_controller",
        "_nodes",
        "_running"
    )
    def __init__(self, *nodes: ProxyNode):
        self._nodes: list[ProxyNode] = list(nodes)
        self._running: bool = False
        self._controller: HybridQueue[ProxySignal] = HybridQueue()

    def nodes(self) -> list[ProxyNode]:
        """
        Get nodes in the graph.
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
        """
        Controller queue lifetime manager.
        """
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
        in iteration order, until either side is full. (Symmetric)

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

    async def run(self) -> Exception | None:
        """
        Run the graph.

        Returns last error; Raises `RuntimeError` instead if any node in
        the graph is already running.

        Immediately claims ownership of the nodes; Some nodes might still be
        internally mutable.
        """
        if self._running or any(node.running() for node in self._nodes):
            raise RuntimeError("Something is already running")
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
                except Exception as e: # noqa: BLE001
                    error = e
                    for node in self._nodes:
                        node.controller().put_nowait("SIGKILL")
        self._running = False
        _penprox_running_graphs.remove(self)
        return error
