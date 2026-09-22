import aiodns
import dnslib

from ..sdk import *


def waitDNS(host: str) -> IPv4Address | IPv6Address:
    """
    Simple synchronous system DNS lookup. Raises exception if fails.
    """
    addrInfo = socket.getaddrinfo(host, None, socket.AF_UNSPEC)
    for addr in addrInfo:
        match addr[0]:
            case socket.AF_INET:
                return IPv4Address(addr[4][0])
            case socket.AF_INET6:
                return IPv6Address(addr[4][0])
    raise socket.gaierror(f"Domain {host} DNS lookup did not return any address")

dnsResolver: aiodns.DNSResolver | None = None

async def queryDNS(domain: str) -> IPv4Address | IPv6Address | None:
    """
    DNS lookup by async runtime local DNS server.
    """
    global dnsResolver
    loop = asyncio.get_running_loop()
    if dnsResolver is None or dnsResolver.loop is not loop:
        dnsResolver = aiodns.DNSResolver(loop=loop)
    ipv4 = dnsResolver.getaddrinfo(domain, socket.AF_INET)
    ipv6 = dnsResolver.getaddrinfo(domain, socket.AF_INET6)
    pending = (ipv4, ipv6)
    try:
        while pending:
            done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
            for task in done:
                result = task.result()
                if task is ipv4 and result.nodes:
                    return IPv4Address(result.nodes[0].addr[0].decode())
                elif result.nodes:
                    return IPv6Address(result.nodes[0].addr[0].decode())
    except aiodns.error.DNSError:
        pass

async def resolveDNS(bound: TCPSession | UDPSession) -> bool:
    """
    Idempotently resolve `TCPSession` / `UDPSession` by async runtime
    local DNS server.

    Returns `False` if failed.
    """
    if not isinstance(bound.host, str):
        return True
    answer = await queryDNS(bound.host)
    # Async resolve race
    if isinstance(bound.host, str):
        if not answer:
            return False
        bound.host = answer
    return True

class DNSInterface:
    """
    Async DNS interface with LRUTTL cache. Wrapper of resolver downstream.
    Only parses A records for now.

    Takes one interface upstream and one resolver downstream.
    
    Interface upstream consumes `str` domain name queries | `None` shut down
    control signal, produces `(str, IPv4Address | IPv6Address | None)` result
    | `None` malformed result. To prevent async races, the interface always
    returns one answer for one query. Upstream should aggregate queries
    on its own.

    Downstream is standard `UDPPacket` resolver downstream edge.
    """
    __slots__ = (
        "_downstream",
        "_resolver",
        "_running",
        "_size",
        "_ttl",
        "_upstream"
    )
    def __init__(
        self,
        upstream: EdgeEnd,
        downstream: EdgeEnd,
        resolver: tuple[IPv4Address | IPv6Address, int],
        size: int = 5000,
        ttl: float = 300
    ):
        assert size > 0
        assert ttl > 0
        self._upstream: EdgeEnd = upstream
        self._downstream: EdgeEnd = downstream
        self._resolver: tuple[IPv4Address | IPv6Address, int] = resolver
        self._size: int = size
        self._ttl: float = ttl
        self._running: bool = False

    async def run(self):
        """
        Run DNS interface.
        """
        if self._running:
            raise RuntimeError("DNS Interface is already running")
        cache: LRUTTLDict[str, IPv4Address | IPv6Address] = LRUTTLDict(self._size, self._ttl)
        # Will reuse this connection
        # Connection is active iff queries to fit in SIGTERM semantic
        connection = UDPConnection(*self._resolver)
        queries: int = 0
        upstream = create_task(self._upstream[0].get())
        downstream = create_task(self._downstream[0].get())
        while True:
            done, _ = await asyncio.wait(
                (upstream, downstream),
                return_when=asyncio.FIRST_COMPLETED
            )
            for task in done:
                match task:
                    case _ if task is upstream:
                        upstream = create_task(self._upstream[0].get())
                        host = cast(str | None, task.result())
                        if host is None:
                            logger.debug("DNSInterface: Received shut down signal, quitting")
                            if queries:
                                self._downstream[1].put_nowait(UDPPacket(
                                    connection,
                                    "FIN"
                                ))
                            self._running = False
                            return
                        record = cache.get(host)
                        if record:
                            self._upstream[1].put_nowait((host, record))
                            continue
                        if not queries:
                            self._downstream[1].put_nowait(UDPPacket(
                                connection,
                                "SYN"
                            ))
                        queries += 1
                        qA = dnslib.DNSRecord.question(host, "A").pack()
                        self._downstream[1].put_nowait(UDPPacket(
                            connection,
                            bytes(qA)
                        ))
                        continue
                    case _: # downstream
                        downstream = create_task(self._downstream[0].get())
                        packet = cast(UDPPacket, task.result())
                        if packet.payload == "SYN": # Never
                            logger.error("DNSInterface: Resolver downstream sent SYN?")
                            continue
                        if packet.payload == "FIN":
                            queries = 0
                            continue
                        queries -= 1
                        if not queries:
                            self._downstream[1].put_nowait(UDPPacket(
                                connection,
                                "FIN"
                            ))
                        try:
                            record = dnslib.DNSRecord.parse(packet.payload)
                        except Exception as e:  # noqa: BLE001
                            # This is an ERROR for two reasons:
                            # 1) This is really bad, because we don't know which query is fucked,
                            #    so upstream will wait till timeout or permanently connections
                            #    as "resolving".
                            # 2) We trust DNS resolver because we have no choice.
                            logger.error(f"DNSInterface: Resolver sent invalid reply: {e}")
                            self._upstream[1].put_nowait(None)
                            continue
                        if not record.rr:
                            self._upstream[1].put_nowait((str(record.q.qname)[:-1], None))
                            continue
                        rr = record.a
                        domain = str(rr.rname)[:-1]
                        if rr.rtype != 1: # IPv4
                            self._upstream[1].put_nowait((str(record.q.qname)[:-1], None))
                        address = IPv4Address(rr.rdata)
                        cache.set(domain, address)
                        self._upstream[1].put_nowait((domain, address))
                        continue

class DNSMiddlewareNode(BaseNode):
    """
    On-path middleware node that blocks `TCPSession` / `UDPSession`
    messages with a domain name host until it resolves them. Only scans SYN
    messages for new sessions to resolve.

    DNS resolver uses python native IP represenation or a string domain,
    which is resolved using system DNS at construct time. Port 53 is used
    by default.

    Has a `TCPMessage` / `UDPMessage` upstream, a flow-pass 
    downstream and a `UDPPacket` resolver downstream.
    """
    __slots__ = (
        "_boundary",
        "_controller",
        "_edges",
        "_resolver",
        "_running",
    )
    def __init__(
            self,
            resolver: IPv4Address | IPv6Address | str | tuple[
                IPv4Address | IPv6Address | str, int
            ] = IPv4Address("1.1.1.1"),  # noqa: B008
            /,
            boundary: bool = False
        ) -> None:
        if not isinstance(resolver, tuple):
            resolver = (resolver, 53)
        if isinstance(resolver[0], str):
            resolver = (waitDNS(resolver[0]), resolver[1])
        self._resolver: tuple[IPv4Address | IPv6Address, int] = cast(
            tuple[IPv4Address | IPv6Address, int], resolver
        )
        self._boundary: bool = boundary
        self._edges: list[EdgeEnd | None] = [None, None, None]
        self._controller: Queue[Signal] = Queue()
        self._running: bool = False
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
        return (1, 2)
    async def run(self) -> Signal | None:
        if self._running:
            raise RuntimeError("Attempted to run a running DNSMiddlewareNode")
        if len(self._edges) != 3 or not all(self._edges):
            raise ValueError("Running improperly connected DNSMiddlewareNode")
        while not self._controller.empty():
            self._controller.get_nowait()
        self._running = True
        logger.info("Running DNSMiddlewareNode...")

        # All connections
        pool: set[TCPSession | UDPSession] = set()
        # Blocked connections
        block: dict[TCPSession | UDPSession, list[TCPMessage | UDPMessage]] = {}
        # Current outreaching DNS queries
        resolving: dict[str, list[TCPSession | UDPSession]] = {}
        signal: Signal | None = None
        while not self._controller.empty():
            self._controller.get_nowait()

        # Resolver downstream wrapper
        interfaceEdge = Edge()
        interface = DNSInterface(
            interfaceEdge[1],
            self._edges[2], # pyright: ignore[reportArgumentType]
            self._resolver
        )
        create_task(interface.run())

        controller = create_task(self._controller.get())
        upstream = create_task(self._edges[0][0].get()) # pyright: ignore[reportOptionalSubscript]
        downstream = create_task(self._edges[1][0].get()) # pyright: ignore[reportOptionalSubscript]
        resolver = create_task(interfaceEdge[0][0].get())
        while True:
            done, _ = await asyncio.wait(
                (controller, upstream, downstream, resolver),
                return_when=asyncio.FIRST_COMPLETED
            )
            for task in done:
                match task:
                    case _ if task is upstream:
                        upstream = create_task(self._edges[0][0].get()) # pyright: ignore[reportOptionalSubscript]
                        message = cast(TCPMessage | UDPMessage, task.result())
                        if message.payload == "SYN":
                            if signal == "SIGTERM" and self._boundary:
                                self._reject(0, message)
                                continue
                            pool.add(message.bound)
                            host = message.bound.host
                            if isinstance(host, str):
                                block[message.bound] = [message]
                                if resolving.get(host):
                                    resolving[host].append(message.bound)
                                else:
                                    logger.debug(f"DNSMiddlewareNode: Resolving host {host}")
                                    resolving[host] = [message.bound]
                                    interfaceEdge[0][1].put_nowait(host)
                                continue
                        if message.bound in block:
                            block[message.bound].append(message)
                            continue
                        self._forward(1, message)
                        if message.payload == "FIN":
                            pool.discard(message.bound)
                            host = message.bound.host
                            if isinstance(host, str):
                                sessions = resolving.get(host)
                                if sessions and message.bound in sessions:
                                    sessions.remove(message.bound)
                                block.pop(message.bound, None)
                            if signal == "SIGTERM" and not pool:
                                logger.info("DNSMiddlewareNode: All connection served, quitting (SIGTERM)")
                                self._running = False
                                interfaceEdge[0][1].put_nowait(None)
                                return
                        continue
                    case _ if task is downstream:
                        downstream = create_task(self._edges[1][0].get()) # pyright: ignore[reportOptionalSubscript]
                        message = cast(TCPMessage | UDPMessage, task.result())
                        self._forward(0, message)
                        if message.payload == "FIN":
                            pool.discard(message.bound)
                            if signal == "SIGTERM" and not pool:
                                logger.info("DNSMiddlewareNode: All connection served, quitting (SIGTERM)")
                                self._running = False
                                interfaceEdge[0][1].put_nowait(None)
                                return
                        continue
                    case _ if task is resolver:
                        resolver = create_task(interfaceEdge[0][0].get())
                        result = cast(tuple[str, IPv4Address | IPv6Address | None] | None, task.result())
                        if not result:
                            logger.error("DNSMiddleware: Received malformed DNS result. This leaks memory and hangs connections.")
                            continue
                        sessions = resolving.pop(result[0], None)
                        if not sessions: # Never
                            logger.error(f"DNSMiddlewareNode: Received DNS result of {result[0]} (did not ask)")
                            continue
                        if not result[1]:
                            logger.debug(f"DNSMiddlewareNode: {result[0]} DNS lookup did not return any address, rejecting sessions")
                            for session in sessions:
                                self._close(0, session)
                                pool.discard(session)
                                block.pop(session, None)
                            if signal == "SIGTERM" and not pool:
                                logger.info("DNSMiddlewareNode: All connection served, quitting (SIGTERM)")
                                self._running = False
                                interfaceEdge[0][1].put_nowait(None)
                                return
                            continue
                        logger.debug(f"DNSMiddlewareNode: Host {result[0]} resolved into {result[1]!s}, releasing blocked sessions")
                        for session in sessions:
                            session.host = result[1]
                            messages = block.pop(session, None)
                            if messages:
                                for message in messages:
                                    self._forward(1, message)
                        continue
                    case _: # controller
                        controller = create_task(self._controller.get())
                        _signal = cast(Signal, task.result())
                        logger.info(f"DNSMiddlewareNode: Received {_signal} signal")
                        if _signal == "SIGKILL":
                            self._running = False
                            interfaceEdge[0][1].put_nowait(None)
                            return
                        if _signal == "SIGTERM":
                            if not pool:
                                logger.info("DNSMiddlewareNode: All connection served, quitting (SIGTERM)")
                                self._running = False
                                interfaceEdge[0][1].put_nowait(None)
                                return
                            signal = "SIGTERM"
                        continue

                        
                        
                            



