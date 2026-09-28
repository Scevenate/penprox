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

@id_hash
@dataclass(eq=False, slots=True)
class DNSQuery:
    """
    An active query process responsible for returning a final answer to its
    upstreamQueries.
    """
    # Upstream queries to resolve when process returned (domain, count)
    upstreamQueries: dict[str, int]
    # Current querying domain (subject to CNAME)
    downstreamQuery: str
    # Response counter for v4+v6 query + first return None
    tried: bool
    def add(self, query: "DNSQuery"):
        """
        Move the upstream queries in the given query to this one.
        """
        for upstreamQuery, count in query.upstreamQueries.items():
            if upstreamQuery in self.upstreamQueries:
                self.upstreamQueries[upstreamQuery] += count
            else:
                self.upstreamQueries[upstreamQuery] = count
        query.upstreamQueries = {}

class DNSInterface:
    """
    Async DNS interface with LRUTTL cache. Wrapper of resolver downstream.

    Takes one interface upstream and one resolver downstream.
    
    Interface upstream consumes `str` domain name queries | `None` shut down
    control signal, produces `(str, IPv4Address | IPv6Address | None)` result.
    To prevent async races, the interface always returns one answer for one query.
    Upstream should aggregate queries on its own.

    Downstream is standard `UDPPacket` resolver downstream edge.
    """
    __sentinel = object()
    __slots__ = (
        "_connection",
        "_downstream",
        "_mode",
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
        mode: Literal["v4v6", "v4", "v6"],
        size: int = 5000,
        ttl: float = 300
    ):
        assert size > 0
        assert ttl > 0
        self._upstream: EdgeEnd = upstream
        self._downstream: EdgeEnd = downstream
        self._mode: Literal["v4v6", "v4", "v6"] = mode  # noqa: UP037
        self._size: int = size
        self._ttl: float = ttl
        self._running: bool = False
        # One instance one downstream connection. Will be reused.
        # Connection is active iff queries to fit in SIGTERM semantic
        self._connection = UDPConnection(*resolver)

    def _query(self, domain: str):
        """
        Query downstream a domain.
        """
        if self._mode != "v6":
            self._downstream[1].put_nowait(UDPPacket(
                self._connection,
                bytes(dnslib.DNSRecord.question(domain, "A").pack())
            ))
        if self._mode != "v4":
            self._downstream[1].put_nowait(UDPPacket(
                self._connection,
                bytes(dnslib.DNSRecord.question(domain, "AAAA").pack())
            ))

    async def run(self):
        """
        Run DNS interface.
        """
        if self._running:
            raise RuntimeError("DNS Interface is already running")
        self._running = True
        drain(None, [self._upstream, self._downstream])
        cache: LRUTTLDict[str, IPv4Address | IPv6Address | None] = LRUTTLDict(self._size, self._ttl)
        
        # Upstream & downstream DNS query lookup
        upstreamQueries: dict[str, DNSQuery] = {}
        downstreamQueries: dict[str, DNSQuery] = {}
        upstream = create_task(self._upstream[0].get())
        downstream = create_task(self._downstream[0].get())
        while True:
            done, pending = await asyncio.wait(
                (upstream, downstream),
                return_when=asyncio.FIRST_COMPLETED
            )
            for task in done:
                match task:
                    case _ if task is upstream:
                        upstream = create_task(self._upstream[0].get())
                        domain = cast(str | None, task.result())
                        if domain is None:
                            logger.debug("DNSInterface: Received shut down signal, quitting")
                            if downstreamQueries:
                                self._downstream[1].put_nowait(UDPPacket(
                                    self._connection,
                                    "FIN"
                                ))
                            self._running = False
                            cancel(pending)
                            return
                        record = cache.get(domain, DNSInterface.__sentinel)
                        if record is not DNSInterface.__sentinel:
                            self._upstream[1].put_nowait((domain, record))
                            continue
                        if not downstreamQueries:
                            self._downstream[1].put_nowait(UDPPacket(
                                self._connection,
                                "SYN"
                            ))
                        if domain in upstreamQueries:
                            upstreamQueries[domain].upstreamQueries[domain] += 1
                        else:
                            query = DNSQuery({domain: 1}, domain, False)
                            upstreamQueries[domain] = query
                            downstreamQueries[domain] = query
                            self._query(domain)
                        continue
                    case _: # downstream
                        downstream = create_task(self._downstream[0].get())
                        packet = cast(UDPPacket, task.result())
                        if packet.payload == "SYN": # Never
                            logger.error("DNSInterface: Resolver downstream sent SYN")
                            continue
                        if packet.payload == "FIN":
                            # Somehow. Anyway will clean up remaining queries.
                            # Use downstream because it's 1 to 1
                            for query in downstreamQueries.values():
                                for domain, count in query.upstreamQueries.items():
                                    for _ in range(count):
                                        self._upstream[1].put_nowait((domain, None))
                            upstreamQueries = {}
                            downstreamQueries = {}
                            continue
                        try:
                            record = dnslib.DNSRecord.parse(packet.payload)
                        except dnslib.DNSError:
                            # We don't know which query failed so we'll just reset
                            self._downstream[1].put_nowait(UDPPacket(self._connection, "FIN"))
                            for query in downstreamQueries.values():
                                for domain, count in query.upstreamQueries.items():
                                    for _ in range(count):
                                        self._upstream[1].put_nowait((domain, None))
                            upstreamQueries = {}
                            downstreamQueries = {}
                            continue
                        question = record.questions[0]
                        domain = str(question.qname)[:-1]
                        query = downstreamQueries.get(domain)
                        if not query: # Late packet in resolved v4+v6 race
                            continue
                        if not record.rr: # Empty answer
                            if self._mode == "v4v6" and query.tried == False:
                                query.tried = True
                                continue
                            del downstreamQueries[domain]
                            answer = None
                        else:
                            response = record.rr[0]
                            del downstreamQueries[domain]
                            if question.qtype == 1: # v4 query
                                if response.rtype == 1: # v4 answer
                                    answer = IPv4Address(response.rdata)
                                elif response.rtype == 5: # CNAME answer
                                    cdomain = str(response.rdata)[:-1]
                                    cquery = downstreamQueries.get(cdomain)
                                    if cquery:
                                        for upstreamQuery in query.upstreamQueries:
                                            upstreamQueries[upstreamQuery] = cquery
                                        cquery.add(query)
                                    else:
                                        downstreamQueries[cdomain] = query
                                        if cdomain not in query.upstreamQueries:
                                            query.upstreamQueries[cdomain] = 0 # So upstream can safely add queries
                                        query.downstreamQuery = cdomain
                                        self._query(cdomain)
                                    continue
                                else: # Other answer, clean up
                                    answer = None
                            elif question.qtype == 28: # v6 query
                                if response.rtype == 28: # v6 answer
                                    answer = IPv6Address(response.rdata)
                                elif response.rtype == 5: # CNAME answer
                                    cdomain = str(response.rdata)[:-1]
                                    cquery = downstreamQueries.get(cdomain)
                                    if cquery:
                                        for upstreamQuery in query.upstreamQueries:
                                            upstreamQueries[upstreamQuery] = cquery
                                        cquery.add(query)
                                    else:
                                        downstreamQueries[cdomain] = query
                                        if cdomain not in query.upstreamQueries:
                                            query.upstreamQueries[cdomain] = 0 # So upstream can safely add queries
                                        query.downstreamQuery = cdomain
                                        self._query(cdomain)
                                    continue
                                else: # Other answer, clean up
                                    answer = None
                            else: # Other query???, clean up
                                answer = None
                        for upstreamQuery, count in query.upstreamQueries.items():
                            cache.set(upstreamQuery, answer)
                            for _ in range(count):
                                self._upstream[1].put_nowait((upstreamQuery, answer))
                            upstreamQueries.pop(upstreamQuery, None)
                        if not downstreamQueries:
                            self._downstream[1].put_nowait(UDPPacket(self._connection, "FIN"))
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
        "_mode",
        "_resolver",
        "_running",
    )
    def __init__(
            self,
            resolver: IPv4Address | IPv6Address | str | tuple[
                IPv4Address | IPv6Address | str, int
            ] = IPv4Address("1.1.1.1"),  # noqa: B008
            mode: Literal["v4v6", "v4", "v6"] = "v4",
            *args,
            boundary: bool = False
        ) -> None:
        if not isinstance(resolver, tuple):
            resolver = (resolver, 53)
        if isinstance(resolver[0], str):
            resolver = (waitDNS(resolver[0]), resolver[1])
        self._resolver: tuple[IPv4Address | IPv6Address, int] = cast(
            tuple[IPv4Address | IPv6Address, int], resolver
        )
        self._mode: Literal["v4v6", "v4", "v6"] = mode  # noqa: UP037
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
        drain(self._controller, self._edges)
        self._running = True
        logger.info("Running DNSMiddlewareNode...")

        # All connections
        pool: set[TCPSession | UDPSession] = set()
        # Blocked connections
        block: dict[TCPSession | UDPSession, list[TCPMessage | UDPMessage]] = {}
        # Current outreaching DNS queries
        resolving: dict[str, list[TCPSession | UDPSession]] = {}
        signal: Signal | None = None

        # Resolver downstream wrapper
        interfaceEdge = Edge()
        interface = DNSInterface(
            interfaceEdge[1],
            self._edges[2], # pyright: ignore[reportArgumentType]
            self._resolver,
            self._mode
        )
        create_task(interface.run())

        controller = create_task(self._controller.get())
        upstream = create_task(self._edges[0][0].get()) # pyright: ignore[reportOptionalSubscript]
        downstream = create_task(self._edges[1][0].get()) # pyright: ignore[reportOptionalSubscript]
        resolver = create_task(interfaceEdge[0][0].get())
        while True:
            done, pending = await asyncio.wait(
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
                                cancel(pending)
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
                                cancel(pending)
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
                                cancel(pending)
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
                            cancel(pending)
                            return
                        if _signal == "SIGTERM":
                            if not pool:
                                logger.info("DNSMiddlewareNode: All connection served, quitting (SIGTERM)")
                                self._running = False
                                interfaceEdge[0][1].put_nowait(None)
                                cancel(pending)
                                return
                            signal = "SIGTERM"
                        continue
