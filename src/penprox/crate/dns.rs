use crate::sdk::*;
use std::{collections::{HashMap, hash_map::RandomState}, hash::{BuildHasher, DefaultHasher, Hasher}, net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr}, time::Duration};
use async_trait::async_trait;
use moka::future::Cache;
use pyo3::{exceptions::PyValueError, prelude::*, pyclass, pymethods};
use simple_dns::{CLASS, Name, Packet as DNSPacket, QCLASS, QTYPE, Question, TYPE, rdata::RData};
use tokio::{net::{UdpSocket}, sync::{OwnedMutexGuard, mpsc::{Receiver, Sender, channel}}, time::{Instant, sleep_until}};

pub const DNS_TIMEOUT: Duration = Duration::from_secs(5);
pub const DNS_CNAME_DEPTH: u8 = 16;
pub const DNS_BUFFER_SIZE: usize = 2048;

struct DNSNonce {
    state: DefaultHasher,
    counter: usize
}

impl DNSNonce {
    fn new() -> Self {
        Self {
            state: RandomState::new().build_hasher(),
            counter: 0
        }
    }
    fn next(&mut self) -> u16 {
        self.counter += 1;
        self.state.write_usize(self.counter);
        self.state.finish() as u16
    }
}

/// Helper function that FINs the connections and removes them from `block`.
/// 
/// This function only fails catasptrophically.
#[allow(clippy::mutable_key_type)]
async fn dns_reject(
    waiters: Vec<ConnectionToken>,
    blocked: &mut HashMap<ConnectionToken, Vec<DownwardPacket>>,
    upstream_sender: &Sender<UpwardPacket>
) -> bool {
    for connection in waiters {
        blocked.remove(&connection); // Drops packets
        let packet = UpwardPacket::FIN(connection);
        if upstream_sender.send(packet).await.is_err() {
            tracing::error!("End closed");
            return true;
        }
    }
    false
}

/// Stateless wrapper of resolver downstream.
/// (The user must manage connection state by themselves.)
enum DNSResolver {
    Socket(UdpSocket),
    End(Sender<DownwardPacket>, OwnedMutexGuard<Receiver<UpwardPacket>>, ConnectionToken)
}

struct DNSQuery<'a> {
    name: &'a str,
    qtypes: &'a [TYPE],
    id: u16 // id is just for security, techinically removable if we're fine being attacked
}

struct DNSReply<'a> {
    name: String,
    /// `None` is negative response.
    rdata: Option<RData<'a>>,
    id: u16
}

impl DNSResolver {
    /// Buffer should be of reasonable size for a DNS packet.
    async fn recv(&mut self, dns_buffer: &mut [u8]) -> Result<DNSReply<'static>, Option<Signal>> {
        let box_buffer; // Lifetime extension
        let reply = match self {
            DNSResolver::Socket(socket) => {
                let Ok(count) = socket.recv(dns_buffer).await else {
                    tracing::error!("DNS resolver socket closed");
                    return Err(Some(Signal::SIGTERM));
                };
                DNSPacket::parse(&dns_buffer[..count]).map_err(|_| {
                    tracing::debug!("Received invalid DNS response");
                    None
                })?
            },
            DNSResolver::End(_, receiver, _) => {
                let UpwardPacket::Data(upward) = receiver.recv().await.ok_or(Signal::SIGTERM)? else {
                    tracing::error!("Received non-data packet from DNS resolver");
                    return Err(Some(Signal::SIGTERM));
                };
                box_buffer = Into::<ConnectionDetached>::into(upward).data;
                DNSPacket::parse(&box_buffer).map_err(|_| {
                    tracing::debug!("Received invalid DNS response");
                    None
                })?
            }
        };
        let question = reply.questions.first().ok_or(None)?;
        let name = question.qname.to_string().trim_end_matches('.').to_ascii_lowercase();
        let mut rdata = None;
        for record in &reply.answers {
            match (&record.rdata, question.qtype) {
                (RData::A(_), QTYPE::TYPE(TYPE::A)) | (RData::AAAA(_), QTYPE::TYPE(TYPE::AAAA)) => {
                    rdata = Some(record.rdata.clone().into_owned());
                    break;
                }
                (RData::CNAME(_), _) if rdata.is_none() => {
                    rdata = Some(record.rdata.clone().into_owned());
                }
                _ => tracing::debug!("DNS reply has no recognizable answer")
            }
        }
        Ok(DNSReply {
            name,
            rdata,
            id: reply.id()
        })
    }
    /// Craft and send a DNS query over the resolver transport.
    async fn query(&mut self, query: DNSQuery<'_>) -> Result<(), Option<Signal>> {
        for qtype in query.qtypes {
            let data = {
                let name = Name::new(query.name).map_err(|_| {
                    tracing::debug!("Invalid queried domain");
                    None
                })?;
                let mut packet = DNSPacket::new_query(query.id);
                packet.set_flags(simple_dns::PacketFlag::RECURSION_DESIRED);
                packet.questions.push(Question::new(name, (*qtype).into(), QCLASS::CLASS(CLASS::IN), false));
                packet.build_bytes_vec_compressed().map_err(|_| {
                    tracing::debug!("c022d224-e635-4f41-993f-e8ac9b1cdb43"); // Yes, a random uuid because I'm not very sure when it will happen
                    Signal::SIGTERM
                })?
            };
            match self {
                DNSResolver::Socket(socket) => {
                    socket.send(&data).await.map_err(|_| {
                        tracing::error!("DNS resolver socket closed");
                        Some(Signal::SIGTERM)
                    })?;
                }
                DNSResolver::End(sender, _, connection) => {
                    let downward = ConnectionDownward::new(connection.clone(), data.into_boxed_slice()).await;
                    sender.send(DownwardPacket::Data(downward)).await.map_err(|_| {
                        tracing::debug!("DNS resolver downstream closed");
                        Some(Signal::SIGTERM)
                    })?;
                }
            }
        }
        Ok(())
    }
}

/// An entire resolution session. Moves with CNAME hops and caches the trace.
struct Resolution {
    waiters: Vec<ConnectionToken>,
    id: u16,
    deadline: Instant,
    budget: u8
}

/// Node for DNS. Intercepts & blocks new connections with unresolved domain,
/// releasing after resolution.
/// 
/// When `middleware` is true, the node runs in middleware mode. The node
/// will have one upstream and one downstream, acts purely as a middleware
/// that resolves DNS locally.
/// 
/// When `middleware` is false, the node runs in explicit mode. The node
/// will have one upstream and two downstreams, in which the additional
/// downstream is for DNS traffic.
/// 
/// When operating with `V4` / `V6` address mode, DNSNode only tries to resolve
/// into the given address family. `V4V6` / `V6V4` are treated the same here.
/// 
/// User may specify the size and TTL of the node-local DNS cache.
#[pyclass]
#[derive(Debug)]
pub struct DNSNode {
    upstream: NodeUpstreamEndToken,
    downstream: NodeDownstreamEndToken,
    resolver_downstream: Option<NodeDownstreamEndToken>,
    signal_receiver: Receiver<Signal>,
    resolver: SocketAddr,
    mode: AddressMode,
    cname_cache: Cache<String, String>,
    address_cache: Cache<String, Option<IpAddr>>
}

impl DNSNode {
    #[allow(clippy::new_ret_no_self)]
    pub fn new(mut resolver: Host, port: u16, middleware: bool, mode: AddressMode, size: u64, ttl: Duration) -> Result<NodeToken, &'static str> {
        let Some(resolver) = resolver.wait_resolve() else {
            tracing::error!("Invalid host");
            return Err("Invalid host");
        };
        let (signal_sender, signal_receiver) = channel(SIGNAL_BUFFER_SIZE);
        let upstream = NodeUpstreamEndToken::new();
        let downstream = NodeDownstreamEndToken::new();
        match middleware {
            true => Ok(NodeToken::new(
                Box::new(Self {
                    upstream: upstream.clone(),
                    downstream: downstream.clone(),
                    resolver_downstream: None,
                    signal_receiver,
                    resolver: SocketAddr::new(resolver, port),
                    mode,
                    cname_cache: Cache::builder()
                        .max_capacity(size)
                        .time_to_live(ttl)
                        .build(),
                    address_cache: Cache::builder()
                        .max_capacity(size)
                        .time_to_live(ttl)
                        .build()
                }),
                signal_sender,
                NodeUpstreamInterface::new(vec![upstream]),
                NodeDownstreamInterface::new(vec![downstream])
            )),
            false => {
                let resolver_downstream = NodeDownstreamEndToken::new();
                Ok(NodeToken::new(
                    Box::new(Self {
                        upstream: upstream.clone(),
                        downstream: downstream.clone(),
                        resolver_downstream: Some(resolver_downstream.clone()),
                        signal_receiver,
                        resolver: SocketAddr::new(resolver, port),
                        mode,
                        cname_cache: Cache::builder()
                            .max_capacity(size)
                            .time_to_live(ttl)
                            .build(),
                        address_cache: Cache::builder()
                            .max_capacity(size)
                            .time_to_live(ttl)
                            .build()
                    }),
                    signal_sender,
                    NodeUpstreamInterface::new(vec![upstream]),
                    NodeDownstreamInterface::new(vec![downstream, resolver_downstream])
                ))
            }
        }
    }
}

#[pymethods]
impl DNSNode {
    #[new]
    #[pyo3(signature = (resolver = Host::IpAddr(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))), middleware = true, size = 5000, ttl = 300.0, *, mode = AddressMode::V4, port = 53))]
    #[allow(clippy::new_ret_no_self)]
    // Port is deferred in argv because it's very unlikely that you'll ever need it
    fn python_new(resolver: Host, middleware: bool, size: u64, ttl: f64, mode: AddressMode, port: u16) -> PyResult<NodeToken> {
        if ttl <= 0.0 {
            tracing::error!("Invalid TTL");
            return Err(PyValueError::new_err("Invalid TTL"));
        }
        Self::new(resolver, port, middleware, mode, size, Duration::from_secs_f64(ttl)).map_err(PyValueError::new_err)
    }
}

#[async_trait]
impl Node for DNSNode {
    #[tracing::instrument(name="DNSNode::run", skip_all)]
    async fn run(&mut self) -> Result<Option<Signal>, GraphError> {
        let upstream_sender = self.upstream.sender().map_err(GraphError::from)?;
        let mut upstream_receiver = self.upstream.receiver().map_err(GraphError::from)?;
        let downstream_sender = self.downstream.sender().map_err(GraphError::from)?;
        let mut downstream_receiver = self.downstream.receiver().map_err(GraphError::from)?;
        let mut resolver = match &self.resolver_downstream {
            None => {
                let socket = match self.resolver {
                    SocketAddr::V4(_) => UdpSocket::bind("0.0.0.0:0").await.map_err(|error| { tracing::error!("Cannot bind v4 UDP port: {error}"); GraphError::NodeError })?,
                    SocketAddr::V6(_) => UdpSocket::bind("[::]:0").await.map_err(|error| { tracing::error!("Cannot bind v6 UDP port: {error}"); GraphError::NodeError })?
                };
                socket.connect(self.resolver).await.map_err(|error| {
                    tracing::error!("Cannot connect to resolver: {error}");
                    GraphError::NodeError
                })?;
                DNSResolver::Socket(socket)
            },
            Some(end) => {
                let resolver_sender = end.sender().map_err(GraphError::from)?;
                let resolver_receiver = end.receiver().map_err(GraphError::from)?;
                let resolver_connection = ConnectionToken::new(Host::IpAddr(self.resolver.ip()), Transport::UDP, self.resolver.port());
                resolver_sender.send(DownwardPacket::SYN(resolver_connection.clone())).await?;
                DNSResolver::End(resolver_sender, resolver_receiver, resolver_connection)
            }
        };
        self.signal_receiver.clear();
        let qtypes: &[TYPE] = match self.mode {
            AddressMode::V4 => &[TYPE::A],
            AddressMode::V6 => &[TYPE::AAAA],
            AddressMode::V4V6 => &[TYPE::A, TYPE::AAAA],
            AddressMode::V6V4 => &[TYPE::AAAA, TYPE::A]
        };
        let cname_cache = self.cname_cache.clone();
        let address_cache = self.address_cache.clone();
        #[allow(clippy::mutable_key_type)]
        let mut blocked: HashMap<ConnectionToken, Vec<DownwardPacket>> = HashMap::new();
        let mut resolving: HashMap<String, Resolution> = HashMap::new();
        let mut dns_buffer = [0u8; DNS_BUFFER_SIZE];
        let mut dns_nonce = DNSNonce::new();
        
        loop {
            let deadline = resolving.values().map(|resolution| resolution.deadline).min();
            tokio::select! {
                biased;
                signal = self.signal_receiver.recv() => match signal {
                    Some(Signal::SIGTERM) => return Ok(None),
                    None => {
                        tracing::error!("Signal receiver is closed");
                        return Err(GraphError::Disconnected)
                    },
                    _ => continue
                },
                packet = upstream_receiver.recv() => match packet {
                    Some(packet) => {
                        let connection = packet.connection().clone();
                        if packet.is_syn() && !connection.is_resolved() {
                            if let Some(packets) = blocked.get_mut(&connection) {
                                packets.push(packet);
                                continue;
                            };
                            let Host::Domain(domain) = connection.host() else {
                                unreachable!();
                            };
                            // Walk the caches to either answer now or find the name to query.
                            let mut name = domain.trim_end_matches('.').to_ascii_lowercase();
                            let mut cached = None;
                            let mut terminal = None;
                            for _ in 0..=DNS_CNAME_DEPTH {
                                if let Some(answer) = address_cache.get(&name).await {
                                    cached = Some(answer);
                                    break;
                                }
                                match cname_cache.get(&name).await {
                                    Some(target) => name = target,
                                    None => {
                                        terminal = Some(name.clone());
                                        break;
                                    }
                                }
                            }
                            match cached {
                                Some(Some(ip_addr)) => {
                                    connection.resolve(ip_addr);
                                    downstream_sender.send(packet).await?;
                                }
                                Some(None) => { // Negative cache hit
                                    upstream_sender.send(UpwardPacket::FIN(connection.clone())).await?;
                                }
                                None => {
                                    let Some(name) = terminal else { // CNAME exhaustion (Only reachable by cycle)
                                        upstream_sender.send(UpwardPacket::FIN(connection.clone())).await?;
                                        continue;
                                    };
                                    if let Some(resolution) = resolving.get_mut(&name) {
                                        resolution.waiters.push(connection.clone());
                                        blocked.insert(connection, vec![packet]);
                                        continue;
                                    }
                                    let resolution = Resolution {
                                        waiters: vec![connection.clone()],
                                        id: dns_nonce.next(),
                                        deadline: Instant::now() + DNS_TIMEOUT,
                                        budget: DNS_CNAME_DEPTH
                                    };
                                    if let Err(signal) = resolver.query(DNSQuery { name: &name, qtypes, id: resolution.id }).await {
                                        match signal {
                                            Some(signal) => return Ok(Some(signal)),
                                            None => {
                                                if dns_reject(vec![connection], &mut blocked, &upstream_sender).await {
                                                    return Ok(Some(Signal::SIGTERM));
                                                }
                                                continue;
                                            }
                                        }
                                    };
                                    
                                    resolving.insert(name, resolution);
                                    blocked.insert(connection, vec![packet]);
                                }
                            }
                            continue;
                        }
                        if let Some(packets) = blocked.get_mut(&connection) {
                            packets.push(packet);
                        } else {
                            downstream_sender.send(packet).await?;
                        }
                    },
                    None => {
                        tracing::error!("End closed"); 
                        return Err(GraphError::Disconnected);
                    }
                },
                received = resolver.recv(&mut dns_buffer) => {
                    let reply = match received {
                        Ok(reply) => reply,
                        Err(Some(signal)) => return Ok(Some(signal)),
                        Err(None) => continue
                    };
                    let name = reply.name;
                    if !matches!(resolving.get(&name).map(|resolution| resolution.id == reply.id), Some(true)) {
                        continue
                    }; // Can't remove yet
                    let mut resolution = resolving.remove(&name).expect("Removing non-existent resolution that is gettable");
                    let ip_addr = match &reply.rdata {
                        Some(RData::A(address)) => Some(IpAddr::V4(Ipv4Addr::from(address.address))),
                        Some(RData::AAAA(address)) => Some(IpAddr::V6(Ipv6Addr::from(address.address))),
                        _ => None
                    };
                    if let Some(ip_addr) = ip_addr {
                        address_cache.insert(name, Some(ip_addr)).await;
                        // dns_accept
                        for connection in resolution.waiters {
                            connection.resolve(ip_addr);
                            if let Some(packets) = blocked.remove(&connection) {
                                for packet in packets {
                                    downstream_sender.send(packet).await?;
                                }
                            }
                        }
                        continue;
                    }
                    if let Some(RData::CNAME(target)) = &reply.rdata {
                        let target = target.to_string().trim_end_matches('.').to_ascii_lowercase();
                        cname_cache.insert(name, target.clone()).await;
                        if resolution.budget == 0 {
                            if dns_reject(resolution.waiters, &mut blocked, &upstream_sender).await {
                                return Ok(Some(Signal::SIGTERM));
                            }
                            continue;
                        }
                        resolution.budget -= 1;
                        if let Some(existing) = resolving.get_mut(&target) {
                            existing.waiters.extend(resolution.waiters);
                            continue;
                        }
                        let id = dns_nonce.next();
                        if resolver.query(DNSQuery { name: &target, qtypes, id }).await.is_err() {
                            if dns_reject(resolution.waiters, &mut blocked, &upstream_sender).await {
                                return Ok(Some(Signal::SIGTERM));
                            }
                            continue;
                        };
                        resolution.id = id;
                        resolution.deadline = Instant::now() + DNS_TIMEOUT;
                        resolving.insert(target, resolution);
                        continue;
                    }
                    address_cache.insert(name, None).await;
                    if dns_reject(resolution.waiters, &mut blocked, &upstream_sender).await {
                        return Ok(Some(Signal::SIGTERM));
                    }
                },
                packet = downstream_receiver.recv() => match packet {
                    Some(packet) => {
                        if upstream_sender.send(packet).await.is_err() {
                            return Ok(Some(Signal::SIGTERM));
                        }
                    },
                    None => return Ok(Some(Signal::SIGTERM))
                },
                _ = async move {
                    match deadline {
                        Some(deadline) => sleep_until(deadline).await,
                        None => std::future::pending::<()>().await
                    }
                } => {
                    let now = Instant::now();
                    let expired: Vec<String> = resolving.iter()
                        .filter(|(_, resolution)| resolution.deadline <= now)
                        .map(|(name, _)| name.clone())
                        .collect();
                    for name in expired {
                        if let Some(resolution) = resolving.remove(&name)
                            && dns_reject(resolution.waiters, &mut blocked, &upstream_sender).await {
                            return Ok(Some(Signal::SIGTERM));
                        }
                    }
                }
            }
        }
    }
}
