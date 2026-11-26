use crate::sdk::*;
use std::{collections::HashMap, net::{IpAddr, Ipv4Addr, Ipv6Addr}, sync::{Arc, Mutex as MutexStd}};
use async_trait::async_trait;
use pyo3::{exceptions::PyValueError, prelude::*};
use tokio::{sync::{OwnedMutexGuard, mpsc::{Receiver, Sender, channel}}, task::JoinSet};

// SOCKS5 byte field semantics
const SOCKS5_VERSION: u8 = 0x05;
const SOCKS5_METHOD_NO_AUTH: u8 = 0x00;
const SOCKS5_COMMAND_CONNECT: u8 = 0x01;
const SOCKS5_ADDRESS_IPV4: u8 = 0x01;
const SOCKS5_ADDRESS_DOMAIN: u8 = 0x03;
const SOCKS5_ADDRESS_IPV6: u8 = 0x04;
const SOCKS5_REPLY_SUCCEEDED: u8 = 0x00;
const SOCKS5_REPLY_COMMAND_UNSUPPORTED: u8 = 0x07;

/// SOCKS5 client hello parsed state
enum Socks5ClientHello {
    Incomplete,
    Invalid,
    Ok
}

fn parse_client_hello(buffer: &[u8]) -> Socks5ClientHello {
    if buffer.len() < 2 {
        return Socks5ClientHello::Incomplete;
    }
    let methods = buffer[1] as usize;
    let length = 2 + methods;
    if buffer.len() < length {
        return Socks5ClientHello::Incomplete;
    }
    if buffer.len() > length
        || buffer[0] != SOCKS5_VERSION
        || methods == 0
        || !buffer[2..].contains(&SOCKS5_METHOD_NO_AUTH) {
        return Socks5ClientHello::Invalid;
    }
    Socks5ClientHello::Ok
}

/// Socks5 server hello parsed state
enum Socks5ServerHello {
    Incomplete,
    Invalid,
    Ok
}

fn parse_server_hello(buffer: &[u8]) -> Socks5ServerHello {
    if buffer.len() < 2 {
        return Socks5ServerHello::Incomplete;
    }
    if buffer.len() != 2 || buffer[0] != SOCKS5_VERSION || buffer[1] != SOCKS5_METHOD_NO_AUTH {
        return Socks5ServerHello::Invalid;
    }
    Socks5ServerHello::Ok
}

/// SOCKS5 request parsed state
enum Socks5Request {
    Incomplete,
    Invalid,
    Unsupported,
    Connect(Host, u16)
}

fn parse_request(buffer: &[u8]) -> Socks5Request {
    if buffer.len() < 4 {
        return Socks5Request::Incomplete;
    }
    if buffer[0] != SOCKS5_VERSION
        || buffer[2] != 0x00
        || !matches!(buffer[3], SOCKS5_ADDRESS_IPV4 | SOCKS5_ADDRESS_DOMAIN | SOCKS5_ADDRESS_IPV6) {
        return Socks5Request::Invalid;
    }
    let length = match buffer[3] {
        SOCKS5_ADDRESS_IPV4 => 10,
        SOCKS5_ADDRESS_IPV6 => 22,
        SOCKS5_ADDRESS_DOMAIN => match buffer.get(4) {
            Some(length) => 7 + *length as usize,
            None => return Socks5Request::Incomplete
        },
        _ => return Socks5Request::Invalid
    };
    if buffer.len() < length {
        return Socks5Request::Incomplete;
    }
    if buffer.len() > length || !matches!(buffer[1], 0x01..=0x03) {
        return Socks5Request::Invalid;
    }
    if buffer[1] != SOCKS5_COMMAND_CONNECT {
        return Socks5Request::Unsupported;
    }
    let host = match buffer[3] {
        SOCKS5_ADDRESS_IPV4 => {
            let mut octets = [0u8; 4];
            octets.copy_from_slice(&buffer[4..8]);
            Host::IpAddr(IpAddr::V4(Ipv4Addr::from(octets)))
        },
        SOCKS5_ADDRESS_IPV6 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&buffer[4..20]);
            Host::IpAddr(IpAddr::V6(Ipv6Addr::from(octets)))
        },
        SOCKS5_ADDRESS_DOMAIN => match std::str::from_utf8(&buffer[5..length - 2]) {
            Ok(domain) => Host::Domain(domain.to_string()),
            Err(_) => return Socks5Request::Invalid
        },
        _ => unreachable!("valid rlength with invalid field for calculating rlength")
    };
    let port = u16::from_be_bytes([buffer[length - 2], buffer[length - 1]]);
    Socks5Request::Connect(host, port)
}

/// SOCKS5 reply parsed state
enum Socks5Reply {
    Incomplete,
    Invalid,
    Ok
}

fn parse_reply(buffer: &[u8]) -> Socks5Reply {
    if buffer.len() < 4 {
        return Socks5Reply::Incomplete;
    }
    let length = match buffer[3] {
        SOCKS5_ADDRESS_IPV4 => 10,
        SOCKS5_ADDRESS_IPV6 => 22,
        SOCKS5_ADDRESS_DOMAIN => match buffer.get(4) {
            Some(length) => 7 + *length as usize,
            None => return Socks5Reply::Incomplete
        },
        _ => return Socks5Reply::Invalid
    };
    if buffer.len() < length {
        return Socks5Reply::Incomplete;
    }
    if buffer.len() > length
        || buffer[0] != SOCKS5_VERSION
        || buffer[1] != SOCKS5_REPLY_SUCCEEDED
        || buffer[2] != 0x00 {
        return Socks5Reply::Invalid;
    }
    Socks5Reply::Ok
}

fn build_request(host: Host, port: u16) -> Box<[u8]> {
    let mut request = vec![SOCKS5_VERSION, SOCKS5_COMMAND_CONNECT, 0x00];
    match host {
        Host::IpAddr(IpAddr::V4(ip_addr)) => {
            request.push(SOCKS5_ADDRESS_IPV4);
            request.extend_from_slice(&ip_addr.octets());
        },
        Host::IpAddr(IpAddr::V6(ip_addr)) => {
            request.push(SOCKS5_ADDRESS_IPV6);
            request.extend_from_slice(&ip_addr.octets());
        },
        Host::Domain(domain) => {
            let bytes = domain.as_bytes();
            let length = bytes.len().min(u8::MAX as usize);
            request.push(SOCKS5_ADDRESS_DOMAIN);
            request.push(length as u8);
            request.extend_from_slice(&bytes[..length]);
        }
    }
    request.extend_from_slice(&port.to_be_bytes());
    request.into_boxed_slice()
}

/// Dispatch table from a connection to the handler's inbound channel.
#[derive(Default)]
#[allow(clippy::mutable_key_type)]
struct Router {
    upstream: HashMap<ConnectionToken, Sender<DownwardPacket>>,
    downstream: HashMap<ConnectionToken, Sender<UpwardPacket>>
}

/// Phone book of all senders ever existed
/// 
/// (Born of `clippy::too_many_arguments`)
struct Relay {
    upstream_sender: Sender<UpwardPacket>,
    downstream_sender: Sender<DownwardPacket>,
    router: Arc<MutexStd<Router>>
}

/// Relays same-direction packets of `receiver` into `target` through `sender`.
async fn forward_handler<D: Direction>(
    receiver: &mut Receiver<D::ForwardPacket>,
    target: &ConnectionToken,
    sender: &Sender<D::ForwardPacket>,
    queue: Vec<Box<[u8]>>
) -> Result<(), GraphError> {
    for data in queue {
        sender.send(D::ForwardPacket::new_data(target.clone(), data).await).await?;
    }
    loop {
        let Some(packet) = receiver.recv().await else {
            return Ok(());
        };
        let detached: DetachedPacket = packet.into();
        match detached {
            DetachedPacket::Data(attached) => {
                sender.send(D::ForwardPacket::new_data(target.clone(), attached.data).await).await?;
            },
            DetachedPacket::FIN(_) => {
                sender.send(D::ForwardPacket::new_fin(target.clone())).await?;
                return Ok(());
            },
            DetachedPacket::SYN(_) => return Ok(())
        }
    }
}

/// SOCKS5 server node. Only supports `CONNECT`; Does not support authentication.
/// 
/// - Accepts one upstream SOCKS5 client request.
/// - Sends the proxied session to one downstream.
/// 
/// The host of an inbound SOCKS5 request is faithfully translated into the
/// session host without bothering DNS.
#[derive(Debug)]
pub struct SOCKS5ServerNode {
    transport: NodeUpstreamEndToken,
    session: NodeDownstreamEndToken,
    signal_receiver: Receiver<Signal>
}

impl SOCKS5ServerNode {
    #[allow(clippy::new_ret_no_self)]
    pub fn new() -> NodeToken {
        let (signal_sender, signal_receiver) = channel(SIGNAL_BUFFER_SIZE);
        let transport = NodeUpstreamEndToken::new();
        let session = NodeDownstreamEndToken::new();
        NodeToken::new(
            Box::new(Self {
                transport: transport.clone(),
                session: session.clone(),
                signal_receiver
            }),
            signal_sender,
            NodeUpstreamInterface::new(vec![transport]),
            NodeDownstreamInterface::new(vec![session])
        )
    }
}

/// SOCKS5 client node. Only supports `CONNECT`; Does not support authentication.
/// 
/// - Reads the proxied session from one upstream.
/// - Initiates the SOCKS5 connection with the remote server through one downstream.
#[derive(Debug)]
pub struct SOCKS5ClientNode {
    session: NodeUpstreamEndToken,
    transport: NodeDownstreamEndToken,
    signal_receiver: Receiver<Signal>,
    server: (Host, u16)
}

impl SOCKS5ClientNode {
    #[allow(clippy::new_ret_no_self)]
    pub fn new(server: Host, port: u16) -> Result<NodeToken, &'static str> {
        let (signal_sender, signal_receiver) = channel(SIGNAL_BUFFER_SIZE);
        let session = NodeUpstreamEndToken::new();
        let transport = NodeDownstreamEndToken::new();
        Ok(NodeToken::new(
            Box::new(Self {
                session: session.clone(),
                transport: transport.clone(),
                signal_receiver,
                server: (server, port)
            }),
            signal_sender,
            NodeUpstreamInterface::new(vec![session]),
            NodeDownstreamInterface::new(vec![transport])
        ))
    }
}

#[pyfunction]
#[pyo3(name = "SOCKS5Node", signature = (server=None))]
pub(crate) fn socks5_node(server: Option<(Host, u16)>) -> PyResult<NodeToken> {
    match server {
        None => Ok(SOCKS5ServerNode::new()),
        Some((host, port)) => SOCKS5ClientNode::new(host, port).map_err(PyValueError::new_err)
    }
}

#[async_trait]
impl Node for SOCKS5ServerNode {
    #[tracing::instrument(name="SOCKS5ServerNode::run", skip_all)]
    async fn run(&mut self) -> Result<Option<Signal>, GraphError> {
        let upstream_sender = self.transport.sender().map_err(GraphError::from)?;
        let upstream_receiver = self.transport.receiver().map_err(GraphError::from)?;
        let downstream_sender = self.session.sender().map_err(GraphError::from)?;
        let downstream_receiver = self.session.receiver().map_err(GraphError::from)?;
        socks5_run(upstream_sender, upstream_receiver, downstream_sender, downstream_receiver, &mut self.signal_receiver, None).await
    }
}

#[async_trait]
impl Node for SOCKS5ClientNode {
    #[tracing::instrument(name="SOCKS5ClientNode::run", skip_all)]
    async fn run(&mut self) -> Result<Option<Signal>, GraphError> {
        let upstream_sender = self.session.sender().map_err(GraphError::from)?;
        let upstream_receiver = self.session.receiver().map_err(GraphError::from)?;
        let downstream_sender = self.transport.sender().map_err(GraphError::from)?;
        let downstream_receiver = self.transport.receiver().map_err(GraphError::from)?;
        socks5_run(upstream_sender, upstream_receiver, downstream_sender, downstream_receiver, &mut self.signal_receiver, Some(&self.server)).await
    }
}

/// Shared runtime for both SOCKS5 server and client.
/// 
/// `server` is `None` for the server node and `Some(address)` for the client node.
#[allow(clippy::mutable_key_type)]
#[tracing::instrument(name="socks5_run", skip_all)]
async fn socks5_run(
    upstream_sender: Sender<UpwardPacket>,
    mut upstream_receiver: OwnedMutexGuard<Receiver<DownwardPacket>>,
    downstream_sender: Sender<DownwardPacket>,
    mut downstream_receiver: OwnedMutexGuard<Receiver<UpwardPacket>>,
    signal_receiver: &mut Receiver<Signal>,
    server: Option<&(Host, u16)>
) -> Result<Option<Signal>, GraphError> {
    signal_receiver.clear();
    let router: Arc<MutexStd<Router>> = Arc::new(MutexStd::new(Router::default()));
    let mut handlers: JoinSet<Option<Signal>> = JoinSet::new(); // This cancels on drop
    loop {
        tokio::select! {
            biased;
            signal = signal_receiver.recv() => match signal {
                Some(Signal::SIGTERM) => return Ok(None),
                None => {
                    tracing::error!("Signal receiver is closed");
                    return Err(GraphError::Disconnected)
                },
                Some(signal) => {
                    tracing::warn!("Received unknown signal {:?}", signal);
                    continue
                }
            },
            handler = handlers.join_next(), if !handlers.is_empty() => match handler {
                None => unreachable!("Awaiting non-empty join set that is empty"),
                Some(Err(error)) => {
                    tracing::warn!("SOCKS5 handler task failed: {error}");
                    continue;
                }
                Some(Ok(signal)) => {
                    if let Some(signal) = signal {
                        tracing::warn!("SOCKS5 handler returned signal {:?}, propagating", signal);
                        return Ok(Some(signal));
                    }
                    continue;
                }
            },
            packet = upstream_receiver.recv() => match packet {
                Some(packet) if packet.is_syn() => {
                    let connection = packet.connection().clone();
                    let (upstream_dispatch, upstream_handler) = channel(CONNECTION_BUFFER_SIZE);
                    let (downstream_dispatch, downstream_handler) = channel(CONNECTION_BUFFER_SIZE);
                    router.lock().expect("Router is poisoned").upstream.insert(connection.clone(), upstream_dispatch);
                    let relay = Relay {
                        upstream_sender: upstream_sender.clone(),
                        downstream_sender: downstream_sender.clone(),
                        router: router.clone()
                    };
                    match server {
                        None => handlers.spawn(server_handler(connection, upstream_handler, downstream_handler, downstream_dispatch, relay)),
                        Some(server) => handlers.spawn(client_handler(connection, upstream_handler, downstream_handler, downstream_dispatch, server.clone(), relay))
                    };
                },
                Some(packet) => {
                    let sender = router.lock().expect("Router is poisoned").upstream.get(packet.connection()).cloned();
                    match sender {
                        Some(sender) => { let _ = sender.send(packet).await; }, // Guaranteed to success, given that packets after FIN does not matter
                        None if !packet.is_fin() => {
                            tracing::debug!("Received packet that does not belong");
                            upstream_sender.send(UpwardPacket::FIN(packet.connection().clone())).await?;
                        },
                        None => continue
                    }
                },
                None => return Ok(None)
            },
            packet = downstream_receiver.recv() => match packet {
                Some(packet) if packet.is_syn() => {
                    downstream_sender.send(DownwardPacket::FIN(packet.connection().clone())).await?;
                },
                Some(packet) => {
                    let sender = router.lock().expect("Router is poisoned").downstream.get(packet.connection()).cloned();
                    match sender {
                        Some(sender) => { let _ = sender.send(packet).await; },
                        None if !packet.is_fin() => downstream_sender.send(DownwardPacket::FIN(packet.connection().clone())).await?,
                        None => continue
                    }
                },
                None => return Ok(None)
            }
        }
    }
}

/// SOCKS5 server handler wrapper
async fn server_handler(
    transport: ConnectionToken,
    transport_receiver: Receiver<DownwardPacket>,
    session_receiver: Receiver<UpwardPacket>,
    session_sender: Sender<UpwardPacket>,
    relay: Relay
) -> Option<Signal> {
    let mut session = None;
    let signal = server_session(
        transport.clone(),
        &mut session,
        transport_receiver,
        session_receiver,
        session_sender,
        &relay
    ).await;
    let mut guard = relay.router.lock().expect("Router is poisoned");
    guard.upstream.remove(&transport);
    if let Some(session) = &session {
        guard.downstream.remove(session);
    }
    signal
}

/// Actual server handler
async fn server_session(
    transport: ConnectionToken,
    session_out: &mut Option<ConnectionToken>,
    mut transport_receiver: Receiver<DownwardPacket>,
    mut session_receiver: Receiver<UpwardPacket>,
    session_sender: Sender<UpwardPacket>,
    relay: &Relay
) -> Option<Signal> {
    tracing::debug!("Accepted new connection from client");
    let mut buffer = Vec::new();
    let mut established = false;
    let session = loop {
        let packet = transport_receiver.recv().await?;
        let detached: DetachedPacket = packet.into();
        let DetachedPacket::Data(attached) = detached else {
            return None;
        };
        buffer.extend_from_slice(&attached.data);
        if !established {
            match parse_client_hello(&buffer) {
                Socks5ClientHello::Incomplete => continue,
                Socks5ClientHello::Invalid => {
                    tracing::debug!("Invalid SOCKS5 client hello");
                    if relay.upstream_sender.send(UpwardPacket::new_fin(transport.clone())).await.is_err() {
                        return Some(Signal::SIGTERM);
                    }
                    return None;
                },
                Socks5ClientHello::Ok => {
                    buffer.clear();
                    established = true;
                    let reply = Box::from([SOCKS5_VERSION, SOCKS5_METHOD_NO_AUTH]);
                    if relay.upstream_sender.send(UpwardPacket::new_data(transport.clone(), reply).await).await.is_err() {
                        return Some(Signal::SIGTERM);
                    }
                    continue;
                }
            }
        }
        match parse_request(&buffer) {
            Socks5Request::Incomplete => continue,
            Socks5Request::Invalid => {
                tracing::debug!("Invalid SOCKS5 request");
                if relay.upstream_sender.send(UpwardPacket::new_fin(transport)).await.is_err() {
                    return Some(Signal::SIGTERM);
                }
                return None;
            },
            Socks5Request::Unsupported => {
                tracing::debug!("Unsupported SOCKS5 request");
                let reply = Box::from([SOCKS5_VERSION, SOCKS5_REPLY_COMMAND_UNSUPPORTED, 0x00, SOCKS5_ADDRESS_IPV4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                if relay.upstream_sender.send(UpwardPacket::new_data(transport.clone(), reply).await).await.is_err() {
                    return Some(Signal::SIGTERM);
                }
                if relay.upstream_sender.send(UpwardPacket::new_fin(transport)).await.is_err() {
                    return Some(Signal::SIGTERM);
                }
                return None;
            },
            Socks5Request::Connect(host, port) => {
                let session = ConnectionToken::new(host, Transport::TCP, port);
                relay.router.lock().expect("Router is poisoned").downstream.insert(session.clone(), session_sender);
                *session_out = Some(session.clone());
                if relay.downstream_sender.send(DownwardPacket::new_syn(session.clone())).await.is_err() {
                    return Some(Signal::SIGTERM);
                }
                let reply = Box::from([SOCKS5_VERSION, SOCKS5_REPLY_SUCCEEDED, 0x00, SOCKS5_ADDRESS_IPV4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                if relay.upstream_sender.send(UpwardPacket::new_data(transport.clone(), reply).await).await.is_err() {
                    return Some(Signal::SIGTERM);
                }
                break session;
            }
        }
    };
    tracing::debug!("Established SOCKS5 connection");
    match tokio::select! {
        result = forward_handler::<Downward>(&mut transport_receiver, &session, &relay.downstream_sender, Vec::new()) => result,
        result = forward_handler::<Upward>(&mut session_receiver, &transport, &relay.upstream_sender, Vec::new()) => result
    } {
        Ok(()) => {
            tracing::debug!("SOCKS5 connection closed");
            None
        },
        Err(error) => {
            tracing::error!("SOCKS5 session downwarding failed: {error}");
            Some(Signal::SIGTERM)
        }
    }
}

/// SOCKS5 client handler wrapper
async fn client_handler(
    session: ConnectionToken,
    session_receiver: Receiver<DownwardPacket>,
    transport_receiver: Receiver<UpwardPacket>,
    transport_sender: Sender<UpwardPacket>,
    server: (Host, u16),
    relay: Relay
) -> Option<Signal> {
    let mut transport_out = None;
    let signal = client_session(
        session.clone(),
        &mut transport_out,
        session_receiver,
        transport_receiver,
        transport_sender,
        server,
        &relay
    ).await;
    let mut guard = relay.router.lock().expect("Router is poisoned");
    guard.upstream.remove(&session);
    if let Some(transport) = &transport_out {
        guard.downstream.remove(transport);
    }
    signal
}

/// Actual client handler
async fn client_session(
    session: ConnectionToken,
    transport_out: &mut Option<ConnectionToken>,
    mut session_receiver: Receiver<DownwardPacket>,
    mut transport_receiver: Receiver<UpwardPacket>,
    transport_sender: Sender<UpwardPacket>,
    server: (Host, u16),
    relay: &Relay
) -> Option<Signal> {
    tracing::debug!("SOCKS5 client connection reached server");
    let transport = ConnectionToken::new(server.0, Transport::TCP, server.1);
    relay.router.lock().expect("Router is poisoned").downstream.insert(transport.clone(), transport_sender);
    *transport_out = Some(transport.clone());
    if relay.downstream_sender.send(DownwardPacket::new_syn(transport.clone())).await.is_err() {
        return Some(Signal::SIGTERM);
    }
    let greeting = Box::from([SOCKS5_VERSION, 0x01, SOCKS5_METHOD_NO_AUTH]);
    if relay.downstream_sender.send(DownwardPacket::new_data(transport.clone(), greeting).await).await.is_err() {
        return Some(Signal::SIGTERM);
    }
    let mut buffer = Vec::new();
    let mut queue: Vec<Box<[u8]>> = Vec::new();
    let mut established = false;
    loop {
        tokio::select! {
            biased;
            packet = transport_receiver.recv() => match packet {
                Some(packet) => {
                    let detached: DetachedPacket = packet.into();
                    match detached {
                        DetachedPacket::Data(attached) => {
                            buffer.extend_from_slice(&attached.data);
                            if !established {
                                match parse_server_hello(&buffer) {
                                    Socks5ServerHello::Incomplete => continue,
                                    Socks5ServerHello::Invalid => {
                                        tracing::debug!("Invalid SOCKS5 server hello");
                                        if relay.upstream_sender.send(UpwardPacket::new_fin(session)).await.is_err() {
                                            return Some(Signal::SIGTERM);
                                        }
                                        if relay.downstream_sender.send(DownwardPacket::new_fin(transport.clone())).await.is_err() {
                                            return Some(Signal::SIGTERM);
                                        }
                                        return None;
                                    },
                                    Socks5ServerHello::Ok => {
                                        buffer.clear();
                                        established = true;
                                        let request = build_request(session.host(), session.port());
                                        if relay.downstream_sender.send(DownwardPacket::new_data(transport.clone(), request).await).await.is_err() {
                                            return Some(Signal::SIGTERM);
                                        }
                                        continue;
                                    }
                                }
                            }
                            match parse_reply(&buffer) {
                                Socks5Reply::Incomplete => continue,
                                Socks5Reply::Invalid => {
                                    tracing::debug!("Invalid SOCKS5 reply");
                                    if relay.upstream_sender.send(UpwardPacket::new_fin(session)).await.is_err() {
                                        return Some(Signal::SIGTERM);
                                    }
                                    if relay.downstream_sender.send(DownwardPacket::new_fin(transport)).await.is_err() {
                                        return Some(Signal::SIGTERM);
                                    }
                                    return None;
                                },
                                Socks5Reply::Ok => break
                            }
                        },
                        DetachedPacket::FIN(_) => {
                            let _ = relay.upstream_sender.send(UpwardPacket::new_fin(session)).await;
                            return None;
                        },
                        DetachedPacket::SYN(_) => {
                            let _ = relay.downstream_sender.send(DownwardPacket::new_fin(transport)).await;
                            return None;
                        }
                    }
                },
                None => {
                    let _ = relay.upstream_sender.send(UpwardPacket::new_fin(session)).await;
                    return None;
                }
            },
            packet = session_receiver.recv() => match packet {
                Some(packet) => {
                    let detached: DetachedPacket = packet.into();
                    match detached {
                        DetachedPacket::Data(attached) => queue.push(attached.data),
                        _ => {
                            let _ = relay.downstream_sender.send(DownwardPacket::new_fin(transport)).await;
                            return None;
                        }
                    }
                },
                None => {
                    let _ = relay.downstream_sender.send(DownwardPacket::new_fin(transport)).await;
                    return None;
                }
            }
        }
    }
    tracing::debug!("Established SOCKS5 connection with server");
    match tokio::select! {
        result = forward_handler::<Upward>(&mut transport_receiver, &session, &relay.upstream_sender, Vec::new()) => result,
        result = forward_handler::<Downward>(&mut session_receiver, &transport, &relay.downstream_sender, queue) => result
    } {
        Ok(()) => {
            tracing::debug!("SOCKS5 connection with server closed");
            None
        },
        Err(error) => {
            tracing::error!("SOCKS5 session downwarding failed: {error}");
            Some(Signal::SIGTERM)
        }
    }
}
