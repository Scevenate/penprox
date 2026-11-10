#![allow(clippy::all)]

#[pyo3::pymodule(submodule)]
pub mod socks5 {
    use crate::_sdk::sdk::*;
    use std::{collections::HashMap, net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr}, sync::{Arc, Mutex as MutexStd}};
    use async_trait::async_trait;
    use pyo3::{exceptions::PyValueError, prelude::*, pyclass, pymethods};
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

    /// All established connections of the server.
    #[derive(Default)]
    #[allow(clippy::mutable_key_type)]
    struct Router {
        transport: HashMap<ConnectionToken, Sender<Packet>>,
        session: HashMap<ConnectionToken, Sender<Packet>>
    }

    /// Phone book of all senders ever existed
    /// 
    /// (Born of `clippy::too_many_arguments`)
    struct Relay {
        upstream_sender: Sender<Packet>,
        downstream_sender: Sender<Packet>,
        router: Arc<MutexStd<Router>>
    }

    /// Relays detached packets of `receiver` into `target` through `sender`.
    async fn forward_handler(
        receiver: &mut Receiver<Packet>,
        target: &ConnectionToken,
        sender: &Sender<Packet>,
        queue: Vec<Box<[u8]>>
    ) -> Result<(), GraphError> {
        for data in queue {
            sender.send(Packet::Data(target.attach(data).await)).await.map_err(|error| { tracing::error!("End closed: {error}"); GraphError::Disconnected })?;
        }
        loop {
            match receiver.recv().await {
                Some(Packet::Data(attached)) => {
                    let data = attached.detach().data;
                    sender.send(Packet::Data(target.attach(data).await)).await.map_err(|error| { tracing::error!("End closed: {error}"); GraphError::Disconnected })?;
                },
                Some(Packet::FIN(_)) => {
                    sender.send(Packet::FIN(target.clone())).await.map_err(|error| { tracing::error!("End closed: {error}"); GraphError::Disconnected })?;
                    return Ok(());
                },
                Some(Packet::SYN(_)) | None => return Ok(())
            }
        }
    }

    /// SOCKS5 node. Only supports `CONNECT`; Does not support authentication.
    /// 
    /// When constructed without a server address, the node is a SOCKS5 server:
    /// - Accepts one upstream SOCKS5 client requests.
    /// - Sends proxied session to one downstream.
    /// 
    /// When constructed with a SOCKS5 server address, the node is a SOCKS5 client:
    /// - Reads proxied session from one upstream.
    /// - Initiates SOCKS5 connection with remote server through one downstream.
    /// 
    /// The host of an inbound SOCKS5 request is faithfully translated into the
    /// session host without bothering DNS.
    #[pyclass]
    #[derive(Debug)]
    pub struct SOCKS5Node {
        transport: NodeEndToken,
        session: NodeEndToken,
        signal_receiver: Receiver<Signal>,
        server: Option<SocketAddr>
    }

    impl SOCKS5Node {
        #[allow(clippy::new_ret_no_self)]
        pub fn new(server: Option<(Host, u16)>) -> Result<NodeToken, &'static str> {
            let server = match server.map(|mut server| (server.0.wait_resolve(), server.1)) {
                Some((Some(ip), port)) => Some(SocketAddr::new(ip, port)),
                None => None,
                _ => {
                    tracing::error!("Server is unreachable");
                    return Err("Server is unreachable");
                }
            };
            let (signal_sender, signal_receiver) = channel(SIGNAL_BUFFER_SIZE);
            let transport = NodeEndToken::new();
            let session = NodeEndToken::new();
            let socks5_node = Self {
                transport: transport.clone(),
                session: session.clone(),
                signal_receiver,
                server
            };
            if server.is_some() {
                return Ok(NodeToken::new(
                    Box::new(socks5_node),
                    signal_sender,
                    NodeInterface::new(vec![session]),
                    NodeInterface::new(vec![transport])
                ))
            } else {
                return Ok(NodeToken::new(
                    Box::new(socks5_node),
                    signal_sender,
                    NodeInterface::new(vec![transport]),
                    NodeInterface::new(vec![session])
                ))
            }
        }
    }

    #[pymethods]
    impl SOCKS5Node {
        #[new]
        #[pyo3(signature = (server = None))]
        #[allow(clippy::new_ret_no_self)]
        fn python_new(server: Option<(Host, u16)>) -> PyResult<NodeToken> {
            Self::new(server).map_err(PyValueError::new_err)
        }
    }

    #[async_trait]
    impl Node for SOCKS5Node {
        #[tracing::instrument(name="SOCKS5Node::run", skip_all)]
        async fn run(&mut self) -> Result<Option<Signal>, GraphError> {
            self.signal_receiver.drain();
            match self.server {
                None => {
                    let upstream_sender = self.transport.sender().map_err(GraphError::from)?;
                    let upstream_receiver = self.transport.receiver().map_err(GraphError::from)?;
                    let downstream_sender = self.session.sender().map_err(GraphError::from)?;
                    let downstream_receiver = self.session.receiver().map_err(GraphError::from)?;
                    self.run_server(upstream_sender, upstream_receiver, downstream_sender, downstream_receiver).await
                },
                Some(server) => {
                    let upstream_sender = self.session.sender().map_err(GraphError::from)?;
                    let upstream_receiver = self.session.receiver().map_err(GraphError::from)?;
                    let downstream_sender = self.transport.sender().map_err(GraphError::from)?;
                    let downstream_receiver = self.transport.receiver().map_err(GraphError::from)?;
                    self.run_client(upstream_sender, upstream_receiver, downstream_sender, downstream_receiver, server).await
                }
            }
        }
    }

    impl SOCKS5Node {
        #[allow(clippy::mutable_key_type)]
        #[tracing::instrument(name="SOCKS5Node::run_server", skip_all)]
        async fn run_server(
            &mut self,
            upstream_sender: Sender<Packet>, // SOCKS5 raw
            mut upstream_receiver: OwnedMutexGuard<Receiver<Packet>>,
            downstream_sender: Sender<Packet>, // Proxied data
            mut downstream_receiver: OwnedMutexGuard<Receiver<Packet>>
        ) -> Result<Option<Signal>, GraphError> {
            let router: Arc<MutexStd<Router>> = Arc::new(MutexStd::new(Router::default()));
            let mut handlers: JoinSet<Option<Signal>> = JoinSet::new(); // This cancels on drop
            loop {
                tokio::select! {
                    biased;
                    signal = self.signal_receiver.recv() => match signal {
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
                        Some(Packet::SYN(transport)) => {
                            let (transport_sender, transport_receiver) = channel(CONNECTION_BUFFER_SIZE);
                            let (session_sender, session_receiver) = channel(CONNECTION_BUFFER_SIZE);
                            router.lock().expect("Router is poisoned").transport.insert(transport.clone(), transport_sender);
                            handlers.spawn(server_handler(
                                transport,
                                transport_receiver,
                                session_receiver,
                                session_sender,
                                Relay {
                                    upstream_sender: upstream_sender.clone(),
                                    downstream_sender: downstream_sender.clone(),
                                    router: router.clone()
                                }
                            ));
                        },
                        Some(packet) => {
                            let sender = router.lock().expect("Router is poisoned").transport.get(packet.connection()).cloned();
                            match sender {
                                Some(sender) => { let _ = sender.send(packet).await; }, // Guaranteed to success, given that packets after FIN does not matter
                                None if !packet.is_fin() => {
                                    tracing::debug!("Received packet that does not belong");
                                    if upstream_sender.send(Packet::FIN(packet.connection().clone())).await.is_err() {
                                        tracing::error!("End closed");
                                        return Err(GraphError::Disconnected);
                                    }
                                },
                                None => continue
                            }
                        },
                        None => return Ok(None)
                    },
                    packet = downstream_receiver.recv() => match packet {
                        Some(Packet::SYN(session)) => {
                            if downstream_sender.send(Packet::FIN(session)).await.is_err() {
                                tracing::error!("End closed");
                                return Err(GraphError::Disconnected);
                            }
                        },
                        Some(packet) => {
                            let sender = router.lock().expect("Router is poisoned").session.get(packet.connection()).cloned();
                            match sender {
                                Some(sender) => { let _ = sender.send(packet).await; },
                                None if !packet.is_fin() => if downstream_sender.send(Packet::FIN(packet.connection().clone())).await.is_err() {
                                    tracing::error!("End closed");
                                    return Err(GraphError::Disconnected);
                                },
                                None => continue
                            }
                        },
                        None => return Ok(None)
                    }
                }
            }
        }

        #[allow(clippy::mutable_key_type)]
        #[tracing::instrument(name="SOCKS5Node::run_client", skip_all)]
        async fn run_client(
            &mut self,
            upstream_sender: Sender<Packet>, // Proxied data
            mut upstream_receiver: OwnedMutexGuard<Receiver<Packet>>,
            downstream_sender: Sender<Packet>, // SOCKS5 raw
            mut downstream_receiver: OwnedMutexGuard<Receiver<Packet>>,
            server: SocketAddr
        ) -> Result<Option<Signal>, GraphError> {
            let router: Arc<MutexStd<Router>> = Arc::new(MutexStd::new(Router::default()));
            let mut handlers: JoinSet<Option<Signal>> = JoinSet::new();
            loop {
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
                    handler = handlers.join_next(), if !handlers.is_empty() => match handler {
                        None => unreachable!("Awaiting non-empty join set that is empty"),
                        Some(Err(error)) => {
                            tracing::warn!("SOCKS5 handler task failed: {error}");
                            continue;
                        }
                        Some(Ok(signal)) => {
                            if let Some(signal) = signal {
                                return Ok(Some(signal));
                            }
                            continue;
                        }
                    },
                    packet = upstream_receiver.recv() => match packet {
                        Some(Packet::SYN(session)) => {
                            let (session_sender, session_receiver) = channel(CONNECTION_BUFFER_SIZE);
                            let (transport_sender, transport_receiver) = channel(CONNECTION_BUFFER_SIZE);
                            router.lock().expect("Router is poisoned").session.insert(session.clone(), session_sender);
                            handlers.spawn(client_handler(
                                session,
                                session_receiver,
                                transport_receiver,
                                transport_sender,
                                server,
                                Relay {
                                    upstream_sender: upstream_sender.clone(),
                                    downstream_sender: downstream_sender.clone(),
                                    router: router.clone()
                                }
                            ));
                        },
                        Some(packet) => {
                            let sender = router.lock().expect("Router is poisoned").session.get(packet.connection()).cloned();
                            match sender {
                                Some(sender) => { let _ = sender.send(packet).await; },
                                None if !packet.is_fin() => if upstream_sender.send(Packet::FIN(packet.connection().clone())).await.is_err() {
                                    tracing::error!("End closed");
                                    return Err(GraphError::Disconnected);
                                },
                                None => continue
                            }
                        },
                        None => return Ok(None)
                    },
                    packet = downstream_receiver.recv() => match packet {
                        Some(Packet::SYN(transport)) => {
                            if downstream_sender.send(Packet::FIN(transport)).await.is_err() {
                                tracing::error!("End closed");
                                return Err(GraphError::Disconnected);
                            }
                        },
                        Some(packet) => {
                            let sender = router.lock().expect("Router is poisoned").transport.get(packet.connection()).cloned();
                            match sender {
                                Some(sender) => { let _ = sender.send(packet).await; },
                                None if !packet.is_fin() => if downstream_sender.send(Packet::FIN(packet.connection().clone())).await.is_err() {
                                    tracing::error!("End closed");
                                    return Err(GraphError::Disconnected);
                                },
                                None => continue
                            }
                        },
                        None => return Ok(None)
                    }
                }
            }
        }
    }

    /// SOCKS5 server handler wrapper
    async fn server_handler(
        transport: ConnectionToken,
        transport_receiver: Receiver<Packet>,
        session_receiver: Receiver<Packet>,
        session_sender: Sender<Packet>,
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
        guard.transport.remove(&transport);
        if let Some(session) = &session {
            guard.session.remove(session);
        }
        signal
    }

    /// Actual server handler
    async fn server_session(
        transport: ConnectionToken,
        session_out: &mut Option<ConnectionToken>,
        mut transport_receiver: Receiver<Packet>,
        mut session_receiver: Receiver<Packet>,
        session_sender: Sender<Packet>,
        relay: &Relay
    ) -> Option<Signal> {
        tracing::debug!("Accepted new connection from client");
        let mut buffer = Vec::new();
        let mut established = false;
        let session = loop {
            let Some(Packet::Data(attached)) = transport_receiver.recv().await else {
                return None;
            };
            buffer.extend_from_slice(&attached.data);
            drop(attached);
            if !established {
                match parse_client_hello(&buffer) {
                    Socks5ClientHello::Incomplete => continue,
                    Socks5ClientHello::Invalid => {
                        tracing::debug!("Invalid SOCKS5 client hello");
                        if relay.upstream_sender.send(Packet::FIN(transport.clone())).await.is_err() {
                            return Some(Signal::SIGTERM);
                        }
                        return None;
                    },
                    Socks5ClientHello::Ok => {
                        buffer.clear();
                        established = true;
                        let reply = Box::from([SOCKS5_VERSION, SOCKS5_METHOD_NO_AUTH]);
                        if relay.upstream_sender.send(Packet::Data(transport.attach(reply).await)).await.is_err() {
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
                    if relay.upstream_sender.send(Packet::FIN(transport.clone())).await.is_err() {
                        return Some(Signal::SIGTERM);
                    }
                    return None;
                },
                Socks5Request::Unsupported => {
                    tracing::debug!("Unsupported SOCKS5 request");
                    let reply = Box::from([SOCKS5_VERSION, SOCKS5_REPLY_COMMAND_UNSUPPORTED, 0x00, SOCKS5_ADDRESS_IPV4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                    if relay.upstream_sender.send(Packet::Data(transport.attach(reply).await)).await.is_err() {
                        return Some(Signal::SIGTERM);
                    }
                    if relay.upstream_sender.send(Packet::FIN(transport.clone())).await.is_err() {
                        return Some(Signal::SIGTERM);
                    }
                    return None;
                },
                Socks5Request::Connect(host, port) => {
                    let session = ConnectionToken::new(host, Transport::TCP, port);
                    relay.router.lock().expect("Router is poisoned").session.insert(session.clone(), session_sender);
                    *session_out = Some(session.clone());
                    if relay.downstream_sender.send(Packet::SYN(session.clone())).await.is_err() {
                        return Some(Signal::SIGTERM);
                    }
                    let reply = Box::from([SOCKS5_VERSION, SOCKS5_REPLY_SUCCEEDED, 0x00, SOCKS5_ADDRESS_IPV4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                    if relay.upstream_sender.send(Packet::Data(transport.attach(reply).await)).await.is_err() {
                        return Some(Signal::SIGTERM);
                    }
                    break session;
                }
            }
        };
        tracing::debug!("Established SOCKS5 connection");
        match tokio::select! {
            result = forward_handler(&mut transport_receiver, &session, &relay.downstream_sender, Vec::new()) => result,
            result = forward_handler(&mut session_receiver, &transport, &relay.upstream_sender, Vec::new()) => result
        } {
            Ok(()) => {
                tracing::debug!("SOCKS5 connection closed");
                None
            },
            Err(error) => {
                tracing::error!("SOCKS5 session forwarding failed: {error}");
                Some(Signal::SIGTERM)
            }
        }
    }

    /// SOCKS5 client handler wrapper
    async fn client_handler(
        session: ConnectionToken,
        session_receiver: Receiver<Packet>,
        transport_receiver: Receiver<Packet>,
        transport_sender: Sender<Packet>,
        server: SocketAddr,
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
        guard.session.remove(&session);
        if let Some(transport) = &transport_out {
            guard.transport.remove(transport);
        }
        signal
    }

    /// Actual client handler
    async fn client_session(
        session: ConnectionToken,
        transport_out: &mut Option<ConnectionToken>,
        mut session_receiver: Receiver<Packet>,
        mut transport_receiver: Receiver<Packet>,
        transport_sender: Sender<Packet>,
        server: SocketAddr,
        relay: &Relay
    ) -> Option<Signal> {
        tracing::debug!("SOCKS5 client connection reached server");
        let transport = ConnectionToken::new(Host::IpAddr(server.ip()), Transport::TCP, server.port());
        relay.router.lock().expect("Router is poisoned").transport.insert(transport.clone(), transport_sender);
        *transport_out = Some(transport.clone());
        if relay.downstream_sender.send(Packet::SYN(transport.clone())).await.is_err() {
            return Some(Signal::SIGTERM);
        }
        let greeting = Box::from([SOCKS5_VERSION, 0x01, SOCKS5_METHOD_NO_AUTH]);
        if relay.downstream_sender.send(Packet::Data(transport.attach(greeting).await)).await.is_err() {
            return Some(Signal::SIGTERM);
        }
        let mut buffer = Vec::new();
        let mut queue: Vec<Box<[u8]>> = Vec::new();
        let mut established = false;
        loop {
            tokio::select! {
                biased;
                packet = transport_receiver.recv() => match packet {
                    Some(Packet::Data(attached)) => {
                        buffer.extend_from_slice(&attached.data);
                        drop(attached);
                        if !established {
                            match parse_server_hello(&buffer) {
                                Socks5ServerHello::Incomplete => continue,
                                Socks5ServerHello::Invalid => {
                                    tracing::debug!("Invalid SOCKS5 server hello");
                                    if relay.upstream_sender.send(Packet::FIN(session.clone())).await.is_err() {
                                        return Some(Signal::SIGTERM);
                                    }
                                    if relay.downstream_sender.send(Packet::FIN(transport.clone())).await.is_err() {
                                        return Some(Signal::SIGTERM);
                                    }
                                    return None;
                                },
                                Socks5ServerHello::Ok => {
                                    buffer.clear();
                                    established = true;
                                    let request = build_request(session.host(), session.port());
                                    if relay.downstream_sender.send(Packet::Data(transport.attach(request).await)).await.is_err() {
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
                                if relay.upstream_sender.send(Packet::FIN(session.clone())).await.is_err() {
                                    return Some(Signal::SIGTERM);
                                }
                                if relay.downstream_sender.send(Packet::FIN(transport.clone())).await.is_err() {
                                    return Some(Signal::SIGTERM);
                                }
                                return None;
                            },
                            Socks5Reply::Ok => break
                        }
                    },
                    Some(Packet::FIN(_)) | None => {
                        let _ = relay.upstream_sender.send(Packet::FIN(session.clone())).await;
                        return None;
                    },
                    Some(Packet::SYN(_)) => {
                        let _ = relay.downstream_sender.send(Packet::FIN(transport.clone())).await;
                        return None;
                    }
                },
                packet = session_receiver.recv() => match packet {
                    Some(Packet::Data(attached)) => {
                        queue.push(attached.detach().data);
                    },
                    Some(Packet::FIN(_)) | None | Some(Packet::SYN(_)) => {
                        let _ = relay.downstream_sender.send(Packet::FIN(transport.clone())).await;
                        return None;
                    }
                }
            }
        }
        tracing::debug!("Established SOCKS5 connection with server");
        match tokio::select! {
            result = forward_handler(&mut transport_receiver, &session, &relay.upstream_sender, Vec::new()) => result,
            result = forward_handler(&mut session_receiver, &transport, &relay.downstream_sender, queue) => result
        } {
            Ok(()) => {
                tracing::debug!("SOCKS5 connection with server closed");
                None
            },
            Err(error) => {
                tracing::error!("SOCKS5 session forwarding failed: {error}");
                Some(Signal::SIGTERM)
            }
        }
    }
}
