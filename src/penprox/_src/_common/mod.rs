#[pyo3::pymodule(submodule)]
pub mod common {
    use crate::{_sdk::sdk::*, sdk::ConnectionDetached};
    use std::{collections::{HashMap, hash_map::RandomState}, hash::{BuildHasher, DefaultHasher, Hasher}, io::{ErrorKind, Read, Write}, net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr}, path::PathBuf, pin::Pin, sync::Arc, time::Duration};
    use async_trait::async_trait;
    use futures::future::select_all;
    use moka::future::Cache;
    use pyo3::{FromPyObject, exceptions::{PyFileNotFoundError, PyValueError}, prelude::*, pyclass, pymethods, types::PyString};
    use rustls::{ClientConfig, ClientConnection, Connection as TLSConnection, RootCertStore, ServerConfig, ServerConnection, pki_types::{CertificateDer, PrivateKeyDer, ServerName}};
    use simple_dns::{CLASS, Name, Packet as DNSPacket, QCLASS, QTYPE, Question, TYPE, rdata::RData};
    use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::{TcpListener, TcpStream, UdpSocket}, sync::{OwnedMutexGuard, mpsc::{Receiver, Sender, channel}}, task::JoinSet, time::{Instant, sleep_until}};

    pub const TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
    pub const TCP_TIMEOUT: Duration = Duration::from_secs(300);
    pub const UDP_TIMEOUT: Duration = Duration::from_secs(60);
    pub const DNS_TIMEOUT: Duration = Duration::from_secs(5);

    pub const DNS_CNAME_DEPTH: u8 = 16;
    pub const DNS_BUFFER_SIZE: usize = 2048;

    #[pyfunction]
    #[pyo3(name = "TCPNode", signature = (address=None))]
    fn tcp_node(address: Option<(IpAddr, u16)>) -> NodeToken {
        match address {
            Some(address) => TCPUpstreamNode::new(SocketAddr::new(address.0, address.1)),
            None => TCPDownstreamNode::new()
        }
    }

    /// Node for listening an upstream TCP port. Has one downstream.
    #[derive(Debug)]
    pub struct TCPUpstreamNode {
        end: NodeDownstreamEndToken,
        address: SocketAddr,
        signal_receiver: Receiver<Signal>,
    }

    impl TCPUpstreamNode {
        #[allow(clippy::new_ret_no_self)]
        pub fn new(address: SocketAddr) -> NodeToken {
            let (signal_sender, signal_receiver) = channel(SIGNAL_BUFFER_SIZE);
            let end = NodeDownstreamEndToken::new();
            NodeToken::new(
                Box::new(Self {
                    end: end.clone(),
                    address,
                    signal_receiver
                }),
                signal_sender,
                NodeUpstreamInterface::new(vec![]),
                NodeDownstreamInterface::new(vec![end])
            )
        }
        pub fn address(&self) -> SocketAddr {
            self.address
        }
    }

    #[async_trait]
    impl Node for TCPUpstreamNode {
        #[tracing::instrument(name="TCPUpstreamNode::run", skip_all)]
        async fn run(&mut self) -> Result<Option<Signal>, GraphError> {
            let sender = self.end.sender().map_err(GraphError::from)?;
            let mut receiver = self.end.receiver().map_err(GraphError::from)?;
            self.signal_receiver.clear();
            let listener = TcpListener::bind(self.address).await.map_err(|error| {
                tracing::error!("Cannot bind address: {error}");
                GraphError::NodeError
            })?;
            // write back ephermal port
            self.address = listener.local_addr().map_err(|error| {
                tracing::error!("Cannot get address: {error}");
                GraphError::NodeError
            })?;
            #[allow(clippy::mutable_key_type)]
            let mut dispatch: HashMap<ConnectionToken, Sender<UpwardPacket>> = HashMap::new();
            let mut handlers: JoinSet<(ConnectionToken, Option<Signal>)> = JoinSet::new(); // This cancels on drop
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
                            tracing::warn!("TCP handler join failed: {error}");
                            continue;
                        }
                        Some(Ok((connection, signal))) => {
                            dispatch.remove(&connection);
                            if let Some(signal) = signal {
                                tracing::debug!("Connection {:?} removed with signal {:?}, return & propagate", connection, signal);
                                return Ok(Some(signal));
                            }
                            continue;
                        }
                    },
                    packet = receiver.recv() => match packet {
                        Some(packet) => {
                            if let Some(handler) = dispatch.get(packet.connection()) {
                                let _ = handler.try_send(packet); // No good countermeasure for this never condition
                            }
                        },
                        None => {
                            tracing::error!("Downstream closed");
                            return Err(GraphError::Disconnected);
                        }
                    },
                    accepted = listener.accept() => match accepted {
                        Ok((stream, peer)) => {
                            let connection = ConnectionToken::new(Host::IpAddr(peer.ip()), Transport::TCP, peer.port());
                            let (dispatch_sender, dispatch_receiver) = channel(CONNECTION_BUFFER_SIZE);
                            dispatch.insert(connection.clone(), dispatch_sender);
                            handlers.spawn(tcp_upstream_handler(
                                connection,
                                stream,
                                dispatch_receiver,
                                sender.clone()
                            ));
                        },
                        Err(error) => {
                            tracing::warn!("TCP accept failed: {error}");
                            continue;
                        }
                    }
                }
            }

        }
    }

    #[tracing::instrument(name="tcp_upstream_handler", skip_all)]
    async fn tcp_upstream_handler(
        connection: ConnectionToken,
        stream: TcpStream,
        dispatch: Receiver<UpwardPacket>,
        sender: Sender<DownwardPacket>
    ) -> (ConnectionToken, Option<Signal>) {
        let (mut reader, writer) = stream.into_split();
        if sender.send(DownwardPacket::SYN(connection.clone())).await.is_err() {
            return (connection, Some(Signal::SIGTERM));
        }
        let writer_sender = sender.clone();
        let writer_connection = connection.clone();
        let mut writer_task = AbortOnDropHandle::new(tokio::spawn(async move {
            let mut writer = writer;
            let mut receiver = dispatch;
            while let Some(packet) = receiver.recv().await {
                match packet {
                    UpwardPacket::SYN(connection) => {
                        tracing::debug!("Received invalid SYN packet");
                        if writer_sender.send(DownwardPacket::FIN(connection)).await.is_err() {
                            return Some(Signal::SIGTERM);
                        }
                        return None;
                    }
                    UpwardPacket::FIN(_) => {
                        tracing::debug!("Connection to {:?} closed (FIN)", writer_connection.host());
                        return None
                    },
                    UpwardPacket::Data(attached) => {
                        if !matches!(tokio::time::timeout(TCP_TIMEOUT, writer.write_all(&attached.data)).await, Ok(Ok(()))) {
                            if writer_sender.send(DownwardPacket::FIN(writer_connection)).await.is_err() {
                                return Some(Signal::SIGTERM);
                            }
                            return None;
                        }
                    }
                }
            }
            Some(Signal::SIGTERM)
        }));
        let mut buffer = [0u8; PACKET_DATA_SIZE];
        loop {
            tokio::select! {
                biased;
                result = &mut writer_task => {
                    return (connection, result.ok().flatten());
                },
                read = tokio::time::timeout(TCP_TIMEOUT, reader.read(&mut buffer)) => match read {
                    Ok(Err(_)) | Err(_) => {
                        tracing::debug!("Remote is irresponsive");
                        if sender.send(DownwardPacket::FIN(connection.clone())).await.is_err() {
                            return (connection, Some(Signal::SIGTERM));
                        };
                        return (connection, None);
                    }
                    Ok(Ok(0)) => {
                        tracing::debug!("Connection to {:?} closed", connection.host());
                        if sender.send(DownwardPacket::FIN(connection.clone())).await.is_err() {
                            return (connection, Some(Signal::SIGTERM));
                        };
                        return (connection, None);
                    }
                    Ok(Ok(count)) => {
                        let data = buffer[..count].to_vec().into_boxed_slice();
                        if sender.send(DownwardPacket::Data(ConnectionDownward::new(connection.clone(), data).await)).await.is_err() {
                            return (connection, Some(Signal::SIGTERM));
                        }
                    }
                }
            }
        }
    }

    
    /// Node for serving downstream TCP connections. Has one upstream.
    #[derive(Debug)]
    pub struct TCPDownstreamNode {
        end: NodeUpstreamEndToken,
        signal_receiver: Receiver<Signal>,
    }

    impl TCPDownstreamNode {
        #[allow(clippy::new_ret_no_self)]
        pub fn new() -> NodeToken {
            let (signal_sender, signal_receiver) = channel(SIGNAL_BUFFER_SIZE);
            let end = NodeUpstreamEndToken::new();
            NodeToken::new(
                Box::new(Self {
                    end: end.clone(),
                    signal_receiver
                }),
                signal_sender,
                NodeUpstreamInterface::new(vec![end]),
                NodeDownstreamInterface::new(vec![])
            )
        }
    }

    #[async_trait]
    impl Node for TCPDownstreamNode {
        #[tracing::instrument(name="TCPDownstreamNode::run", skip_all)]
        async fn run(&mut self) -> Result<Option<Signal>, GraphError> {
            let sender = self.end.sender().map_err(GraphError::from)?;
            let mut receiver = self.end.receiver().map_err(GraphError::from)?;
            self.signal_receiver.clear();
            #[allow(clippy::mutable_key_type)]
            let mut dispatch: HashMap<ConnectionToken, Sender<DownwardPacket>> = HashMap::new();
            let mut handlers: JoinSet<(ConnectionToken, Option<Signal>)> = JoinSet::new();
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
                            tracing::warn!("Node handler task failed: {error}");
                            continue;
                        }
                        Some(Ok((connection, signal))) => {
                            dispatch.remove(&connection);
                            if let Some(signal) = signal {
                                return Ok(Some(signal));
                            }
                            continue;
                        }
                    },
                    packet = receiver.recv() => match packet {
                        Some(packet) => {
                            match packet {
                                DownwardPacket::SYN(connection) => {
                                    if dispatch.contains_key(&connection) {
                                        tracing::debug!("Received SYN for existing connection {:?}, closing", connection);
                                        let handler = dispatch.remove(&connection).expect("Unwrapping None that is some");
                                        let _ = handler.send(DownwardPacket::FIN(connection.clone())).await; // Violates standard behaviour
                                        sender.send(UpwardPacket::FIN(connection)).await?;
                                        continue;
                                    }
                                    let (dispatch_sender, dispatch_receiver) = channel(CONNECTION_BUFFER_SIZE);
                                    dispatch.insert(connection.clone(), dispatch_sender);
                                    handlers.spawn(tcp_downstream_handler(connection.clone(), dispatch_receiver, sender.clone()));
                                },
                                DownwardPacket::Data(downward) => {
                                    match dispatch.get(downward.connection()) {
                                        Some(handler) => {
                                            let _ = handler.send(DownwardPacket::Data(downward)).await;
                                        },
                                        None => {
                                            sender.send(UpwardPacket::FIN(downward.connection().clone())).await?;
                                        }
                                    };
                                },
                                DownwardPacket::FIN(connection) => {
                                    if !dispatch.contains_key(&connection) {
                                        continue;
                                    }
                                    let handler = dispatch.remove(&connection).expect("Removing non-existent key that is gettable");
                                    let _ = handler.send(DownwardPacket::FIN(connection)).await;
                                }
                            }
                            
                        }
                        None => return Ok(None)
                    }
                }
            }
        }
    }

    #[tracing::instrument(name="tcp_downstream_handler", skip_all)]
    async fn tcp_downstream_handler(
        connection: ConnectionToken,
        dispatch: Receiver<DownwardPacket>,
        sender: Sender<UpwardPacket>
    ) -> (ConnectionToken, Option<Signal>) {
        let Host::IpAddr(ip_addr) = connection.host() else {
            tracing::debug!("Host is not resolved");
            if sender.send(UpwardPacket::FIN(connection.clone())).await.is_err() {
                return (connection, Some(Signal::SIGTERM));
            }
            return (connection, None);
        };
        let stream = match tokio::time::timeout(TCP_CONNECT_TIMEOUT, TcpStream::connect(SocketAddr::new(ip_addr, connection.port()))).await {
            Ok(Ok(stream)) => {
                tracing::debug!("Established new downstream connection");
                stream
            },
            Ok(Err(error)) => {
                tracing::debug!("Cannot connect to remote host: {error}");
                if sender.send(UpwardPacket::FIN(connection.clone())).await.is_err() {
                    return (connection, Some(Signal::SIGTERM));
                };
                return (connection, None);
            },
            _ => {
                tracing::debug!("Cannot connect to remote host (timeout)");
                if sender.send(UpwardPacket::FIN(connection.clone())).await.is_err() {
                    return (connection, Some(Signal::SIGTERM));
                };
                return (connection, None);
            }
        };
        let (mut reader, writer) = stream.into_split();
        let writer_sender = sender.clone();
        let writer_connection = connection.clone();
        let mut writer_task = AbortOnDropHandle::new(tokio::spawn(async move {
            let mut writer = writer;
            let mut receiver = dispatch;
            while let Some(packet) = receiver.recv().await {
                match packet {
                    DownwardPacket::SYN(connection) => {
                        tracing::debug!("Received invalid SYN packet");
                        if writer_sender.send(UpwardPacket::FIN(connection)).await.is_err() {
                            return Some(Signal::SIGTERM);
                        }
                        return None;
                    }
                    DownwardPacket::FIN(_) => {
                        tracing::debug!("Connection to {:?} closed (FIN)", writer_connection.host());
                        return None
                    },
                    DownwardPacket::Data(attached) => {
                        if !matches!(tokio::time::timeout(TCP_TIMEOUT, writer.write_all(&attached.data)).await, Ok(Ok(()))) {
                            if writer_sender.send(UpwardPacket::FIN(writer_connection)).await.is_err() {
                                return Some(Signal::SIGTERM);
                            }
                            return None;
                        }
                    }
                }
            }
            Some(Signal::SIGTERM)
        }));
        let mut buffer = [0u8; PACKET_DATA_SIZE];
        loop {
            tokio::select! {
                biased;
                result = &mut writer_task => {
                    return (connection, result.ok().flatten());
                },
                read = tokio::time::timeout(TCP_TIMEOUT, reader.read(&mut buffer)) => match read {
                    Ok(Err(_)) | Err(_) => {
                        tracing::debug!("Remote is irresponsive");
                        if sender.send(UpwardPacket::FIN(connection.clone())).await.is_err() {
                            return (connection, Some(Signal::SIGTERM));
                        };
                        return (connection, None);
                    }
                    Ok(Ok(0)) => {
                        tracing::debug!("Connection to {:?} closed", connection.host());
                        if sender.send(UpwardPacket::FIN(connection.clone())).await.is_err() {
                            return (connection, Some(Signal::SIGTERM));
                        };
                        return (connection, None);
                    }
                    Ok(Ok(count)) => {
                        let data = buffer[..count].to_vec().into_boxed_slice();
                        if sender.send(UpwardPacket::Data(ConnectionUpward::new(connection.clone(), data).await)).await.is_err() {
                            return (connection, Some(Signal::SIGTERM));
                        }
                    }
                }
            }
        }
    }

    #[derive(Clone, Copy, FromPyObject, Debug)]
    enum UDPNodeMode {
        Upstream(IpAddr, u16),
        Downstream(AddressMode)
    }

    #[pyfunction]
    #[pyo3(name = "UDPNode", signature = (mode=UDPNodeMode::Downstream(AddressMode::V4V6)))]
    fn udp_node(mode: UDPNodeMode) -> NodeToken {
        match mode {
            UDPNodeMode::Upstream(ip, port) => UDPUpstreamNode::new(SocketAddr::new(ip, port)),
            UDPNodeMode::Downstream(mode) => UDPDownstreamNode::new(mode)
        }
    }

    /// Upstream UDP node that binds a port. Has one downstream.
    #[derive(Debug)]
    pub struct UDPUpstreamNode {
        end: NodeDownstreamEndToken,
        signal_receiver: Receiver<Signal>,
        address: SocketAddr
    }

    impl UDPUpstreamNode {
        #[allow(clippy::new_ret_no_self)]
        pub fn new(address: SocketAddr) -> NodeToken {
            let (signal_sender, signal_receiver) = channel(SIGNAL_BUFFER_SIZE);
            let end = NodeDownstreamEndToken::new();
            NodeToken::new(
                Box::new(Self {
                    end: end.clone(),
                    signal_receiver,
                    address
                }),
                signal_sender,
                NodeUpstreamInterface::new(vec![]),
                NodeDownstreamInterface::new(vec![end])
            )
        }
        pub fn address(&self) -> SocketAddr {
            self.address
        }
    }

    #[async_trait]
    impl Node for UDPUpstreamNode {
        async fn run(&mut self) -> Result<Option<Signal>, GraphError> {
            let sender = self.end.sender().map_err(GraphError::from)?;
            let mut receiver = self.end.receiver().map_err(GraphError::from)?;
            self.signal_receiver.clear();
            let socket = UdpSocket::bind(self.address).await.map_err(|error| {
                tracing::error!("Cannot bind address: {error}");
                GraphError::NodeError
            })?;
            self.address = socket.local_addr().map_err(|_| GraphError::Occupied)?;
            let mut connections: HashMap<SocketAddr, (ConnectionToken, Instant)> = HashMap::new();
            let mut buffer = [0u8; PACKET_DATA_SIZE];
            loop {
                let deadline = connections.values().map(|(_, deadline)| *deadline).min();
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
                    packet = receiver.recv() => match packet {
                        Some(UpwardPacket::SYN(connection)) => {
                            sender.send(DownwardPacket::FIN(connection)).await?;
                            continue;
                        }
                        Some(UpwardPacket::FIN(connection)) => {
                            if let Host::IpAddr(ip_addr) = connection.host() {
                                connections.remove(&SocketAddr::new(ip_addr, connection.port()));
                            }
                        },
                        Some(UpwardPacket::Data(upward)) => {
                            match upward.connection().host() {
                                Host::Domain(_) => sender.send(DownwardPacket::FIN(upward.connection().clone())).await?,
                                Host::IpAddr(ip_addr) => {
                                    socket.send_to(&upward.data[..], SocketAddr::new(ip_addr, upward.connection().port())).await.map_err(|error| {
                                        tracing::error!("UDP socket closed: {error}");
                                        GraphError::NodeError
                                    })?;
                                    if let Some((_, deadline)) = connections.get_mut(&SocketAddr::new(ip_addr, upward.connection().port())) {
                                        *deadline = Instant::now() + UDP_TIMEOUT;
                                    }
                                }
                            }
                        },
                        None => return Ok(Some(Signal::SIGTERM))
                    },
                    accepted = socket.recv_from(&mut buffer) => {
                        let (count, peer) = match accepted {
                            Ok(result) => result,
                            Err(error) => {
                                tracing::error!("UDP receive failed: {error}");
                                return Ok(Some(Signal::SIGTERM));
                            }
                        };
                        let connection = match connections.get_mut(&peer) {
                            Some((connection, deadline)) => {
                                *deadline = Instant::now() + UDP_TIMEOUT;
                                connection.clone()
                            }
                            None => {
                                let connection = ConnectionToken::new(Host::IpAddr(peer.ip()), Transport::UDP, peer.port());
                                sender.send(DownwardPacket::SYN(connection.clone())).await?;
                                connections.insert(peer, (connection.clone(), Instant::now() + UDP_TIMEOUT));
                                connection
                            }
                        };
                        let data = buffer[..count].to_vec().into_boxed_slice();
                        if let Ok(downward) = ConnectionDownward::try_new(connection, data) { // Just drop UDP, it's proper "back pressure"
                            sender.send(DownwardPacket::Data(downward)).await?;
                        }
                    },
                    _ = async move {
                        match deadline {
                            Some(deadline) => sleep_until(deadline).await,
                            None => std::future::pending::<()>().await
                        }
                    } => {
                        let now = Instant::now();
                        let expired: Vec<SocketAddr> = connections.iter()
                            .filter(|(_, (_, deadline))| *deadline <= now)
                            .map(|(peer, _)| *peer)
                            .collect();
                        for peer in expired {
                            if let Some((connection, _)) = connections.remove(&peer) {
                                sender.send(DownwardPacket::FIN(connection)).await?;
                            }
                        }
                    }
                }
            }
        }
    }

    /// Downstream UDP node that serves out going UDP connections.
    /// Has one upstream.
    #[derive(Debug)]
    pub struct UDPDownstreamNode {
        end: NodeUpstreamEndToken,
        signal_receiver: Receiver<Signal>,
        mode: AddressMode
    }

    impl UDPDownstreamNode {
        #[allow(clippy::new_ret_no_self)]
        pub fn new(mode: AddressMode) -> NodeToken {
            let (signal_sender, signal_receiver) = channel(SIGNAL_BUFFER_SIZE);
            let end = NodeUpstreamEndToken::new();
            NodeToken::new(
                Box::new(Self {
                    end: end.clone(),
                    signal_receiver,
                    mode
                }),
                signal_sender,
                NodeUpstreamInterface::new(vec![end]),
                NodeDownstreamInterface::new(vec![])
            )
        }
    }

    #[async_trait]
    impl Node for UDPDownstreamNode {
        async fn run(&mut self) -> Result<Option<Signal>, GraphError> {
            let sender = self.end.sender().map_err(GraphError::from)?;
            let mut receiver = self.end.receiver().map_err(GraphError::from)?;
            self.signal_receiver.clear();
            let socket_v4 = match self.mode {
                AddressMode::V6 => None,
                _ => Some(UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)).await.map_err(|error| {
                    tracing::error!("Cannot bind ipv4 address: {error}");
                    GraphError::NodeError
                })?),
                
            };
            let socket_v6 = match self.mode {
                AddressMode::V4 => None,
                _ => Some(UdpSocket::bind(SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)).await.map_err(|error| {
                    tracing::error!("Cannot bind ipv6 address: {error}");
                    GraphError::NodeError
                })?),
            };
            let mut connections: HashMap<SocketAddr, (ConnectionToken, Instant)> = HashMap::new();
            let mut buffer_v4 = [0u8; PACKET_DATA_SIZE];
            let mut buffer_v6 = [0u8; PACKET_DATA_SIZE];
            loop {
                let deadline = connections.values().map(|(_, deadline)| *deadline).min();
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
                    packet = receiver.recv() => match packet {
                        Some(DownwardPacket::SYN(connection)) => {
                            match connection.host() {
                                Host::Domain(_) => sender.send(UpwardPacket::FIN(connection)).await?,
                                Host::IpAddr(ip_addr) => { connections.insert(SocketAddr::new(ip_addr, connection.port()), (connection, Instant::now() + UDP_TIMEOUT)); }
                            };
                        }
                        Some(DownwardPacket::FIN(connection)) => {
                            if let Host::IpAddr(ip_addr) = connection.host() {
                                connections.remove(&SocketAddr::new(ip_addr, connection.port()));
                            }
                        },
                        Some(DownwardPacket::Data(attached)) => {
                            match attached.connection().host() {
                                Host::Domain(_) => sender.send(UpwardPacket::FIN(attached.connection().clone())).await?,
                                Host::IpAddr(ip_addr) => {
                                    let socket = match ip_addr {
                                        IpAddr::V4(_) => socket_v4.as_ref(),
                                        IpAddr::V6(_) => socket_v6.as_ref()
                                    };
                                    if let Some(socket) = socket {
                                        socket.send_to(&attached.data[..], SocketAddr::new(ip_addr, attached.connection().port())).await.map_err(|error| {
                                            tracing::error!("UDP socket closed: {error}");
                                            GraphError::NodeError
                                        })?;
                                    };
                                    if let Some((_, deadline)) = connections.get_mut(&SocketAddr::new(ip_addr, attached.connection().port())) {
                                        *deadline = Instant::now() + UDP_TIMEOUT;
                                    }
                                }
                            }
                        },
                        None => return Ok(Some(Signal::SIGTERM))
                    },
                    accepted_v4 = socket_v4.as_ref().expect("Unwrapping None which is Some").recv_from(&mut buffer_v4), if socket_v4.is_some() => {
                        let (count, peer) = match accepted_v4 {
                            Ok(result) => result,
                            Err(error) => {
                                tracing::error!("UDP receive failed: {error}");
                                return Ok(Some(Signal::SIGTERM));
                            }
                        };
                        let connection = match connections.get_mut(&peer) {
                            Some((connection, deadline)) => {
                                *deadline = Instant::now() + UDP_TIMEOUT;
                                connection.clone()
                            }
                            None => continue
                        };
                        let data = buffer_v4[..count].to_vec().into_boxed_slice();
                        if let Ok(upward) = ConnectionUpward::try_new(connection, data) { // Just drop UDP, it's proper "back pressure"
                            sender.send(UpwardPacket::Data(upward)).await?;
                        }
                    },
                    accepted_v6 = socket_v6.as_ref().expect("Unwrapping None which is Some").recv_from(&mut buffer_v6), if socket_v6.is_some() => {
                        let (count, peer) = match accepted_v6 {
                            Ok(result) => result,
                            Err(error) => {
                                tracing::error!("UDP receive failed: {error}");
                                return Ok(Some(Signal::SIGTERM));
                            }
                        };
                        let connection = match connections.get_mut(&peer) {
                            Some((connection, deadline)) => {
                                *deadline = Instant::now() + UDP_TIMEOUT;
                                connection.clone()
                            }
                            None => continue
                        };
                        let data = buffer_v6[..count].to_vec().into_boxed_slice();
                        if let Ok(attached) = ConnectionUpward::try_new(connection, data) { // Just drop UDP, it's proper "back pressure"
                            sender.send(UpwardPacket::Data(attached)).await?;
                        }
                    },
                    _ = async move {
                        match deadline {
                            Some(deadline) => sleep_until(deadline).await,
                            None => std::future::pending::<()>().await
                        }
                    } => {
                        let now = Instant::now();
                        let expired: Vec<SocketAddr> = connections.iter()
                            .filter(|(_, (_, deadline))| *deadline <= now)
                            .map(|(peer, _)| *peer)
                            .collect();
                        for peer in expired {
                            if let Some((connection, _)) = connections.remove(&peer) {
                                sender.send(UpwardPacket::FIN(connection)).await?;
                            }
                        }
                    }
                }
            }
        }
    }

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

    /// Python arg type
    #[derive(Clone, Copy, Debug)]
    enum PythonCallbackChannelType {
        Signal,
        Upstream,
        Downstream
    }

    impl<'py> IntoPyObject<'py> for PythonCallbackChannelType {
        type Error = PyErr;
        type Target = PyAny;
        type Output = Bound<'py, Self::Target>;
        fn into_pyobject(self, py: Python<'py>) -> Result<Self::Output, Self::Error> {
            match self {
                Self::Signal => Ok(PyString::new(py, "Signal").into_any()),
                Self::Upstream => Ok(PyString::new(py, "Upstream").into_any()),
                Self::Downstream => Ok(PyString::new(py, "Downstream").into_any())
            }
        }
    }

    /// Python arg type
    #[derive(IntoPyObject, Debug)]
    enum PythonCallbackChannelObject {
        DetachedPacket(DetachedPacket),
        Signal(Signal),
        Error(())
    }

    /// Python return type
    #[derive(FromPyObject, Debug)]
    enum PythonCallbackReturnCode {
        Control(bool),
        Signal(Signal)
    }

    #[pyclass]
    #[derive(Debug)]
    pub struct PythonNode {
        pub upstreams: NodeUpstreamInterface,
        pub downstreams: NodeDownstreamInterface,
        pub signal_receiver: Receiver<Signal>,
        pub callback: Py<PyAny>
    }

    impl PythonNode {
        #[allow(clippy::new_ret_no_self)]
        pub fn new<'py>(callback: Bound<'py, PyAny>, upstreams: usize, downstreams: usize) -> Result<NodeToken, &'static str> {
            if !callback.is_callable() {
                tracing::error!("Callback is not callable");
                return Err("Callback is not callable");
            }
            let mut u = Vec::with_capacity(upstreams);
            let mut d = Vec::with_capacity(downstreams);
            u.resize_with(upstreams, NodeUpstreamEndToken::new);
            d.resize_with(downstreams, NodeDownstreamEndToken::new);
            let (signal_sender, signal_receiver) = channel(SIGNAL_BUFFER_SIZE);
            let u = NodeUpstreamInterface::new(u);
            let d = NodeDownstreamInterface::new(d);
            Ok(NodeToken::new(
                Box::new(Self {
                    upstreams: u.clone(),
                    downstreams: d.clone(),
                    signal_receiver,
                    callback: callback.unbind()
                }),
                signal_sender,
                u,
                d
            ))
        }
    }

    #[pymethods]
    impl PythonNode {
        #[new]
        #[allow(clippy::new_ret_no_self)]
        fn python_new<'py>(callback: Bound<'py, PyAny>, upstreams: usize, downstreams: usize) -> PyResult<NodeToken> {
            Self::new(callback, upstreams, downstreams).map_err(PyValueError::new_err)
        }
    }

    #[async_trait]
    impl Node for PythonNode {
        #[tracing::instrument(name="PythonNode::run", skip_all)]
        async fn run(&mut self) -> Result<Option<Signal>, GraphError> {
            let mut upstreams = Vec::with_capacity(self.upstreams.len());
            for upstream in &mut self.upstreams.get_all() {
                upstreams.push(upstream.receiver().map_err(GraphError::from)?
                );
            }
            let mut downstreams = Vec::with_capacity(self.downstreams.len());
            for downstream in &mut self.downstreams.get_all() {
                downstreams.push(downstream.receiver().map_err(GraphError::from)?);
            }
            loop {
                let (channel_type, channel_index, channel_object) = {
                    let mut node_ends: Vec<Pin<Box<dyn Future<Output = (PythonCallbackChannelType, isize, PythonCallbackChannelObject)> + Send + '_>>> = Vec::with_capacity(upstreams.len() + downstreams.len());
                    for (index, receiver) in upstreams.iter_mut().enumerate() {
                        node_ends.push(Box::pin(async move {
                            match receiver.recv().await {
                                Some(packet) => (PythonCallbackChannelType::Upstream, index as isize, PythonCallbackChannelObject::DetachedPacket(packet.into())),
                                None => (PythonCallbackChannelType::Upstream, index as isize, PythonCallbackChannelObject::Error(())) // This error is mapped to actual error later in loop
                            }
                        }));
                    }
                    for (index, receiver) in downstreams.iter_mut().enumerate() {
                        node_ends.push(Box::pin(async move {
                            match receiver.recv().await {
                                Some(packet) => (PythonCallbackChannelType::Downstream, index as isize, PythonCallbackChannelObject::DetachedPacket(packet.into())),
                                None => (PythonCallbackChannelType::Downstream, index as isize, PythonCallbackChannelObject::Error(()))
                            }
                        }));
                    }
                    if node_ends.is_empty() {
                        match self.signal_receiver.recv().await {
                            Some(signal) => (PythonCallbackChannelType::Signal, -1, PythonCallbackChannelObject::Signal(signal)),
                            None => {
                                tracing::error!("Signal handle closed");
                                return Err(GraphError::Disconnected)
                            }
                        }
                    } else {
                        tokio::select! {
                            biased;
                            signal = self.signal_receiver.recv() => match signal {
                                Some(signal) => {
                                    if signal == Signal::SIGTERM {
                                        return Ok(None);
                                    }
                                    (PythonCallbackChannelType::Signal, -1, PythonCallbackChannelObject::Signal(signal))
                                },
                                None => {
                                    tracing::error!("Signal handle closed");
                                    return Err(GraphError::Disconnected)
                                }
                            },
                            packet = select_all(node_ends) => packet.0, // Cancel safe
                        }
                    }
                };
                if matches!(&channel_object, PythonCallbackChannelObject::Error(())) {
                    tracing::error!("End is closed");
                    return Err(GraphError::Disconnected);
                }
                let result = Python::attach(|py| {
                    let argument = (channel_type, channel_index, channel_object).into_pyobject(py)?;
                    let object = self.callback.call1(py, (argument,))?;
                    object.bind(py).extract::<PythonCallbackReturnCode>()
                });
                match result {
                    Ok(PythonCallbackReturnCode::Control(false)) => continue,
                    Ok(PythonCallbackReturnCode::Control(true)) => return Ok(None),
                    Ok(PythonCallbackReturnCode::Signal(signal)) => return Ok(Some(signal)),
                    _ => {
                        tracing::error!("Python callback returned invalid value {:?}", result);
                        return Ok(Some(Signal::SIGTERM));
                    }
                }
            }
        }
    }

    /// `ClientConfig` or `ServerConfig`
    #[derive(Clone, Debug)]
    enum TLSMode {
        Server(Arc<ServerConfig>),
        Client(Arc<ClientConfig>)
    }

    /// TLS server node with one cipher upstream and one plaintext downstream.
    #[derive(Debug)]
    pub struct TLSServerNode {
        cipher: NodeUpstreamEndToken,
        clear: NodeDownstreamEndToken,
        signal_receiver: Receiver<Signal>,
        config: Arc<ServerConfig>
    }

    impl TLSServerNode {
        #[allow(clippy::new_ret_no_self)]
        pub fn new(certificates: Vec<CertificateDer<'static>>, key: PrivateKeyDer<'static>) -> Result<NodeToken, String> {
            let config = ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(certificates, key)
                .map_err(|error| format!("Invalid certificate or private key: {error}"))?;
            let (signal_sender, signal_receiver) = channel(SIGNAL_BUFFER_SIZE);
            let cipher = NodeUpstreamEndToken::new();
            let clear = NodeDownstreamEndToken::new();
            Ok(NodeToken::new(
                Box::new(Self {
                    cipher: cipher.clone(),
                    clear: clear.clone(),
                    signal_receiver,
                    config: Arc::new(config)
                }),
                signal_sender,
                NodeUpstreamInterface::new(vec![cipher]),
                NodeDownstreamInterface::new(vec![clear])
            ))
        }
    }

    /// TLS client node, has one upstream (clear) and one downstream (cipher).
    #[derive(Debug)]
    pub struct TLSClientNode {
        clear: NodeUpstreamEndToken,
        cipher: NodeDownstreamEndToken,
        signal_receiver: Receiver<Signal>,
        config: Arc<ClientConfig>
    }

    impl TLSClientNode {
        #[allow(clippy::new_ret_no_self)]
        pub fn new() -> NodeToken {
            let config = ClientConfig::builder()
                .with_root_certificates(RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() })
                .with_no_client_auth();
            let (signal_sender, signal_receiver) = channel(SIGNAL_BUFFER_SIZE);
            let clear = NodeUpstreamEndToken::new();
            let cipher = NodeDownstreamEndToken::new();
            NodeToken::new(
                Box::new(Self {
                    clear: clear.clone(),
                    cipher: cipher.clone(),
                    signal_receiver,
                    config: Arc::new(config)
                }),
                signal_sender,
                NodeUpstreamInterface::new(vec![clear]),
                NodeDownstreamInterface::new(vec![cipher])
            )
        }
    }

    /// The server certificate chain and private key are loaded from PEM files.
    /// The certificate file may contain the whole chain; the key file may be
    /// PKCS#1, PKCS#8 or SEC1.
    #[pyfunction]
    #[pyo3(name = "TLSNode", signature = (cert_and_key=None))]
    fn tls_node(cert_and_key: Option<(PathBuf, PathBuf)>) -> PyResult<NodeToken> {
        let Some((certificate, key)) = cert_and_key else {
            return Ok(TLSClientNode::new());
        };
        let certificate_bytes = std::fs::read(&certificate).map_err(PyFileNotFoundError::new_err)?;
        let mut certificate_reader = &certificate_bytes[..];
        let certificate_chain = rustls_pemfile::certs(&mut certificate_reader)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| PyValueError::new_err(format!("Cannot parse certificate: {error}")))?;
        if certificate_chain.is_empty() {
            return Err(PyValueError::new_err("No certificate found"));
        }
        let key_bytes = std::fs::read(&key).map_err(PyFileNotFoundError::new_err)?;
        let mut key_reader = &key_bytes[..];
        let key_der = rustls_pemfile::private_key(&mut key_reader)
            .map_err(|error| PyValueError::new_err(format!("Cannot parse private key: {error}")))?
            .ok_or(PyValueError::new_err("No private key found"))?;
        TLSServerNode::new(certificate_chain, key_der).map_err(PyValueError::new_err)
    }

    #[async_trait]
    impl Node for TLSServerNode {
        #[tracing::instrument(name="TLSServerNode::run", skip_all)]
        async fn run(&mut self) -> Result<Option<Signal>, GraphError> {
            let cipher_sender = self.cipher.sender().map_err(GraphError::from)?;
            let cipher_receiver = self.cipher.receiver().map_err(GraphError::from)?;
            let clear_sender = self.clear.sender().map_err(GraphError::from)?;
            let clear_receiver = self.clear.receiver().map_err(GraphError::from)?;
            tls_run::<Downward>(
                cipher_sender,
                cipher_receiver,
                clear_sender,
                clear_receiver,
                &mut self.signal_receiver,
                TLSMode::Server(self.config.clone())
            ).await
        }
    }

    #[async_trait]
    impl Node for TLSClientNode {
        #[tracing::instrument(name="TLSClientNode::run", skip_all)]
        async fn run(&mut self) -> Result<Option<Signal>, GraphError> {
            let clear_sender = self.clear.sender().map_err(GraphError::from)?;
            let clear_receiver = self.clear.receiver().map_err(GraphError::from)?;
            let cipher_sender = self.cipher.sender().map_err(GraphError::from)?;
            let cipher_receiver = self.cipher.receiver().map_err(GraphError::from)?;
            tls_run::<Upward>(
                cipher_sender,
                cipher_receiver,
                clear_sender,
                clear_receiver,
                &mut self.signal_receiver,
                TLSMode::Client(self.config.clone())
            ).await
        }
    }

    /// Shared runtime for both TLS server and client.
    ///
    /// Downward `D` is server (decrypting).
    #[allow(clippy::mutable_key_type)]
    #[tracing::instrument(name="tls_run", skip_all)]
    async fn tls_run<D: Direction>(
        cipher_sender: Sender<D::BackwardPacket>,
        mut cipher_receiver: OwnedMutexGuard<Receiver<D::ForwardPacket>>,
        clear_sender: Sender<D::ForwardPacket>,
        mut clear_receiver: OwnedMutexGuard<Receiver<D::BackwardPacket>>,
        signal_receiver: &mut Receiver<Signal>,
        mode: TLSMode
    ) -> Result<Option<Signal>, GraphError> {
        signal_receiver.clear();
        let trigger_is_cipher = matches!(&mode, TLSMode::Server(_));
        let mut dispatch: HashMap<ConnectionToken, (Sender<D::ForwardPacket>, Sender<D::BackwardPacket>)> = HashMap::new();
        let mut handlers: JoinSet<(ConnectionToken, Option<Signal>)> = JoinSet::new();
        loop {
            tokio::select! {
                biased;
                signal = signal_receiver.recv() => match signal {
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
                        tracing::warn!("TLS handler task failed: {error}");
                        continue;
                    }
                    Some(Ok((connection, signal))) => {
                        dispatch.remove(&connection);
                        if let Some(signal) = signal {
                            tracing::warn!("TLS handler returned signal {:?}, propagating", signal);
                            return Ok(Some(signal));
                        }
                        continue;
                    }
                },
                packet = cipher_receiver.recv() => match packet {
                    Some(packet) if packet.is_syn() && trigger_is_cipher => {
                        if !matches!(packet.connection().transport(), Transport::TCP) {
                            tracing::debug!("TLS is only supported over TCP");
                            cipher_sender.send(D::BackwardPacket::new_fin(packet.connection().clone())).await?;
                            continue;
                        }
                        let connection = packet.connection().clone();
                        let (cipher_dispatch, cipher_handler) = channel(CONNECTION_BUFFER_SIZE);
                        let (clear_dispatch, clear_handler) = channel(CONNECTION_BUFFER_SIZE);
                        dispatch.insert(connection.clone(), (cipher_dispatch, clear_dispatch));
                        handlers.spawn(tls_handler::<D>(
                            connection,
                            cipher_handler,
                            clear_handler,
                            cipher_sender.clone(),
                            clear_sender.clone(),
                            mode.clone()
                        ));
                    },
                    Some(packet) if packet.is_syn() => {
                        tracing::debug!("Received invalid SYN packet");
                        cipher_sender.send(D::BackwardPacket::new_fin(packet.connection().clone())).await?;
                    },
                    Some(packet) => {
                        match dispatch.get(packet.connection()) {
                            Some((sender, _)) => { let _ = sender.send(packet).await; },
                            None if !packet.is_fin() => {
                                tracing::debug!("Received packet that does not belong");
                                cipher_sender.send(D::BackwardPacket::new_fin(packet.connection().clone())).await?;
                            },
                            None => continue
                        }
                    },
                    None => return Ok(None)
                },
                packet = clear_receiver.recv() => match packet {
                    Some(packet) if packet.is_syn() && !trigger_is_cipher => {
                        if !matches!(packet.connection().transport(), Transport::TCP) {
                            tracing::debug!("TLS is only supported over TCP");
                            clear_sender.send(D::ForwardPacket::new_fin(packet.connection().clone())).await?;
                            continue;
                        }
                        let connection = packet.connection().clone();
                        let (cipher_dispatch, cipher_handler) = channel(CONNECTION_BUFFER_SIZE);
                        let (clear_dispatch, clear_handler) = channel(CONNECTION_BUFFER_SIZE);
                        dispatch.insert(connection.clone(), (cipher_dispatch, clear_dispatch));
                        handlers.spawn(tls_handler::<D>(
                            connection,
                            cipher_handler,
                            clear_handler,
                            cipher_sender.clone(),
                            clear_sender.clone(),
                            mode.clone()
                        ));
                    },
                    Some(packet) if packet.is_syn() => {
                        tracing::debug!("Received invalid SYN packet");
                        clear_sender.send(D::ForwardPacket::new_fin(packet.connection().clone())).await?;
                    },
                    Some(packet) => {
                        match dispatch.get(packet.connection()) {
                            Some((_, sender)) => { let _ = sender.send(packet).await; },
                            None if !packet.is_fin() => {
                                tracing::debug!("Received packet that does not belong");
                                clear_sender.send(D::ForwardPacket::new_fin(packet.connection().clone())).await?;
                            },
                            None => continue
                        }
                    },
                    None => return Ok(None)
                }
            }
        }
    }

    /// Util: Close the one / two (established) side connections with catch `Signal` failure
    async fn tls_close<D: Direction>(
        connection: ConnectionToken,
        cipher_sender: &Sender<D::BackwardPacket>,
        clear_sender: &Sender<D::ForwardPacket>,
        established: bool
    ) -> Option<Signal> {
        if cipher_sender.send(D::BackwardPacket::new_fin(connection.clone())).await.is_err() {
            return Some(Signal::SIGTERM);
        }
        if established && clear_sender.send(D::ForwardPacket::new_fin(connection)).await.is_err() {
            return Some(Signal::SIGTERM);
        }
        None
    }

    /// A rustls connection bundled with some missing buffers, and a simple interface.
    ///
    /// Flush on write is necessary due to how rustls works. Follows the usual direction convention.
    struct TLSStream {
        connection: TLSConnection,
        /// Ciphertext in
        cipher_buffer: Vec<u8>
    }

    impl TLSStream {
        fn new(mut connection: TLSConnection) -> Self {
            // A buffer large enough.
            //
            // Because we flush on write, this is only to buffer plaintext
            // during hanshake.
            connection.set_buffer_limit(Some(CONNECTION_BUFFER_SIZE * PACKET_DATA_SIZE));
            Self {
                connection,
                cipher_buffer: Vec::new()
            }
        }

        fn is_handshaking(&self) -> bool {
            self.connection.is_handshaking()
        }

        fn send_close_notify(&mut self) {
            self.connection.send_close_notify();
        }

        /// Push to cipher buffer.
        fn push_cipher(&mut self, data: &[u8]) {
            self.cipher_buffer.extend_from_slice(data);
        }

        /// Push to plaintext buffer.
        /// 
        /// Fails when buffer is full. However, the buffer is large enough that
        /// this should not happen if connection buffer rules are followed.
        fn push_plaintext(&mut self, data: &[u8]) -> Result<(), ()> {
            self.connection.writer().write_all(data).map_err(|error| {
                tracing::debug!("TLS write failed: {error}");
            })
        }

        /// Flush cipher out (rustls to sender) and cipher in (buffer to rustls).
        async fn flush_cipher<D: Direction>(
            &mut self,
            cipher_sender: &Sender<D::BackwardPacket>,
            connection: &ConnectionToken
        ) -> Result<(), Option<Signal>> {
            let mut tls_buffer = [0u8; PACKET_DATA_SIZE];
            loop {
                while self.connection.wants_write() {
                    let Ok(count) = self.connection.write_tls(&mut &mut tls_buffer[..]) else {
                        tracing::warn!("TLS write failed");
                        return Err(None);
                    };
                    if count == 0 { // EOF
                        return Err(None);
                    }
                    if cipher_sender.send(D::BackwardPacket::new_data(connection.clone(), tls_buffer[..count].to_vec().into_boxed_slice()).await).await.is_err() {
                        return Err(Some(Signal::SIGTERM));
                    }
                }
                if self.cipher_buffer.is_empty() || !self.connection.wants_read() {
                    return Ok(());
                }
                let Ok(count) = self.connection.read_tls(&mut self.cipher_buffer.as_slice()) else {
                    tracing::debug!("TLS read failed");
                    return Err(None);
                };
                if count == 0 { // close_notify
                    return Err(None);
                }
                self.cipher_buffer.drain(..count);
                if let Err(error) = self.connection.process_new_packets() {
                    tracing::debug!("TLS processing failed: {error}");
                    return Err(None);
                }
            }
        }

        /// Flush plaintext out (send).
        ///
        /// Plaintext in is directly written into rustls in initial push.
        async fn flush_plaintext<D: Direction>(
            &mut self,
            clear_sender: &Sender<D::ForwardPacket>,
            connection: &ConnectionToken
        ) -> Result<(), Option<Signal>> {
            let mut plain_buffer = [0u8; PACKET_DATA_SIZE];
            loop {
                let data = {
                    let mut reader = self.connection.reader();
                    match reader.read(&mut plain_buffer) {
                        Ok(0) => return Ok(()),
                        Ok(count) => plain_buffer[..count].to_vec().into_boxed_slice(),
                        Err(error) if error.kind() == ErrorKind::WouldBlock => return Ok(()),
                        Err(_) => {
                            tracing::debug!("TLS plaintext read failed");
                            return Err(None);
                        }
                    }
                };
                if clear_sender.send(D::ForwardPacket::new_data(connection.clone(), data).await).await.is_err() {
                    return Err(Some(Signal::SIGTERM));
                }
            }
        }

        /// Full flush.
        async fn flush<D: Direction>(
            &mut self,
            cipher_sender: &Sender<D::BackwardPacket>,
            clear_sender: &Sender<D::ForwardPacket>,
            connection: &ConnectionToken
        ) -> Result<(), Option<Signal>> {
            loop { // rustls needs a clear out buffer so alternating loop is necessary
                self.flush_cipher::<D>(cipher_sender, connection).await?;
                self.flush_plaintext::<D>(clear_sender, connection).await?;
                if self.cipher_buffer.is_empty() || !self.connection.wants_read() {
                    return Ok(());
                }
            }
        }
    }

    /// Takes over control until handshake is finished.
    #[tracing::instrument(name="tls_handshake", skip_all)]
    async fn tls_handshake<D: Direction>(
        connection: ConnectionToken,
        cipher_receiver: &mut Receiver<D::ForwardPacket>,
        clear_receiver: &mut Receiver<D::BackwardPacket>,
        cipher_sender: &Sender<D::BackwardPacket>,
        clear_sender: &Sender<D::ForwardPacket>,
        mode: TLSMode
    ) -> Result<TLSStream, Option<Signal>> {
        let is_client = matches!(&mode, TLSMode::Client(_));
        let mut established = false;
        let connection_tls = match &mode {
            TLSMode::Server(config) => match ServerConnection::new(config.clone()) {
                Ok(tls) => TLSConnection::Server(tls),
                Err(error) => {
                    tracing::debug!("Cannot create TLS connection: {error}");
                    if cipher_sender.send(D::BackwardPacket::new_fin(connection)).await.is_err() {
                        return Err(Some(Signal::SIGTERM));
                    }
                    return Err(None);
                }
            },
            TLSMode::Client(config) => {
                let server_name = match connection.host() {
                    Host::Domain(domain) => ServerName::try_from(domain).ok(),
                    Host::IpAddr(ip_addr) => Some(ServerName::from(ip_addr))
                };
                let Some(server_name) = server_name else {
                    tracing::debug!("Cannot derive TLS server name");
                    return Err(tls_close::<D>(connection, cipher_sender, clear_sender, established).await);
                };
                match ClientConnection::new(config.clone(), server_name) {
                    Ok(tls) => TLSConnection::Client(tls),
                    Err(error) => {
                        tracing::debug!("Cannot create TLS connection: {error}");
                        return Err(tls_close::<D>(connection, cipher_sender, clear_sender, established).await);
                    }
                }
            }
        };
        let mut tls = TLSStream::new(connection_tls);
        let mut queue: Vec<D::BackwardPacket> = Vec::new(); // emptied carriers for clear data already handed to rustls during the handshake; holding them keeps the connection permits backpressuring the clear side
        if is_client {
            if cipher_sender.send(D::BackwardPacket::new_syn(connection.clone())).await.is_err() {
                return Err(Some(Signal::SIGTERM));
            }
            established = true;
            match tls.flush_cipher::<D>(cipher_sender, &connection).await {
                Ok(()) => {}
                Err(Some(signal)) => return Err(Some(signal)),
                Err(None) => return Err(tls_close::<D>(connection, cipher_sender, clear_sender, established).await)
            }
        }
        loop {
            tokio::select! {
                biased;
                packet = cipher_receiver.recv() => {
                    let Some(packet) = packet else {
                        return Err(tls_close::<D>(connection, cipher_sender, clear_sender, established).await);
                    };
                    let detached: DetachedPacket = packet.into();
                    match detached {
                        DetachedPacket::Data(attached) => {
                            tls.push_cipher(&attached.data);
                            match tls.flush_cipher::<D>(cipher_sender, &connection).await {
                                Ok(()) => {}
                                Err(Some(signal)) => return Err(Some(signal)),
                                Err(None) => return Err(tls_close::<D>(connection, cipher_sender, clear_sender, established).await)
                            }
                            if !tls.is_handshaking() {
                                break;
                            }
                        },
                        DetachedPacket::FIN(_) => return Err(tls_close::<D>(connection, cipher_sender, clear_sender, established).await),
                        DetachedPacket::SYN(_) => {
                            tracing::debug!("Received invalid SYN packet");
                            if cipher_sender.send(D::BackwardPacket::new_fin(connection)).await.is_err() {
                                return Err(Some(Signal::SIGTERM));
                            }
                            return Err(None);
                        }
                    }
                },
                packet = clear_receiver.recv() => {
                    let Some(mut packet) = packet else {
                        return Err(tls_close::<D>(connection, cipher_sender, clear_sender, established).await);
                    };
                    if packet.is_syn() {
                        if clear_sender.send(D::ForwardPacket::new_fin(connection)).await.is_err() {
                            return Err(Some(Signal::SIGTERM));
                        }
                        return Err(None);
                    } else if packet.is_fin() {
                        return Err(tls_close::<D>(connection, cipher_sender, clear_sender, established).await);
                    } else {
                        // Keep emptied packets attached to backpressure
                        let data = std::mem::replace(packet.data_mut().expect("Clear data packet has data"), Vec::new().into_boxed_slice());
                        if tls.push_plaintext(&data).is_err() {
                            return Err(tls_close::<D>(connection, cipher_sender, clear_sender, established).await);
                        }
                        queue.push(packet);
                    }
                }
            }
        }
        tracing::debug!("Established TLS connection");
        if !is_client {
            if clear_sender.send(D::ForwardPacket::new_syn(connection.clone())).await.is_err() {
                return Err(Some(Signal::SIGTERM));
            }
            established = true;
        }
        match tls.flush::<D>(cipher_sender, clear_sender, &connection).await {
            Ok(()) => {}
            Err(Some(signal)) => return Err(Some(signal)),
            Err(None) => return Err(tls_close::<D>(connection, cipher_sender, clear_sender, established).await)
        }
        queue.clear();
        Ok(tls)
    }

    /// Actual handler of the TLS connection. Handshake + forward loop.
    #[tracing::instrument(name="tls_handler", skip_all)]
    async fn tls_handler<D: Direction>(
        connection: ConnectionToken,
        mut cipher_receiver: Receiver<D::ForwardPacket>,
        mut clear_receiver: Receiver<D::BackwardPacket>,
        cipher_sender: Sender<D::BackwardPacket>,
        clear_sender: Sender<D::ForwardPacket>,
        mode: TLSMode
    ) -> (ConnectionToken, Option<Signal>) {
        let mut tls = match tls_handshake::<D>(connection.clone(), &mut cipher_receiver, &mut clear_receiver, &cipher_sender, &clear_sender, mode).await {
            Ok(tls) => tls,
            Err(signal) => return (connection, signal)
        };
        // Established: relay transparently.
        loop {
            tokio::select! {
                biased;
                packet = cipher_receiver.recv() => {
                    let Some(packet) = packet else {
                        return (connection.clone(), tls_close::<D>(connection, &cipher_sender, &clear_sender, true).await);
                    };
                    let detached: DetachedPacket = packet.into();
                    match detached {
                        DetachedPacket::Data(attached) => {
                            tls.push_cipher(&attached.data);
                            match tls.flush::<D>(&cipher_sender, &clear_sender, &connection).await {
                                Ok(()) => {}
                                Err(Some(signal)) => return (connection, Some(signal)),
                                Err(None) => return (connection.clone(), tls_close::<D>(connection, &cipher_sender, &clear_sender, true).await)
                            }
                        },
                        DetachedPacket::FIN(_) => {
                            tls.send_close_notify();
                            let _ = tls.flush::<D>(&cipher_sender, &clear_sender, &connection).await;
                            return (connection.clone(), tls_close::<D>(connection, &cipher_sender, &clear_sender, true).await);
                        },
                        DetachedPacket::SYN(_) => {
                            tracing::debug!("Received invalid SYN packet");
                            if cipher_sender.send(D::BackwardPacket::new_fin(connection.clone())).await.is_err() {
                                return (connection, Some(Signal::SIGTERM));
                            }
                            return (connection, None);
                        }
                    }
                },
                packet = clear_receiver.recv() => {
                    let Some(packet) = packet else {
                        return (connection.clone(), tls_close::<D>(connection, &cipher_sender, &clear_sender, true).await);
                    };
                    let detached: DetachedPacket = packet.into();
                    match detached {
                        DetachedPacket::Data(attached) => {
                            if tls.push_plaintext(&attached.data).is_err() {
                                return (connection.clone(), tls_close::<D>(connection, &cipher_sender, &clear_sender, true).await);
                            }
                            match tls.flush::<D>(&cipher_sender, &clear_sender, &connection).await {
                                Ok(()) => {}
                                Err(Some(signal)) => return (connection, Some(signal)),
                                Err(None) => return (connection.clone(), tls_close::<D>(connection, &cipher_sender, &clear_sender, true).await)
                            }
                        },
                        DetachedPacket::FIN(_) => {
                            tls.send_close_notify();
                            let _ = tls.flush::<D>(&cipher_sender, &clear_sender, &connection).await;
                            return (connection.clone(), tls_close::<D>(connection, &cipher_sender, &clear_sender, true).await);
                        },
                        DetachedPacket::SYN(_) => {
                            if clear_sender.send(D::ForwardPacket::new_fin(connection.clone())).await.is_err() {
                                return (connection, Some(Signal::SIGTERM));
                            }
                            return (connection, None);
                        }
                    }
                }
            }
        }
    }
}
