#[pyo3::pymodule]
mod common {
    #[cfg(feature = "library")]
    use crate::sdk::sdk::*;
    #[cfg(not(feature = "library"))]
    use sdk::sdk::*;

    use std::{collections::HashMap, net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr}};
    use async_trait::async_trait;
    use pyo3::{pyclass, pymethods};
    use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::{TcpListener, TcpStream, UdpSocket}, sync::mpsc::{Receiver, Sender, channel}, task::JoinSet};

    /// Handler for a TCP upstream connection. Takes over the stream; Handles all SYN, read, write and FIN.
    /// 
    /// The handler does NOT check if receiver `Packet` belongs to the connection.
    async fn tcp_upstream_handler(
        stream: TcpStream,
        connection: ConnectionToken,
        sender: Sender<Packet>,
        receiver: Receiver<Packet>,
    ) -> (ConnectionToken, Option<Signal>) {
        let (mut reader, writer) = stream.into_split();
        let _ = sender.send(Packet::new(connection.clone(), Payload::SYN).await).await;
        // Separate read & write future to prevent `Packet::new` deadlock
        let write_sender = sender.clone();
        let write_connection = connection.clone();
        let mut writer_task = AbortOnDropHandle::new(tokio::spawn(async move {
            let mut writer = writer;
            let mut receiver = receiver;
            while let Some(packet) = receiver.recv().await {
                match &packet.payload {
                    Payload::SYN => {
                        let _ = write_sender.send(Packet::new(write_connection.clone(), Payload::FIN).await).await;
                        return None;
                    }
                    Payload::FIN => return None,
                    Payload::Data(data) => {
                        if writer.write_all(data).await.is_err() {
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
                read = reader.read(&mut buffer) => match read {
                    Ok(0) | Err(_) => {
                        let _ = sender.send(Packet::new(connection.clone(), Payload::FIN).await).await;
                        writer_task.abort();
                        return (connection, None);
                    }
                    Ok(count) => {
                        let data = buffer[..count].to_vec().into_boxed_slice();
                        if sender.send(Packet::new(connection.clone(), Payload::Data(data)).await).await.is_err() {
                            writer_task.abort();
                            return (connection, Some(Signal::SIGTERM));
                        }
                    }
                }
            }
        }
    }

    /// Node that listens on one TCP socket and exposes one downstream edge.
    #[pyclass]
    pub struct UpstreamTCPNode {
        downstream: NodeEndToken,
        signal_receiver: Receiver<Signal>,
        address: SocketAddr
    }

    #[pymethods]
    impl UpstreamTCPNode {
        #[new]
        #[allow(clippy::new_ret_no_self)]
        pub fn new(host: IpAddr, port: u16) -> NodeToken {
            let (signal_sender, signal_receiver) = channel(SIGNAL_BUFFER_SIZE);
            NodeToken::new(
                Box::new(Self {
                    downstream: NodeEndToken::new(),
                    signal_receiver,
                    address: SocketAddr::new(host, port)
                }),
                signal_sender
            )
        }
    }

    #[async_trait]
    impl Node for UpstreamTCPNode {
        fn upstreams(&self) -> Vec<NodeEndToken> {
            Vec::new()
        }
        fn downstreams(&self) -> Vec<NodeEndToken> {
            vec![self.downstream.clone()]
        }
        async fn run(&mut self) -> Result<Option<Signal>, &'static str> {
            let sender = self.downstream.sender().ok_or("Node is improperly connected")?;
            let mut receiver = self.downstream.receiver().map_err(|_| "End is occupied")?.ok_or("Node is improperly connected")?;
            while self.signal_receiver.try_recv().is_ok() {}
            let listener = TcpListener::bind(self.address).await.map_err(|_| "Cannot bind address")?;
            self.address = listener.local_addr().map_err(|_| "Cannot get address")?;
            #[allow(clippy::mutable_key_type)]
            let mut dispatch: HashMap<ConnectionToken, Sender<Packet>> = HashMap::new();
            let mut handlers: JoinSet<(ConnectionToken, Option<Signal>)> = JoinSet::new(); // This cancels on drop
            loop {
                tokio::select! {
                    biased;
                    signal = self.signal_receiver.recv() => match signal {
                        Some(Signal::SIGTERM) => return Ok(None),
                        None => return Err("Signal receiver is closed"),
                        _ => continue
                    },
                    handler = handlers.join_next(), if !handlers.is_empty() => match handler {
                        None => panic!("Awaiting non-empty join set that is empty"),
                        Some(Err(_)) => continue,
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
                            if let Some(sender) = dispatch.get(packet.connection()) {
                                let _ = sender.try_send(packet);
                            }
                        },
                        None => return Ok(None)
                    },
                    accepted = listener.accept() => match accepted {
                        Ok((stream, peer)) => {
                            let connection = ConnectionToken::new(Host::IpAddr(peer.ip()), Transport::TCP, peer.port());
                            let (dispatch_sender, dispatch_receiver) = channel(CONNECTION_BUFFER_SIZE);
                            dispatch.insert(connection.clone(), dispatch_sender);
                            handlers.spawn(tcp_upstream_handler(
                                stream,
                                connection,
                                sender.clone(),
                                dispatch_receiver
                            ));
                        },
                        _ => continue
                    }
                }
            }
        }
    }

    /// Node that listens on one UDP socket and exposes one downstream edge.
    #[pyclass]
    pub struct UpstreamUDPNode {
        downstream: NodeEndToken,
        signal_receiver: Receiver<Signal>,
        address: SocketAddr
    }

    #[pymethods]
    impl UpstreamUDPNode {
        #[new]
        #[allow(clippy::new_ret_no_self)]
        pub fn new(host: IpAddr, port: u16) -> NodeToken {
            let (signal_sender, signal_receiver) = channel(SIGNAL_BUFFER_SIZE);
            NodeToken::new(
                Box::new(Self {
                    downstream: NodeEndToken::new(),
                    signal_receiver,
                    address: SocketAddr::new(host, port)
                }),
                signal_sender
            )
        }
    }

    #[async_trait]
    impl Node for UpstreamUDPNode {
        fn upstreams(&self) -> Vec<NodeEndToken> {
            Vec::new()
        }
        fn downstreams(&self) -> Vec<NodeEndToken> {
            vec![self.downstream.clone()]
        }
        async fn run(&mut self) -> Result<Option<Signal>, &'static str> {
            let sender = self.downstream.sender().ok_or("Node is improperly connected")?;
            let mut receiver = self.downstream.receiver().map_err(|_| "End is occupied")?.ok_or("Node is improperly connected")?;
            while self.signal_receiver.try_recv().is_ok() {}
            let socket = UdpSocket::bind(self.address).await.map_err(|_| "Cannot bind address")?;
            let mut connections: HashMap<SocketAddr, ConnectionToken> = HashMap::new();
            let mut buffer = [0u8; PACKET_DATA_SIZE];
            loop {
                tokio::select! {
                    biased;
                    signal = self.signal_receiver.recv() => match signal {
                        Some(Signal::SIGTERM) => return Ok(None),
                        None => return Err("Signal receiver is closed"),
                        _ => continue
                    },
                    packet = receiver.recv() => match packet {
                        Some(packet) => {
                            let connection = packet.connection().clone();
                            match &packet.payload {
                                Payload::SYN => continue, // UpstreamUDPNode does not support downstream SYN
                                Payload::FIN => {
                                    if let Host::IpAddr(ip_addr) = connection.host() {
                                        let address = SocketAddr::new(ip_addr, connection.port());
                                        connections.remove(&address); // This drop closes
                                    }
                                }
                                Payload::Data(data) => {
                                    if let Host::IpAddr(ip_addr) = connection.host() {
                                        let address = SocketAddr::new(ip_addr, connection.port());
                                        socket.send_to(&data[..], address).await.map_err(|_| "UDP socket closed")?;
                                    }
                                }
                            }
                        },
                        None => return Ok(Some(Signal::SIGTERM))
                    },
                    accepted = socket.recv_from(&mut buffer) => {
                        let (count, peer) = match accepted {
                            Ok(result) => result,
                            _ => return Ok(Some(Signal::SIGTERM))
                        };
                        let connection = match connections.get(&peer) {
                            Some(connection) => connection.clone(),
                            None => {
                                let connection = ConnectionToken::new(Host::IpAddr(peer.ip()), Transport::UDP, peer.port());
                                connections.insert(peer, connection.clone());
                                connection
                            }
                        };
                        let data = buffer[..count].to_vec().into_boxed_slice();
                        if let Ok(packet) = Packet::try_new(connection, Payload::Data(data)) { // Just drop UDP, it's proper "back pressure"
                            sender.send(packet).await.map_err(|_| "Downstream closed")?; // We will await downstream to process stuff first
                        };
                    }
                }
            }
        }
    }

    /// Handler for a TCP downstream connection. Initiates the stream; Handles all read, write and FIN.
    /// 
    /// The handler does NOT check if receiver `Packet` belongs to the connection.
    async fn tcp_downstream_handler(
        connection: ConnectionToken,
        sender: Sender<Packet>,
        receiver: Receiver<Packet>,
    ) -> (ConnectionToken, Option<Signal>) {
        let stream = match connection.host() {
            Host::IpAddr(ip_addr) => Some(TcpStream::connect(SocketAddr::new(ip_addr, connection.port())).await),
            Host::Domain(domain) => Some(TcpStream::connect((domain.as_str(), connection.port())).await),
        };
        let stream = match stream {
            Some(Ok(stream)) => stream,
            _ => {
                let _ = sender.send(Packet::new(connection.clone(), Payload::FIN).await).await;
                return (connection, None);
            }
        };
        let (mut reader, writer) = stream.into_split();
        let mut writer_task = AbortOnDropHandle::new(tokio::spawn(async move {
            let mut writer = writer;
            let mut receiver = receiver;
            while let Some(packet) = receiver.recv().await {
                match &packet.payload {
                    Payload::SYN | Payload::FIN => return None,
                    Payload::Data(data) => {
                        if writer.write_all(&data[..]).await.is_err() {
                            return None;
                        }
                    }
                }
            }
            Some(Signal::SIGTERM)
        }));
        loop {
            let mut buffer = [0u8; PACKET_DATA_SIZE];
            tokio::select! {
                biased;
                result = &mut writer_task => {
                    return (connection, result.ok().flatten());
                },
                read = reader.read(&mut buffer) => match read {
                    Ok(0) | Err(_) => {
                        let _ = sender.send(Packet::new(connection.clone(), Payload::FIN).await).await;
                        writer_task.abort();
                        return (connection, None);
                    }
                    Ok(count) => {
                        let data = buffer[..count].to_vec().into_boxed_slice();
                        if sender.send(Packet::new(connection.clone(), Payload::Data(data)).await).await.is_err() {
                            writer_task.abort();
                            return (connection, Some(Signal::SIGTERM));
                        }
                    }
                }
            }
        }
    }

    /// TCP downstream node; One upstream edge.
    #[pyclass]
    pub struct DownstreamTCPNode {
        upstream: NodeEndToken,
        signal_receiver: Receiver<Signal>
    }

    #[pymethods]
    impl DownstreamTCPNode {
        #[new]
        #[allow(clippy::new_ret_no_self)]
        pub fn new() -> NodeToken {
            let (signal_sender, signal_receiver) = channel(SIGNAL_BUFFER_SIZE);
            NodeToken::new(
                Box::new(Self {
                    upstream: NodeEndToken::new(),
                    signal_receiver
                }),
                signal_sender
            )
        }
    }

    #[async_trait]
    impl Node for DownstreamTCPNode {
        fn upstreams(&self) -> Vec<NodeEndToken> {
            vec![self.upstream.clone()]
        }
        fn downstreams(&self) -> Vec<NodeEndToken> {
            Vec::new()
        }
        async fn run(&mut self) -> Result<Option<Signal>, &'static str> {
            let sender = self.upstream.sender().ok_or("Node is improperly connected")?;
            let mut receiver = self.upstream.receiver().map_err(|_| "End is occupied")?.ok_or("Node is improperly connected")?;
            while self.signal_receiver.try_recv().is_ok() {}
            #[allow(clippy::mutable_key_type)]
            let mut dispatch: HashMap<ConnectionToken, Sender<Packet>> = HashMap::new();
            let mut handlers: JoinSet<(ConnectionToken, Option<Signal>)> = JoinSet::new();
            loop {
                tokio::select! {
                    biased;
                    signal = self.signal_receiver.recv() => match signal {
                        Some(Signal::SIGTERM) => return Ok(None),
                        None => return Err("Signal receiver is closed"),
                        _ => continue
                    },
                    handler = handlers.join_next(), if !handlers.is_empty() => match handler {
                        None => panic!("Awaiting non-empty join set that is empty"),
                        Some(Err(_)) => continue,
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
                            let connection = packet.connection().clone();
                            if matches!(&packet.payload, Payload::SYN) {
                                if dispatch.contains_key(&connection) {
                                    let _ = sender.send(Packet::new(connection, Payload::FIN).await).await;
                                    continue;
                                }
                                let (dispatch_sender, dispatch_receiver) = channel(CONNECTION_BUFFER_SIZE);
                                dispatch.insert(connection.clone(), dispatch_sender);
                                handlers.spawn(tcp_downstream_handler(connection, sender.clone(), dispatch_receiver));
                            } else if let Some(dispatch_sender) = dispatch.get(&connection) {
                                let _ = dispatch_sender.send(packet).await;
                            }
                        }
                        None => return Ok(None)
                    }
                }
            }
        }
    }

    /// UDP downstream node; One upstream edge.
    /// 
    /// This node uses one ephemeral socket for each address family.
    #[pyclass]
    pub struct DownstreamUDPNode {
        upstream: NodeEndToken,
        signal_receiver: Receiver<Signal>,
        address_mode: AddressMode
    }

    #[pymethods]
    impl DownstreamUDPNode {
        #[new]
        #[allow(clippy::new_ret_no_self)]
        #[pyo3(signature=(address_mode: "v4v6"))]
        pub fn new(address_mode: AddressMode) -> NodeToken {
            let (signal_sender, signal_receiver) = channel(SIGNAL_BUFFER_SIZE);
            NodeToken::new(
                Box::new(Self {
                    upstream: NodeEndToken::new(),
                    signal_receiver,
                    address_mode
                }),
                signal_sender
            )
        }
    }

    #[async_trait]
    impl Node for DownstreamUDPNode {
        fn upstreams(&self) -> Vec<NodeEndToken> {
            vec![self.upstream.clone()]
        }
        fn downstreams(&self) -> Vec<NodeEndToken> {
            Vec::new()
        }
        async fn run(&mut self) -> Result<Option<Signal>, &'static str> {
            let sender = self.upstream.sender().ok_or("Node is improperly connected")?;
            let mut receiver = self.upstream.receiver().map_err(|_| "End is occupied")?.ok_or("Node is improperly connected")?;
            while self.signal_receiver.try_recv().is_ok() {}
            let socket_v4 = match self.address_mode {
                AddressMode::V4 | AddressMode::V4V6 => Some(UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)).await.map_err(|_| "Cannot bind ipv4 address")?),
                _ => None
            };
            let socket_v6 = match self.address_mode {
                AddressMode::V6 | AddressMode::V4V6 => Some(UdpSocket::bind(SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)).await.map_err(|_| "Cannot bind ipv6 address")?),
                _ => None
            };
            let mut connections: HashMap<SocketAddr, ConnectionToken> = HashMap::new();
            let mut buffer_v4 = [0u8; PACKET_DATA_SIZE];
            let mut buffer_v6 = [0u8; PACKET_DATA_SIZE];
            loop {
                tokio::select! {
                    biased;
                    signal = self.signal_receiver.recv() => match signal {
                        Some(Signal::SIGTERM) => return Ok(None),
                        None => return Err("Signal receiver is closed"),
                        _ => continue
                    },
                    packet = receiver.recv() => match packet {
                        Some(packet) => {
                            let connection = packet.connection().clone();
                            match &packet.payload {
                                Payload::SYN => match connection.host() {
                                    Host::IpAddr(ip_addr) => { connections.insert(SocketAddr::new(ip_addr, connection.port()), connection); },
                                    _ => continue
                                },
                                Payload::FIN => {
                                    if let Host::IpAddr(ip_addr) = connection.host() {
                                        let address = SocketAddr::new(ip_addr, connection.port());
                                        connections.remove(&address); // This drop closes
                                    };
                                },
                                Payload::Data(data) => {
                                    if let Host::IpAddr(ip_addr) = connection.host() {
                                        match ip_addr {
                                            IpAddr::V4(_) => {
                                                if let Some(socket_v4) = &socket_v4 {
                                                    let address = SocketAddr::new(ip_addr, connection.port());
                                                    socket_v4.send_to(&data[..], address).await.map_err(|_| "UDP v4 socket closed")?;
                                                };
                                            }
                                            IpAddr::V6(_) => {
                                                if let Some(socket_v6) = &socket_v6 {
                                                    let address = SocketAddr::new(ip_addr, connection.port());
                                                    socket_v6.send_to(&data[..], address).await.map_err(|_| "UDP v6 socket closed")?;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        },
                        None => return Ok(Some(Signal::SIGTERM))
                    },
                    accepted_v4 = socket_v4.as_ref().expect("Unwrapping None which is Some").recv_from(&mut buffer_v4), if socket_v4.is_some() => {
                        let (count, peer) = match accepted_v4 {
                            Ok(result) => result,
                            _ => return Ok(Some(Signal::SIGTERM))
                        };
                        let connection = match connections.get(&peer) {
                            Some(connection) => connection.clone(),
                            None => continue // Downstream does not accept incoming connection
                        };
                        let data = buffer_v4[..count].to_vec().into_boxed_slice();
                        if let Ok(packet) = Packet::try_new(connection, Payload::Data(data)) { // Just drop UDP, it's proper "back pressure"
                            sender.send(packet).await.map_err(|_| "Downstream closed")?; // We will await downstream to process stuff first
                        };
                    },
                    accepted_v6 = socket_v6.as_ref().expect("Unwrapping None which is Some").recv_from(&mut buffer_v6), if socket_v6.is_some() => {
                        let (count, peer) = match accepted_v6 {
                            Ok(result) => result,
                            _ => return Ok(Some(Signal::SIGTERM))
                        };
                        let connection = match connections.get(&peer) {
                            Some(connection) => connection.clone(),
                            None => continue // Downstream does not accept incoming connection
                        };
                        let data = buffer_v6[..count].to_vec().into_boxed_slice();
                        if let Ok(packet) = Packet::try_new(connection, Payload::Data(data)) { // Just drop UDP, it's proper "back pressure"
                            sender.send(packet).await.map_err(|_| "Downstream closed")?; // We will await downstream to process stuff first
                        };
                    }
                }
            }
        }
    }
}
