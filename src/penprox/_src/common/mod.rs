#[pyo3::pymodule]
mod common {
    #[cfg(feature = "library")]
    use crate::sdk::sdk::*;
    #[cfg(not(feature = "library"))]
    use sdk::sdk::*;

    use std::{collections::{HashMap, hash_map::RandomState}, hash::{BuildHasher, DefaultHasher, Hasher}, net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr}, pin::Pin, time::Duration};
    use async_trait::async_trait;
    use futures::future::select_all;
    use moka::future::Cache;
    use pyo3::{FromPyObject, IntoPyObject, exceptions::PyValueError, prelude::*, pyclass, pymethods};
    use simple_dns::{CLASS, Name, Packet as DNSPacket, QCLASS, QTYPE, Question, TYPE, rdata::RData};
    use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::{TcpListener, TcpStream, UdpSocket}, sync::{OwnedMutexGuard, mpsc::{Receiver, Sender, channel}}, task::JoinSet, time::{Instant, sleep_until}};

    /// Handler for a TCP connection. Dials the connection if no `stream` is
    /// given, otherwise takes over the accepted stream and announces Syn.
    /// 
    /// Handles the entire lifetime of a connection (Syn, read, write and Fin).
    /// 
    /// Unresolved domain connections are rejected. The handler does NOT check
    /// if receiver `Packet` belongs to the connection.
    async fn tcp_handler(
        stream: Option<TcpStream>,
        connection: ConnectionToken,
        sender: Sender<Packet>,
        receiver: Receiver<Packet>,
    ) -> (ConnectionToken, Option<Signal>) {
        let announce = stream.is_some();
        let stream = match stream {
            Some(stream) => stream,
            None => {
                let Host::IpAddr(ip_addr) = connection.host() else {
                    if sender.send(Packet::Fin(connection.clone())).await.is_err() {
                        return (connection, Some(Signal::SIGTERM));
                    }
                    return (connection, None);
                };
                match TcpStream::connect(SocketAddr::new(ip_addr, connection.port())).await {
                    Ok(stream) => stream,
                    Err(_) => {
                        if sender.send(Packet::Fin(connection.clone())).await.is_err() {
                            return (connection, Some(Signal::SIGTERM));
                        };
                        return (connection, None);
                    }
                }
            }
        };
        let (mut reader, writer) = stream.into_split();
        if announce && sender.send(Packet::Syn(connection.clone())).await.is_err() {
            return (connection, Some(Signal::SIGTERM));
        }
        // Separate read & write future to prevent `Packet::new` deadlock
        let writer_sender = sender.clone();
        let writer_connection = connection.clone();
        let mut writer_task = AbortOnDropHandle::new(tokio::spawn(async move {
            let mut writer = writer;
            let mut receiver = receiver;
            while let Some(packet) = receiver.recv().await {
                match packet {
                    Packet::Syn(connection) => {
                        if writer_sender.send(Packet::Fin(connection)).await.is_err() {
                            return Some(Signal::SIGTERM);
                        }
                        return None;
                    }
                    Packet::Fin(_) => return None,
                    Packet::Data(attached) => {
                        if writer.write_all(&attached.data).await.is_err() {
                            if writer_sender.send(Packet::Fin(writer_connection)).await.is_err() {
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
                read = reader.read(&mut buffer) => match read {
                    Ok(0) | Err(_) => {
                        if sender.send(Packet::Fin(connection.clone())).await.is_err() {
                            return (connection, Some(Signal::SIGTERM));
                        };
                        return (connection, None);
                    }
                    Ok(count) => {
                        let data = buffer[..count].to_vec().into_boxed_slice();
                        if sender.send(Packet::Data(connection.attach(data).await)).await.is_err() {
                            return (connection, Some(Signal::SIGTERM));
                        }
                    }
                }
            }
        }
    }

    /// Node for TCP, may listen a port. Doesn't support DNS.
    ///
    /// When provided `(ip, port)`, the node is in upstream mode:
    /// - The node listens to the port.
    /// - It has one downstream, no upstream.
    /// - It does not support downstream SYNs.
    /// 
    /// When provided `None`, the node is in downstream mode:
    /// - It has one upstream, no downstream.
    #[pyclass]
    pub struct TCPNode {
        node_end: NodeEndToken,
        signal_receiver: Receiver<Signal>,
        address: Option<SocketAddr>
    }

    #[pymethods]
    impl TCPNode {
        #[new]
        #[pyo3(signature = (address = None))]
        #[allow(clippy::new_ret_no_self)]
        pub fn new(address: Option<(IpAddr, u16)>) -> NodeToken {
            let (signal_sender, signal_receiver) = channel(SIGNAL_BUFFER_SIZE);
            NodeToken::new(
                Box::new(Self {
                    node_end: NodeEndToken::new(),
                    signal_receiver,
                    address: address.map(|(host, port)| SocketAddr::new(host, port))
                }),
                signal_sender
            )
        }
    }

    #[async_trait]
    impl Node for TCPNode {
        fn upstreams(&self) -> Vec<NodeEndToken> {
            match self.address {
                Some(_) => Vec::new(),
                None => vec![self.node_end.clone()]
            }
        }
        fn downstreams(&self) -> Vec<NodeEndToken> {
            match self.address {
                Some(_) => vec![self.node_end.clone()],
                None => Vec::new()
            }
        }
        async fn run(&mut self) -> Result<Option<Signal>, &'static str> {
            let sender = self.node_end.sender().ok_or("Node is improperly connected")?;
            let mut receiver = self.node_end.receiver().map_err(|_| "End is occupied")?.ok_or("Node is improperly connected")?;
            self.signal_receiver.drain();
            match self.address {
                Some(address) => { // TCPNode: upstream mode
                    let listener = TcpListener::bind(address).await.map_err(|_| "Cannot bind address")?;
                    self.address = Some(listener.local_addr().map_err(|_| "Cannot get address")?);
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
                                None => unreachable!("Awaiting non-empty join set that is empty"),
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
                                    if let Some(handler) = dispatch.get(packet.connection()) {
                                        let _ = handler.send(packet).await; // No good countermeasure for this never condition
                                    }
                                },
                                None => return Ok(None)
                            },
                            accepted = listener.accept() => match accepted {
                                Ok((stream, peer)) => {
                                    let connection = ConnectionToken::new(Host::IpAddr(peer.ip()), Transport::TCP, peer.port());
                                    let (dispatch_sender, dispatch_receiver) = channel(CONNECTION_BUFFER_SIZE);
                                    dispatch.insert(connection.clone(), dispatch_sender);
                                    handlers.spawn(tcp_handler(
                                        Some(stream),
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
                None => { // TCPNode: downstream mode
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
                                None => unreachable!("Awaiting non-empty join set that is empty"),
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
                                    if let Packet::Syn(connection) = &packet {
                                        if let Some(handler) = dispatch.get(connection) {
                                            let _ = handler.send(Packet::Fin(connection.clone())).await;
                                            if sender.send(Packet::Fin(connection.clone())).await.is_err() {
                                                return Err("End closed");
                                            };
                                            continue;
                                        }
                                        let (dispatch_sender, dispatch_receiver) = channel(CONNECTION_BUFFER_SIZE);
                                        dispatch.insert(connection.clone(), dispatch_sender);
                                        handlers.spawn(tcp_handler(None, connection.clone(), sender.clone(), dispatch_receiver));
                                    } else {
                                        match dispatch.get(&connection) {
                                            Some(handler) => {
                                                let _ = handler.send(packet).await;
                                            },
                                            None => if sender.send(Packet::Fin(connection)).await.is_err() {
                                                return Err("End closed");
                                            }
                                        };
                                    }
                                }
                                None => return Ok(None)
                            }
                        }
                    }
                }
            }
        }
    }

    #[derive(Clone, Copy, FromPyObject)]
    pub enum UDPNodeMode {
        Upstream(IpAddr, u16),
        Downstream(AddressMode)
    }

    /// Node for UDP, may bind a port. Doesn't support DNS.
    ///
    /// When provided `(ip, port)`, the node is in upstream mode:
    /// - The node listens to the port.
    /// - It has one downstream, no upstream.
    /// - It does not support downstream SYNs.
    /// 
    /// When provided `V4V6 | V6V4 | V4 | V6`, the node is in downstream mode:
    /// - It binds ephemeral v4 | v6 | v4&v6 port(s). (`V4V6` and `V6V4` are treated the same here).
    /// - It has one upstream, no downstream.
    #[pyclass]
    pub struct UDPNode {
        node_end: NodeEndToken,
        signal_receiver: Receiver<Signal>,
        mode: UDPNodeMode
    }

    #[pymethods]
    impl UDPNode {
        #[new]
        #[pyo3(signature = (mode = UDPNodeMode::Downstream(AddressMode::V4V6)))]
        #[allow(clippy::new_ret_no_self)]
        pub fn new(mode: UDPNodeMode) -> NodeToken {
            let (signal_sender, signal_receiver) = channel(SIGNAL_BUFFER_SIZE);
            NodeToken::new(
                Box::new(Self {
                    node_end: NodeEndToken::new(),
                    signal_receiver,
                    mode
                }),
                signal_sender
            )
        }
    }

    #[async_trait]
    impl Node for UDPNode {
        fn upstreams(&self) -> Vec<NodeEndToken> {
            match self.mode {
                UDPNodeMode::Upstream(_, _) => Vec::new(),
                UDPNodeMode::Downstream(_) => vec![self.node_end.clone()]
            }
        }
        fn downstreams(&self) -> Vec<NodeEndToken> {
            match self.mode {
                UDPNodeMode::Upstream(_, _) => vec![self.node_end.clone()],
                UDPNodeMode::Downstream(_) => Vec::new()
            }
        }
        async fn run(&mut self) -> Result<Option<Signal>, &'static str> {
            let sender = self.node_end.sender().ok_or("Node is improperly connected")?;
            let mut receiver = self.node_end.receiver().map_err(|_| "End is occupied")?.ok_or("Node is improperly connected")?;
            self.signal_receiver.drain();
            let mode = self.mode;
            let (socket_v4, socket_v6) = match mode {
                UDPNodeMode::Upstream(host, port) => {
                    let socket = UdpSocket::bind(SocketAddr::new(host, port)).await.map_err(|_| "Cannot bind address")?;
                    match host {
                        IpAddr::V4(_) => (Some(socket), None),
                        IpAddr::V6(_) => (None, Some(socket))
                    }
                }
                UDPNodeMode::Downstream(address_mode) => {
                    let socket_v4 = match address_mode {
                        AddressMode::V6 => None,
                        _ => Some(UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)).await.map_err(|_| "Cannot bind ipv4 address")?),
                        
                    };
                    let socket_v6 = match address_mode {
                        AddressMode::V4 => None,
                        _ => Some(UdpSocket::bind(SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)).await.map_err(|_| "Cannot bind ipv6 address")?),
                    };
                    (socket_v4, socket_v6)
                }
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
                        Some(Packet::Syn(connection)) => {
                            if matches!(mode, UDPNodeMode::Upstream(..)) {
                                if sender.send(Packet::Fin(connection)).await.is_err() {
                                    return Err("End closed");
                                };
                                continue;
                            }
                            match connection.host() {
                                Host::Domain(_) => if sender.send(Packet::Fin(connection)).await.is_err() {
                                    return Err("End closed");
                                },
                                Host::IpAddr(ip_addr) => { connections.insert(SocketAddr::new(ip_addr, connection.port()), connection); }
                            };
                        }
                        Some(Packet::Fin(connection)) => {
                            if let Host::IpAddr(ip_addr) = connection.host() {
                                connections.remove(&SocketAddr::new(ip_addr, connection.port()));
                            }
                        },
                        Some(Packet::Data(attached)) => {
                            match attached.connection().host() {
                                Host::Domain(_) => if sender.send(Packet::Fin(attached.connection().clone())).await.is_err() {
                                    return Err("End closed");
                                },
                                Host::IpAddr(ip_addr) => {
                                    let socket = match ip_addr {
                                        IpAddr::V4(_) => socket_v4.as_ref(),
                                        IpAddr::V6(_) => socket_v6.as_ref()
                                    };
                                    if let Some(socket) = socket {
                                        socket.send_to(&attached.data[..], SocketAddr::new(ip_addr, attached.connection().port())).await.map_err(|_| "UDP socket closed")?;
                                    };
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
                            None => {
                                if matches!(mode, UDPNodeMode::Downstream(..)) {
                                    continue;
                                };
                                let connection = ConnectionToken::new(Host::IpAddr(peer.ip()), Transport::UDP, peer.port());
                                if sender.send(Packet::Syn(connection.clone())).await.is_err() {
                                    return Err("End closed");
                                };
                                connections.insert(peer, connection.clone());
                                connection
                            }
                        };
                        let data = buffer_v4[..count].to_vec().into_boxed_slice();
                        if let Ok(attached) = connection.try_attach(data) { // Just drop UDP, it's proper "back pressure"
                            sender.send(Packet::Data(attached)).await.map_err(|_| "End closed")?;
                        }
                    },
                    accepted_v6 = socket_v6.as_ref().expect("Unwrapping None which is Some").recv_from(&mut buffer_v6), if socket_v6.is_some() => {
                        let (count, peer) = match accepted_v6 {
                            Ok(result) => result,
                            _ => return Ok(Some(Signal::SIGTERM))
                        };
                        let connection = match connections.get(&peer) {
                            Some(connection) => connection.clone(),
                            None => {
                                if matches!(mode, UDPNodeMode::Downstream(..)) {
                                    continue;
                                };
                                let connection = ConnectionToken::new(Host::IpAddr(peer.ip()), Transport::UDP, peer.port());
                                if sender.send(Packet::Syn(connection.clone())).await.is_err() {
                                    return Err("End Closed");
                                };
                                connections.insert(peer, connection.clone());
                                connection
                            }
                        };
                        let data = buffer_v6[..count].to_vec().into_boxed_slice();
                        if let Ok(attached) = connection.try_attach(data) { // Just drop UDP, it's proper "back pressure"
                            sender.send(Packet::Data(attached)).await.map_err(|_| "End closed")?;
                        }
                    }
                }
            }
        }
    }

    /// Python arg type
    #[pyclass(skip_from_py_object)]
    #[derive(Clone, Copy)]
    enum ChannelType {
        Signal,
        Upstream,
        Downstream
    }

    /// Python arg type
    #[derive(IntoPyObject)]
    enum DetachedPacketSignalError {
        DetachedPacket(DetachedPacket),
        Signal(Signal),
        Error(())
    }

    /// Python return type
    #[derive(FromPyObject)]
    enum PythonCallbackReturnCode {
        Control(bool),
        Signal(Signal)
    }

    #[pyclass]
    pub struct PythonNode {
        pub upstreams: Vec<NodeEndToken>,
        pub downstreams: Vec<NodeEndToken>,
        pub signal_receiver: Receiver<Signal>,
        pub callback: Py<PyAny>
    }

    impl PythonNode {
        #[allow(clippy::new_ret_no_self)]
        pub fn new<'py>(callback: Bound<'py, PyAny>, upstreams: usize, downstreams: usize) -> Result<NodeToken, &'static str> {
            if !callback.is_callable() {
                return Err("Callback not callable");
            }
            let mut u = Vec::with_capacity(upstreams);
            let mut d = Vec::with_capacity(downstreams);
            u.resize_with(upstreams, NodeEndToken::new);
            d.resize_with(downstreams, NodeEndToken::new);
            let (signal_sender, signal_receiver) = channel(SIGNAL_BUFFER_SIZE);
            Ok(NodeToken::new(
                Box::new(Self {
                    upstreams: u,
                    downstreams: d,
                    signal_receiver,
                    callback: callback.unbind()
                }),
                signal_sender)
            )
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
        fn upstreams(&self) -> Vec<NodeEndToken> {
            self.upstreams.clone()
        }
        fn downstreams(&self) -> Vec<NodeEndToken> {
            self.downstreams.clone()
        }
        async fn run(&mut self) -> Result<Option<Signal>, &'static str> {
            let mut upstreams = Vec::with_capacity(self.upstreams.len());
            for upstream in &mut self.upstreams {
                upstreams.push(upstream.receiver().map_err(|_| "End is occupied")?.ok_or("Node is improperly connected")?);
            }
            let mut downstreams = Vec::with_capacity(self.downstreams.len());
            for downstream in &mut self.downstreams {
                downstreams.push(downstream.receiver().map_err(|_| "End is occupied")?.ok_or("Node is improperly connected")?);
            }
            loop {
                let (channel_type, index, outcome) = {
                    let mut node_ends: Vec<Pin<Box<dyn Future<Output = (ChannelType, usize, DetachedPacketSignalError)> + Send + '_>>> = Vec::with_capacity(upstreams.len() + downstreams.len());
                    for (index, receiver) in upstreams.iter_mut().enumerate() {
                        node_ends.push(Box::pin(async move {
                            match receiver.recv().await {
                                Some(packet) => (ChannelType::Upstream, index, DetachedPacketSignalError::DetachedPacket(packet.detach())),
                                None => (ChannelType::Upstream, index, DetachedPacketSignalError::Error(()))
                            }
                        }));
                    }
                    for (index, receiver) in downstreams.iter_mut().enumerate() {
                        node_ends.push(Box::pin(async move {
                            match receiver.recv().await {
                                Some(packet) => (ChannelType::Downstream, index, DetachedPacketSignalError::DetachedPacket(packet.detach())),
                                None => (ChannelType::Downstream, index, DetachedPacketSignalError::Error(()))
                            }
                        }));
                    }
                    if node_ends.is_empty() {
                        match self.signal_receiver.recv().await {
                            Some(signal) => (ChannelType::Signal, 0, DetachedPacketSignalError::Signal(signal)),
                            None => return Err("Signal handle closed")
                        }
                    } else {
                        tokio::select! {
                            biased;
                            signal = self.signal_receiver.recv() => match signal {
                                Some(signal) => (ChannelType::Signal, 0, DetachedPacketSignalError::Signal(signal)),
                                None => return Err("Signal handle closed")
                            },
                            packet = select_all(node_ends) => packet.0, // Cancel safe
                        }
                    }
                };
                if matches!(&outcome, DetachedPacketSignalError::Error(())) {
                    return Err("End is closed");
                }
                let result = Python::attach(|py| {
                    let channel_type = Py::new(py, channel_type)?;
                    let object = self.callback.call1(py, (channel_type, index, outcome))?;
                    object.bind(py).extract::<PythonCallbackReturnCode>()
                });
                match result {
                    Ok(PythonCallbackReturnCode::Control(false)) => continue,
                    Ok(PythonCallbackReturnCode::Control(true)) => return Ok(None),
                    Ok(PythonCallbackReturnCode::Signal(signal)) => return Ok(Some(signal)),
                    _ => return Ok(Some(Signal::SIGTERM)),
                }
            }
        }
    }

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
            self.counter += 0x9e3779b97f4a7c15_usize;
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
        blocked: &mut HashMap<ConnectionToken, Vec<Packet>>,
        upstream_sender: &Sender<Packet>
    ) -> bool {
        for connection in waiters {
            blocked.remove(&connection); // Drops packets
            let packet = Packet::Fin(connection);
            if upstream_sender.send(packet).await.is_err() {
                return true;
            }
        }
        false
    }

    /// Stateless wrapper of resolver downstream.
    /// (The user must manage connection state by themselves.)
    enum DNSResolver {
        Socket(UdpSocket),
        End(Sender<Packet>, OwnedMutexGuard<Receiver<Packet>>, ConnectionToken)
    }

    struct DNSQuery<'a> {
        name: &'a str,
        qtypes: &'a [TYPE],
        id: u16 // id is just for security, removable if we're fine being attacked
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
                    let count = socket.recv(dns_buffer).await.map_err(|_| Some(Signal::SIGTERM))?;
                    DNSPacket::parse(&dns_buffer[..count]).map_err(|_| None)?
                },
                DNSResolver::End(_, receiver, _) => {
                    let Packet::Data(attached) = receiver.recv().await.ok_or(Signal::SIGTERM)? else {
                        return Err(Some(Signal::SIGTERM));
                    };
                    box_buffer = attached.detach().data;
                    DNSPacket::parse(&box_buffer).map_err(|_| None)?
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
                    _ => {}
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
                    let name = Name::new(query.name).map_err(|_| None)?;
                    let mut packet = DNSPacket::new_query(query.id);
                    packet.questions.push(Question::new(name, (*qtype).into(), QCLASS::CLASS(CLASS::IN), false));
                    packet.build_bytes_vec_compressed().map_err(|_| Signal::SIGTERM)? // Not very sure why this is Result
                };
                match self {
                    DNSResolver::Socket(socket) => {
                        socket.send(&data).await.map_err(|_| Some(Signal::SIGTERM))?;
                    }
                    DNSResolver::End(sender, _, connection) => {
                        let attached = connection.attach(data.into_boxed_slice()).await;
                        sender.send(Packet::Data(attached)).await.map_err(|_| Some(Signal::SIGTERM))?;
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

    #[pyclass]
    pub struct DNSNode {
        upstream: NodeEndToken,
        downstream: NodeEndToken,
        resolver_downstream: Option<NodeEndToken>,
        signal_receiver: Receiver<Signal>,
        resolver: SocketAddr,
        mode: AddressMode,
        cname_cache: Cache<String, String>,
        address_cache: Cache<String, Option<IpAddr>>
    }

    impl DNSNode {
        #[allow(clippy::new_ret_no_self)]
        // Port is deferred to match python_new signature
        // In rust you have to specify every arg anyway though
        pub fn new(mut resolver: Host, port: u16, middleware: bool, mode: AddressMode, size: u64, ttl: Duration) -> Result<NodeToken, &'static str> {
            let Some(resolver) = resolver.wait_resolve() else {
                return Err("Invalid host");
            };
            let (signal_sender, signal_receiver) = channel(SIGNAL_BUFFER_SIZE);
            Ok(NodeToken::new(
                Box::new(Self {
                    upstream: NodeEndToken::new(),
                    downstream: NodeEndToken::new(),
                    resolver_downstream: match middleware {
                        true => None,
                        false => Some(NodeEndToken::new())
                    },
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
                signal_sender
            ))
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
                return Err(PyValueError::new_err("Invalid TTL"));
            }
            Self::new(resolver, port, middleware, mode, size, Duration::from_secs_f64(ttl)).map_err(PyValueError::new_err)
        }
    }

    #[async_trait]
    impl Node for DNSNode {
        fn upstreams(&self) -> Vec<NodeEndToken> {
            vec![self.upstream.clone()]
        }
        fn downstreams(&self) -> Vec<NodeEndToken> {
            match self.resolver_downstream.clone() {
                None => vec![self.downstream.clone()],
                Some(end) => vec![self.downstream.clone(), end]
            }
        }
        async fn run(&mut self) -> Result<Option<Signal>, &'static str> {
            let upstream_sender = self.upstream.sender().ok_or("Node is improperly connected")?;
            let mut upstream_receiver = self.upstream.receiver().map_err(|_| "End is occupied")?.ok_or("Node is improperly connected")?;
            let downstream_sender = self.downstream.sender().ok_or("Node is improperly connected")?;
            let mut downstream_receiver = self.downstream.receiver().map_err(|_| "End is occupied")?.ok_or("Node is improperly connected")?;
            let mut resolver = match &self.resolver_downstream {
                None => {
                    let socket = match self.resolver {
                        SocketAddr::V4(_) => UdpSocket::bind("0.0.0.0:0").await.map_err(|_| "Cannot bind v4 UDP port")?,
                        SocketAddr::V6(_) => UdpSocket::bind("[::]:0").await.map_err(|_| "Cannot bind v6 UDP port")?
                    };
                    socket.connect(self.resolver).await.map_err(|_| "Cannot connect to resolver")?;
                    DNSResolver::Socket(socket)
                },
                Some(end) => {
                    let resolver_sender = end.sender().ok_or("Node is improperly connected")?;
                    let resolver_receiver = end.receiver().map_err(|_| "End is occupied")?.ok_or("Node is improperly connected")?;
                    let resolver_connection = ConnectionToken::new(Host::IpAddr(self.resolver.ip()), Transport::UDP, self.resolver.port());
                    if resolver_sender.send(Packet::Syn(resolver_connection.clone())).await.is_err() {
                        return Err("End closed");
                    }
                    DNSResolver::End(resolver_sender, resolver_receiver, resolver_connection)
                }
            };
            self.signal_receiver.drain();
            let qtypes: &[TYPE] = match self.mode {
                AddressMode::V4 => &[TYPE::A],
                AddressMode::V6 => &[TYPE::AAAA],
                AddressMode::V4V6 => &[TYPE::A, TYPE::AAAA],
                AddressMode::V6V4 => &[TYPE::AAAA, TYPE::A]
            };
            let cname_cache = self.cname_cache.clone();
            let address_cache = self.address_cache.clone();
            #[allow(clippy::mutable_key_type)]
            let mut blocked: HashMap<ConnectionToken, Vec<Packet>> = HashMap::new();
            let mut resolving: HashMap<String, Resolution> = HashMap::new();
            let mut dns_buffer = [0u8; DNS_BUFFER_SIZE];
            let mut dns_nonce = DNSNonce::new();
            
            loop {
                let deadline = resolving.values().map(|resolution| resolution.deadline).min();
                tokio::select! {
                    biased;
                    signal = self.signal_receiver.recv() => match signal {
                        Some(Signal::SIGTERM) => return Ok(None),
                        None => return Err("Signal receiver is closed"),
                        _ => continue
                    },
                    packet = upstream_receiver.recv() => match packet {
                        Some(packet) => {
                            let connection = packet.connection().clone();
                            if matches!(packet, Packet::Syn(_)) && !connection.is_resolved() {
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
                                        if downstream_sender.send(packet).await.is_err() {
                                            return Ok(Some(Signal::SIGTERM));
                                        }
                                    }
                                    Some(None) => { // Negative cache hit
                                        if upstream_sender.send(Packet::Fin(connection.clone())).await.is_err() {
                                            return Err("End closed");
                                        }
                                    }
                                    None => {
                                        let Some(name) = terminal else { // CNAME exhaustion (Only reachable by cycle)
                                            if upstream_sender.send(Packet::Fin(connection.clone())).await.is_err() {
                                                return Err("End closed");
                                            }
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
                            } else if downstream_sender.send(packet).await.is_err() {
                                return Ok(Some(Signal::SIGTERM));
                            }
                        },
                        None => return Err("End")
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
                                        if downstream_sender.send(packet).await.is_err() {
                                            return Ok(Some(Signal::SIGTERM));
                                        }
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
}
