#[pyo3::pymodule]
pub mod sdk {
    use std::{collections::HashMap, hash::{Hash, Hasher}, net::{IpAddr, ToSocketAddrs}, pin::Pin, ptr, sync::{Arc, Mutex as MutexStd, OnceLock}, task::{Context, Poll}};
    use async_trait::async_trait;
    use pyo3::{Borrowed, FromPyObject, IntoPyObject, IntoPyObjectExt, PyErr, PyResult, exceptions::{PyBufferError, PyEOFError, PyRuntimeError, PyValueError}, prelude::*, pyclass, pymethods, types::{PyBytes, PyString}};
    use tokio::{sync::{Mutex, OwnedMutexGuard, Semaphore, TryLockError, mpsc::{Receiver, Sender, channel, error::TrySendError}}, task::{AbortHandle, JoinHandle, JoinSet}};

    pub const PACKET_BUFFER_SIZE: usize = 64;
    pub const SIGNAL_BUFFER_SIZE: usize = 8;
    #[pymodule_export]
    pub const PACKET_DATA_SIZE: usize = 2048;
    /// Maximum amount of data packets a connection can safely buffer.
    pub const CONNECTION_BUFFER_SIZE: usize = 64;

    #[derive(FromPyObject, IntoPyObject, Clone)]
    pub enum Host {
        Domain(String),
        IpAddr(IpAddr)
    }

    impl Host {
        /// Config util for simple blocking system DNS lookup.
        /// 
        /// `None` only when the host remains unresolvable domain.
        pub fn wait_resolve(&mut self) -> Option<IpAddr> {
            match self {
                Host::Domain(domain) => match (domain.as_str(), 80).to_socket_addrs() {
                    Ok(socket_addrs) => {
                        match socket_addrs.into_iter().next() {
                            Some(socket_addr) => {
                                let ip_addr = socket_addr.ip();
                                *self = Host::IpAddr(ip_addr);
                                Some(ip_addr)
                            },
                            _ => None
                        }
                    },
                    _ => None
                }
                Host::IpAddr(ip_addr) => Some(*ip_addr)
            }
        }
    }

    #[derive(Clone, Copy)]
    pub enum Transport {
        TCP,
        UDP
    }

    impl<'a, 'py> FromPyObject<'a, 'py> for Transport {
        type Error = PyErr;
        fn extract(obj: Borrowed<'a, 'py, PyAny>) -> PyResult<Self> {
            match obj.cast::<PyString>() {
                Ok(obj) => match obj.to_str() {
                    Ok("TCP") => Ok(Transport::TCP),
                    Ok("UDP") => Ok(Transport::UDP),
                    _ => Err(PyValueError::new_err("Invalid Value"))
                },
                _ => Err(PyValueError::new_err("Invalid Value"))
            }
        }
    }

    impl<'py> IntoPyObject<'py> for Transport {
        type Error = PyErr;
        type Target = PyAny;
        type Output = Bound<'py, Self::Target>;
        fn into_pyobject(self, py: Python<'py>) -> Result<Self::Output, Self::Error> {
            match self {
                Transport::TCP => Ok(PyString::new(py, "TCP").into_any()),
                Transport::UDP => Ok(PyString::new(py, "UDP").into_any()),
            }
        }
    }

    struct Connection {
        domain: Option<String>,
        ip: OnceLock<IpAddr>,
        transport: Transport,
        port: u16,
        buffer: Semaphore
    }

    /// General representation of a connection.
    /// 
    /// The endpoint (host, transport, port) has node-dependent meaning:
    /// - For inbound network connection, the host is remote source.
    /// - For outbound network connection, the host is remote destination.
    /// - For proxied connection, the host is the intended proxy destination.
    /// 
    /// Notice that this is purely semantic, and is not enforced by any static or runtime measure.
    /// This is to reduce complexity and enable certain flexible runtime behaviour,
    /// like directly passing a proxied connection to network endpoint (thus exit).
    #[pyclass(from_py_object, frozen, eq, hash, name="Connection")]
    #[derive(Clone)]
    pub struct ConnectionToken(Arc<Connection>);

    impl Eq for ConnectionToken {}
    impl PartialEq for ConnectionToken {
        #[allow(clippy::ptr_eq)]
        fn eq(&self, other: &Self) -> bool {
            self.0.as_ref() as *const Connection as usize == other.0.as_ref() as *const Connection as usize
        }
    }
    impl Hash for ConnectionToken {
        fn hash<H: Hasher>(&self, state: &mut H) {
            state.write_usize(self.0.as_ref() as *const Connection as usize);
        }
    }

    impl ConnectionToken {
        pub fn is_resolved(&self) -> bool {
            self.0.ip.get().is_some()
        }
    }

    #[pymethods]
    impl ConnectionToken {
        /// Set IP.
        /// 
        /// Fails silently if IP is already set.
        pub fn resolve(&self, ip_addr: IpAddr) {
            let _ = self.0.ip.set(ip_addr);
        }
        #[new]
        pub fn new(host: Host, transport: Transport, port: u16) -> Self {
            match host {
                Host::Domain(domain) => Self(Arc::new(Connection {
                    domain: Some(domain),
                    ip: OnceLock::new(),
                    transport,
                    port,
                    buffer: Semaphore::new(CONNECTION_BUFFER_SIZE)
                })),
                Host::IpAddr(ip_addr) => Self(Arc::new(Connection {
                    domain: None,
                    ip: OnceLock::from(ip_addr),
                    transport,
                    port,
                    buffer: Semaphore::new(CONNECTION_BUFFER_SIZE)
                }))
            }
        }
        #[getter]
        pub fn host(&self) -> Host {
            match self.0.ip.get() {
                Some(ip_addr) => Host::IpAddr(*ip_addr),
                None => Host::Domain(self.0.domain.clone().expect("Connection has no host"))
            }
        }
        #[getter]
        pub fn transport(&self) -> Transport {
            self.0.transport
        }
        #[getter]
        pub fn port(&self) -> u16 {
            self.0.port
        }
    }

    pub struct ConnectionAttached {
        connection: ConnectionToken,
        pub data: Box<[u8]>
    }

    impl Drop for ConnectionAttached {
        fn drop(&mut self) {
            self.connection.0.buffer.add_permits(1);
        }
    }

    impl ConnectionToken {
        pub async fn attach(&self, data: Box<[u8]>) -> ConnectionAttached {
            self.0.buffer.acquire().await.expect("Semaphore was closed").forget();
            ConnectionAttached {
                connection: self.clone(),
                data
            }
        }
        pub fn try_attach(&self, data: Box<[u8]>) -> Result<ConnectionAttached, Box<[u8]>> {
            match self.0.buffer.try_acquire() {
                Ok(permit) => {
                    permit.forget();
                    Ok(ConnectionAttached {
                        connection: self.clone(),
                        data
                    })
                },
                Err(_) => Err(data)
            }
        }
    }

    impl ConnectionAttached {
        pub fn connection(&self) -> &ConnectionToken {
            &self.connection
        }
        pub fn detach(self) -> ConnectionDetached {
            let wrapper = std::mem::ManuallyDrop::new(self);
            wrapper.connection.0.buffer.add_permits(1);
            ConnectionDetached {
                connection: unsafe { ptr::read(&wrapper.connection) },
                data: unsafe { ptr::read(&wrapper.data) }
            }
        }
    }

    #[derive(Clone)]
    pub struct ConnectionDetached {
        pub connection: ConnectionToken,
        pub data: Box<[u8]>
    }

    impl ConnectionDetached {
        pub fn new(connection: ConnectionToken, data: Box<[u8]>) -> Self {
            Self {
                connection,
                data
            }
        }
        pub async fn attach(self) -> ConnectionAttached {
            self.connection.0.buffer.acquire().await.expect("Semaphore was closed").forget();
            ConnectionAttached {
                connection: self.connection,
                data: self.data
            }
        }
        pub fn try_attach(self) -> Result<ConnectionAttached, Self> {
            let result = {
                match self.connection.0.buffer.try_acquire() {
                    Ok(permit) => {
                        permit.forget();
                        true
                    },
                    Err(_) => false
                }
            };
            match result {
                true => Ok(ConnectionAttached {
                    connection: self.connection,
                    data: self.data
                }),
                false => Err(self)
            }
        }
    }

    pub enum Packet {
        Syn(ConnectionToken),
        Data(ConnectionAttached),
        Fin(ConnectionToken)
    }

    impl Packet {
        pub fn detach(self) -> DetachedPacket {
            match self {
                Packet::Syn(connection) => DetachedPacket::Syn(connection),
                Packet::Data(attached) => DetachedPacket::Data(attached.detach()),
                Packet::Fin(connection) => DetachedPacket::Fin(connection)
            }
        }
        pub fn clone_detached(&self) -> DetachedPacket {
            match self {
                Packet::Syn(connection) => DetachedPacket::Syn(connection.clone()),
                Packet::Data(attached) => DetachedPacket::Data(ConnectionDetached {
                    connection: attached.connection().clone(),
                    data: attached.data.clone()
                }),
                Packet::Fin(connection) => DetachedPacket::Fin(connection.clone())
            }
        }
        pub fn connection(&self) -> &ConnectionToken {
            match self {
                Packet::Syn(token) => token,
                Packet::Data(attached) => attached.connection(),
                Packet::Fin(token) => token
            }
        }
        pub fn is_syn(&self) -> bool {
            matches!(self, Self::Syn(_))
        }
        pub fn is_data(&self) -> bool {
            matches!(self, Self::Data(_))
        }
        pub fn is_fin(&self) -> bool {
            matches!(self, Self::Fin(_))
        }
    }

    #[derive(Clone)]
    pub enum DetachedPacket {
        Syn(ConnectionToken),
        Data(ConnectionDetached),
        Fin(ConnectionToken)
    }

    impl DetachedPacket {
        pub async fn attach(self) -> Packet {
            match self {
                Self::Syn(connection) => Packet::Syn(connection),
                Self::Data(detached) => Packet::Data(detached.attach().await),
                Self::Fin(connection) => Packet::Fin(connection)
            }
        }
        pub fn try_attach(self) -> Result<Packet, Self> {
            match self {
                Self::Syn(connection) => Ok(Packet::Syn(connection)),
                Self::Data(detached) => match detached.try_attach() {
                    Ok(attached) => Ok(Packet::Data(attached)),
                    Err(detached) => Err(Self::Data(detached))
                },
                Self::Fin(connection) => Ok(Packet::Fin(connection))
            }
        }
        pub fn connection(&self) -> &ConnectionToken {
            match self {
                DetachedPacket::Syn(token) => token,
                DetachedPacket::Data(attached) => &attached.connection,
                DetachedPacket::Fin(token) => token
            }
        }
        pub fn is_syn(&self) -> bool {
            matches!(self, Self::Syn(_))
        }
        pub fn is_data(&self) -> bool {
            matches!(self, Self::Data(_))
        }
        pub fn is_fin(&self) -> bool {
            matches!(self, Self::Fin(_))
        }
    }

    impl<'a, 'py> FromPyObject<'a, 'py> for DetachedPacket {
        type Error = PyErr;
        fn extract(obj: Borrowed<'a, 'py, PyAny>) -> PyResult<Self> {
            match obj.extract::<PyPacket>() {
                Ok(obj) => match obj.payload {
                    PyPayload::Syn => Ok(DetachedPacket::Syn(obj.connection)),
                    PyPayload::Data(data) => Ok(DetachedPacket::Data(ConnectionDetached { connection: obj.connection, data })),
                    PyPayload::Fin => Ok(DetachedPacket::Fin(obj.connection))
                },
                _ => Err(PyValueError::new_err("Invalid packet"))
            }
        }
    }

    impl<'py> IntoPyObject<'py> for DetachedPacket {
        type Error = PyErr;
        type Target = PyAny;
        type Output = Bound<'py, Self::Target>;
        fn into_pyobject(self, py: Python<'py>) -> Result<Self::Output, Self::Error> {
            let py_packet = match self {
                Self::Syn(connection) => PyPacket {
                    connection,
                    payload: PyPayload::Syn
                },
                Self::Data(detached) => PyPacket {
                    connection: detached.connection,
                    payload: PyPayload::Data(detached.data)
                },
                Self::Fin(connection) => PyPacket {
                    connection,
                    payload: PyPayload::Fin
                }
            };
            py_packet.into_bound_py_any(py)
        }
    }

    /// Internal python payload type, as native `"Syn" | "Fin" | bytes`.
    /// 
    /// This type already checks `PACKET_DATA_SIZE` on boundary.
    #[derive(Clone)]
    enum PyPayload {
        Syn,
        Data(Box<[u8]>),
        Fin
    }

    impl<'a, 'py> FromPyObject<'a, 'py> for PyPayload {
        type Error = PyErr;
        fn extract(obj: Borrowed<'a, 'py, PyAny>) -> PyResult<Self> {
            if let Ok(obj) = obj.cast::<PyString>() {
                return match obj.to_str() {
                    Ok("Syn") => Ok(Self::Syn),
                    Ok("Fin") => Ok(Self::Fin),
                    _ => Err(PyValueError::new_err("Invalid flag string. Did you mean bytes?"))
                }
            };
            match obj.cast::<PyBytes>() {
                Ok(obj) => {
                    if obj.len().expect("bytes object has no len") > PACKET_DATA_SIZE {
                        return Err(PyValueError::new_err(format!("Packet payload too long. Maximum {} bytes.", PACKET_DATA_SIZE)));
                    };
                    Ok(Self::Data(Box::from(obj.as_bytes())))
                },
                _ => Err(PyValueError::new_err("Invalid Value"))
            }
        }
    }

    impl<'py> IntoPyObject<'py> for PyPayload {
        type Error = PyErr;
        type Target = PyAny;
        type Output = Bound<'py, Self::Target>;
        fn into_pyobject(self, py: Python<'py>) -> Result<Self::Output, Self::Error> {
            match self {
                Self::Syn => Ok(PyString::new(py, "Syn").into_any()),
                Self::Fin => Ok(PyString::new(py, "Fin").into_any()),
                Self::Data(data) => Ok(PyBytes::new(py, &data).into_any())
            }
        }
    }

    /// Python closure of `DetachedPacket`.
    #[pyclass(from_py_object, name="Packet")]
    #[derive(Clone)]
    struct PyPacket {
        #[pyo3(get, set)]
        connection: ConnectionToken,
        #[pyo3(get, set)]
        payload: PyPayload
    }

    /// Unidirectional control message with high scheduling priority.
    #[pyclass(from_py_object, frozen, eq)]
    #[derive(Clone, Copy, Eq, PartialEq)]
    pub enum Signal {
        /// Ask a node to quit.
        /// 
        /// The node should clear up its private resources; Graph state consistency
        /// is not required. (e.g. No need to close connections)
        SIGTERM,
        /// Node-specific signal.
        /// 
        /// Unrecognized signals are simply discarded.
        SIGUSR1,
        /// Node-specific signal.
        /// 
        /// Unrecognized signals are simply discarded.
        SIGUSR2
    }

    pub trait Drain {
        fn drain(&mut self);
    }

    impl Drain for Receiver<Signal> {
        /// Does what you think
        fn drain(&mut self) {
            while self.try_recv().is_ok() {}
        }
    }

    struct NodeEnd {
        receiver: Arc<Mutex<Receiver<Packet>>>,
        sender: Sender<Packet>
    }

    /// General representation of a node end.
    #[pyclass(from_py_object)]
    #[derive(Clone, Default)]
    pub struct NodeEndToken(Arc<MutexStd<Option<NodeEnd>>>); // This std lock is always short held

    impl NodeEndToken {
        pub fn new() -> Self {
            Self::default()
        }
        pub fn set(&self, sender: Sender<Packet>, receiver: Receiver<Packet>) {
            let mut guard = self.0.lock().expect("End is poisoned");
            *guard = Some(NodeEnd {
                receiver: Arc::new(Mutex::new(receiver)),
                sender
            })
        }
        /// Get the sender. Returns `None` if node end is none.
        pub fn sender(&self) -> Option<Sender<Packet>> {
            let guard = self.0.lock().expect("End is poisoned");
            guard.as_ref().map(|node_end| node_end.sender.clone())
        }
        /// Get the receiver. 
        /// 
        /// Returns `Err(())` if the receiver is in use; Returns `Ok(None)` if node end is none.
        pub fn receiver(&self) -> Result<Option<OwnedMutexGuard<Receiver<Packet>>>, TryLockError> {
            let guard = self.0.lock().expect("End is poisoned");
            match guard.as_ref() {
                Some(node_end) => Ok(Some(node_end.receiver.clone().try_lock_owned()?)),
                None => Ok(None)
            }
        }
    }

    #[pymethods]
    impl NodeEndToken {
        pub fn is_none(&self) -> bool {
            self.0.lock().expect("End is poisoned").is_none()
        }
        pub fn is_some(&self) -> bool {
            self.0.lock().expect("End is poisoned").is_some()
        }
        /// This method will fail if the connection reached its data packet count limit.
        fn put_nowait(&self, packet: DetachedPacket) -> PyResult<()> {
            let Ok(packet) = packet.try_attach() else {
                return Err(PyBufferError::new_err("Cannot create new packet"))
            };
            let Some(sender) = self.sender() else {
                return Err(PyRuntimeError::new_err("End is none"));
            };
            match sender.try_send(packet) {
                Ok(_) => Ok(()),
                Err(err) => {
                    match err {
                        TrySendError::Closed(_) => Err(PyEOFError::new_err("End is closed")),
                        TrySendError::Full(_) => Err(PyBufferError::new_err("End is full")) 
                    }
                }
            }
        }
        /// This method will await if the connection reached its data packet count limit.
        async fn put(&self, packet: DetachedPacket) -> PyResult<()> {
            let packet = packet.attach().await;
            let Some(sender) = self.sender() else {
                return Err(PyRuntimeError::new_err("End is none"));
            };
            match sender.send(packet).await {
                Ok(_) => Ok(()),
                _ => Err(PyEOFError::new_err("End is closed"))
            }
        }
    }

    /// Basic node interface.
    #[async_trait]
    pub trait Node: Send {
        // These two methods returns owned vector because
        // sometimes a node don't store node ends in a vector.
        fn upstreams(&self) -> Vec<NodeEndToken>;
        fn downstreams(&self) -> Vec<NodeEndToken>;
        async fn run(&mut self) -> Result<Option<Signal>, &'static str>;
        /// For merging graphs
        fn nodes(&mut self) -> Option<&mut Vec<NodeToken>> { None }
    }

    /// General representation of a node.
    /// 
    /// The node lock is long held when running.
    #[pyclass(from_py_object, name="Node")]
    #[derive(Clone)]
    pub struct NodeToken {
        node: Arc<Mutex<Box<dyn Node>>>,
        signal_sender: Sender<Signal>
    }

    impl NodeToken {
        pub fn new(node: Box<dyn Node>, signal_sender: Sender<Signal>) -> Self {
            Self {
                node: Arc::new(Mutex::new(node)),
                signal_sender
            }
        }
        /// Lock & run as rust `Future`.
        pub async fn run(&mut self) -> Result<Result<Option<Signal>, &'static str>, &'static str> {
            let mut guard = self.node.try_lock().map_err(|_| "Node is running")?;
            Ok(guard.as_mut().run().await)
        }
        /// Connect a upstream downstream to a downstream upstream.
        pub fn connect(upstream_node: &mut Self, downstream_index: usize, downstream_node: &mut Self, upstream_index: usize) -> Result<(), &'static str> {
            let mut upstream_guard = upstream_node.node.try_lock().map_err(|_| "Node is running")?;
            let mut downstream_guard = downstream_node.node.try_lock().map_err(|_| "Node is running")?;
            let upstream_downstreams = upstream_guard.as_mut().downstreams();
            let downstream_upstreams = downstream_guard.as_mut().upstreams();
            let (sender1, receiver1) = channel(PACKET_BUFFER_SIZE);
            let (sender2, receiver2) = channel(PACKET_BUFFER_SIZE);
            upstream_downstreams[downstream_index].set(sender1, receiver2);
            downstream_upstreams[upstream_index].set(sender2, receiver1);
            Ok(())
        }
        /// Connect upstream empty downstreams to downstream empty upstreams until either side is fully connected.
        pub fn connect_all(upstream_node: &mut Self, downstream_node: &mut Self) -> Result<(), &'static str> {
            let empty_downstreams = {
                let mut upstream_guard = upstream_node.node.try_lock().map_err(|_| "Node is running")?;
                let mut indices = Vec::new();
                for (index, downstream) in upstream_guard.as_mut().downstreams().iter().enumerate() {
                    if downstream.0.try_lock().map_err(|_| "Cannot lock node end")?.is_none() {
                        indices.push(index);
                    }
                }
                indices
            };
            let empty_upstreams = {
                let mut downstream_guard = downstream_node.node.try_lock().map_err(|_| "Node is running")?;
                let mut indices = Vec::new();
                for (index, upstream) in downstream_guard.as_mut().upstreams().iter().enumerate() {
                    if upstream.0.try_lock().map_err(|_| "Cannot lock node end")?.is_none() {
                        indices.push(index);
                    }
                }
                indices
            };
            for (downstream_index, upstream_index) in empty_downstreams.into_iter().zip(empty_upstreams) {
                Self::connect(upstream_node, downstream_index, downstream_node, upstream_index)?;
            }
            Ok(())
        }
        /// Merge nodes or graphs.
        /// 
        /// If both have nodes(), nodes in second are stolen to first.
        /// 
        /// If only one have nodes(), the other is pushed front / back.
        /// 
        /// If none have nodes(), a new GraphNode containing the two nodes is constructed.
        pub fn merge(first: &NodeToken, second: &NodeToken) -> Result<NodeToken, &'static str> {
            // Avoid borrow lifetime problems
            let first_token = first.clone();
            let second_token = second.clone();
            let mut first_guard = first.node.try_lock().map_err(|_| "Node is running")?;
            let mut second_guard = second.node.try_lock().map_err(|_| "Node is running")?;
            let first_node = first_guard.as_mut();
            let second_node = second_guard.as_mut();
            match (first_node.nodes().as_mut(), second_node.nodes().as_mut()) {
                (Some(first_nodes), Some(second_nodes)) => {
                    first_nodes.append(second_nodes);
                    Ok(first_token)
                }
                (Some(first_nodes), None) => {
                    first_nodes.push(second_token);
                    Ok(first_token)
                }
                (None, Some(second_nodes)) => {
                    second_nodes.insert(0, first_token);
                    Ok(second_token)
                }
                (None, None) => Ok(GraphNode::new(Some(vec![first_token, second_token])))
            }
        }
    }

    #[pymethods]
    impl NodeToken {
        /// Send signal.
        pub fn signal(&self, signal: Signal) -> PyResult<()> {
            match self.signal_sender.try_send(signal){
                Ok(()) => Ok(()),
                Err(TrySendError::Closed(_)) => Err(PyRuntimeError::new_err("Signal receiver is closed")),
                Err(TrySendError::Full(_)) => Err(PyRuntimeError::new_err("Signal receiver is full"))
                
            }
        }
        /// Get a COPIED LIST of node upstreams.
        fn copy_upstreams(&self) -> PyResult<Vec<NodeEndToken>> {
            match self.node.try_lock().as_mut() {
                Ok(node) => Ok(node.upstreams()),
                _ => Err(PyRuntimeError::new_err("Node is running"))
            }
        }
        /// Get a COPIED LIST of node downstreams.
        fn copy_downstreams(&self) -> PyResult<Vec<NodeEndToken>> {
            match self.node.try_lock().as_mut() {
                Ok(node) => Ok(node.downstreams()),
                _ => Err(PyRuntimeError::new_err("Node is running"))
            }
        }
        /// Get a COPIED LIST of graph nodes.
        /// 
        /// Returns `None` if the node is not a graph.
        fn copy_nodes(&self) -> PyResult<Option<Vec<NodeToken>>> {
            match self.node.try_lock().as_mut() {
                Ok(node) => Ok(node.nodes().cloned()),
                _ => Err(PyRuntimeError::new_err("Node is running"))
            }
        }
        /// Spawn tokio runtime and run blocked.
        fn spawn(&mut self) -> PyResult<Option<Signal>> {
            let Ok(rt) = tokio::runtime::Runtime::new() else {
                return Err(PyRuntimeError::new_err("Cannot spawn tokio runtime"))
            };
            rt.block_on(self.run())
                .map_err(PyRuntimeError::new_err)?
                .map_err(PyRuntimeError::new_err)
        }
        fn __rshift__(&mut self, other: &mut NodeToken) -> PyResult<NodeToken> {
            NodeToken::connect_all(self, other).map_err(PyRuntimeError::new_err)?;
            NodeToken::merge(self, other).map_err(PyRuntimeError::new_err)
        }
        fn __add__(&mut self, other: &mut NodeToken) -> PyResult<NodeToken> {
            NodeToken::merge(self, other).map_err(PyRuntimeError::new_err)
        }
    }

    /// A node supporting hierarchical construction.
    /// 
    /// This node is implicitly constructed when two nodes merge.
    #[pyclass]
    pub struct GraphNode {
        pub nodes: Vec<NodeToken>,
        pub signal_receiver: Receiver<Signal>
    }

    #[async_trait]
    impl Node for GraphNode {
        fn upstreams(&self) -> Vec<NodeEndToken> {
            let mut upstreams = Vec::new();
            for token in &self.nodes {
                let mut guard = token.node.try_lock().expect("Node is running");
                let node = guard.as_mut();
                upstreams.extend(node.upstreams().iter().cloned());
            }
            upstreams
        }
        fn downstreams(&self) -> Vec<NodeEndToken> {
            let mut downstreams = Vec::new();
            for token in &self.nodes {
                let mut guard = token.node.try_lock().expect("Node is running");
                let node = guard.as_mut();
                downstreams.extend(node.downstreams().iter().cloned());
            }
            downstreams
        }
        async fn run(&mut self) -> Result<Option<Signal>, &'static str> {
            self.signal_receiver.drain();
            for token in &self.nodes {
                if token.node.try_lock().is_err() {
                    return Err("Node is already running");
                }
            }
            let mut tasks: JoinSet<Result<Result<Option<Signal>, &'static str>, &'static str>> = JoinSet::new();
            for token in &self.nodes {
                let mut token = token.clone();
                tasks.spawn(async move { token.run().await });
            }
            loop {
                tokio::select! {
                    biased;
                    signal = self.signal_receiver.recv() => match signal {
                        Some(signal) => {
                            for token in &self.nodes {
                                let _ = token.signal(signal);
                            }
                        }
                        None => return Err("Signal receiver is closed")
                    },
                    joined = tasks.join_next() => match joined {
                        None => return Ok(None),
                        Some(Ok(Ok(Ok(Some(signal))))) => {
                            for token in &self.nodes {
                                let _ = token.signal(signal);
                            }
                        }
                        Some(Ok(Ok(Ok(None)))) => {}
                        Some(Ok(Ok(Err(_)))) | Some(Ok(Err(_))) | Some(Err(_)) => {
                            for token in &self.nodes {
                                let _ = token.signal(Signal::SIGTERM);
                            }
                        }
                    }
                }
            }
        }
        fn nodes(&mut self) -> Option<&mut Vec<NodeToken>> {
            Some(&mut self.nodes)
        }
    }

    #[pymethods]
    impl GraphNode {
        #[new]
        #[pyo3(signature = (nodes = None))]
        #[allow(clippy::new_ret_no_self)]
        pub fn new(nodes: Option<Vec<NodeToken>>) -> NodeToken {
            let (signal_sender, signal_receiver) = channel(SIGNAL_BUFFER_SIZE);
            NodeToken {
                node: Arc::new(Mutex::new(Box::new(Self {
                    nodes: nodes.unwrap_or_default(),
                    signal_receiver
                }))),
                signal_sender,
            }
        }
    }
    
    /// A python-compatible utility enum with "both" option.
    #[derive(Copy, Clone)]
    pub enum AddressMode {
        V4,
        V6,
        V4V6,
        V6V4
    }

    impl<'a, 'py> FromPyObject<'a, 'py> for AddressMode {
        type Error = PyErr;
        fn extract(obj: Borrowed<'a, 'py, PyAny>) -> PyResult<Self> {
            match obj.cast::<PyString>() {
                Ok(obj) => match obj.to_str() {
                    Ok("V4") => Ok(AddressMode::V4),
                    Ok("V6") => Ok(AddressMode::V6),
                    Ok("V4V6") => Ok(AddressMode::V4V6),
                    Ok("V6V4") => Ok(AddressMode::V6V4),
                    _ => Err(PyValueError::new_err("Invalid Value"))
                },
                _ => Err(PyValueError::new_err("Invalid Value"))
            }
        }
    }

    impl<'py> IntoPyObject<'py> for AddressMode {
        type Error = PyErr;
        type Target = PyAny;
        type Output = Bound<'py, Self::Target>;
        fn into_pyobject(self, py: Python<'py>) -> Result<Self::Output, Self::Error> {
            match self {
                AddressMode::V4 => Ok(PyString::new(py, "V4").into_any()),
                AddressMode::V6 => Ok(PyString::new(py, "V6").into_any()),
                AddressMode::V4V6 => Ok(PyString::new(py, "V4V6").into_any()),
                AddressMode::V6V4 => Ok(PyString::new(py, "V6V4").into_any())
            }
        }
    }

    pub struct AbortOnDropHandle<T>(JoinHandle<T>);

    impl<T> AbortOnDropHandle<T> {
        pub fn new(join_handle: JoinHandle<T>) -> Self {
            Self(join_handle)
        }
        pub fn abort(&self) {
            self.0.abort();
        }
        pub fn is_finished(&self) -> bool {
            self.0.is_finished()
        }
        pub fn abort_handle(&self) -> AbortHandle {
            self.0.abort_handle()
        }
        pub fn detach(self) -> JoinHandle<T> {
            let me = std::mem::ManuallyDrop::new(self);
            unsafe { std::ptr::read(&me.0) }
        }
    }

    impl<T> Drop for AbortOnDropHandle<T> {
        fn drop(&mut self) {
            self.abort();
        }
    }

    impl<T> Future for AbortOnDropHandle<T> {
        type Output = Result<T, tokio::task::JoinError>;

        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            Pin::new(&mut self.0).poll(cx)
        }
    }

    impl<T> std::ops::Deref for AbortOnDropHandle<T> {
        type Target = JoinHandle<T>;

        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }

    pub struct Bijection<X: Eq + Hash + Clone, Y: Eq + Hash + Clone> {
        x: HashMap<X, Y>,
        y: HashMap<Y, X>
    }

    impl<X: Eq + Hash + Clone, Y: Eq + Hash + Clone> Default for Bijection<X, Y> {
        fn default() -> Self {
            Self::new()
        }
    }

    impl<X: Eq + Hash + Clone, Y: Eq + Hash + Clone> Bijection<X, Y> {
        pub fn new() -> Self {
            Self {
                x: HashMap::new(),
                y: HashMap::new()
            }
        }
        /// Set `x <-> y` relation.
        /// 
        /// Removes existing relations involving `x` and `y`.
        pub fn set(&mut self, x: X, y: Y) {
            if let Some(prior_y) = self.x.remove(&x) {
                self.y.remove(&prior_y);
            };
            if let Some(prior_x) = self.y.remove(&y) {
                self.x.remove(&prior_x);
            };
            self.x.insert(x.clone(), y.clone());
            self.y.insert(y, x);
        }
        pub fn x_get(&self, x: &X) -> Option<Y> {
            self.x.get(x).cloned()
        }
        pub fn y_get(&self, y: &Y) -> Option<X> {
            self.y.get(y).cloned()
        }
        pub fn is_empty(&self) -> bool {
            self.x.is_empty()
        }
        pub fn x_remove(&mut self, x: &X) -> Option<Y> {
            let y = self.x.remove(x);
            if let Some(y) = &y {
                self.y.remove(y);
            }
            y
        }
        pub fn y_remove(&mut self, y: &Y) -> Option<X> {
            let x = self.y.remove(y);
            if let Some(x) = &x {
                self.x.remove(x);
            }
            x
        }
    }

    pub struct BijectionAD<X: Eq + Hash + Clone, Y: Eq + Hash + Clone, D: Clone> {
        x: HashMap<X, (Y, D)>,
        y: HashMap<Y, (X, D)>
    }

    impl<X: Eq + Hash + Clone, Y: Eq + Hash + Clone, D: Clone> Default for BijectionAD<X, Y, D> {
        fn default() -> Self {
            Self::new()
        }
    }

    impl<X: Eq + Hash + Clone, Y: Eq + Hash + Clone, D: Clone> BijectionAD<X, Y, D> {
        pub fn new() -> Self {
            Self {
                x: HashMap::new(),
                y: HashMap::new()
            }
        }
        /// Set `x <-d-> y` relation.
        /// 
        /// Removes existing relations involving `x` and `y`.
        pub fn set(&mut self, x: X, y: Y, d: D) {
            if let Some((prior_y, _)) = self.x.remove(&x) {
                self.y.remove(&prior_y);
            };
            if let Some((prior_x, _)) = self.y.remove(&y) {
                self.x.remove(&prior_x);
            };
            self.x.insert(x.clone(), (y.clone(), d.clone()));
            self.y.insert(y, (x, d));
        }
        pub fn x_get(&self, x: &X) -> Option<(Y, D)> {
            self.x.get(x).cloned()
        }
        pub fn y_get(&self, y: &Y) -> Option<(X, D)> {
            self.y.get(y).cloned()
        }
        pub fn is_empty(&self) -> bool {
            self.x.is_empty()
        }
        /// Idempotently remove the relation involving `x`.
        pub fn x_remove(&mut self, x: &X) -> Option<(Y, D)> {
            let removed = self.x.remove(x);
            if let Some((y, _)) = &removed {
                self.y.remove(y);
            }
            removed
        }
        /// Idempotently remove the relation involving `y`.
        pub fn y_remove(&mut self, y: &Y) -> Option<(X, D)> {
            let removed = self.y.remove(y);
            if let Some((x, _)) = &removed {
                self.x.remove(x);
            }
            removed
        }
    }
}

