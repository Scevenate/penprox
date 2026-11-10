#[pyo3::pymodule(submodule)]
pub mod sdk {
    use std::{any::Any, collections::HashMap, hash::{Hash, Hasher}, io::IsTerminal, net::{IpAddr, ToSocketAddrs}, pin::Pin, ptr, sync::{Arc, Mutex as MutexStd, OnceLock}, task::{Context, Poll}};
    use async_trait::async_trait;
use pyo3::{Borrowed, FromPyObject, IntoPyObject, IntoPyObjectExt, PyErr, PyResult, exceptions::{PyBufferError, PyEOFError, PyFileNotFoundError, PyRuntimeError, PyValueError, PyIndexError}, prelude::*, pyclass, pymethods, types::{PyBytes, PyString}};
    use tokio::{sync::{Mutex as MutexTokio, OwnedMutexGuard, Semaphore, mpsc::{Receiver, Sender, channel, error::TrySendError}}, task::{AbortHandle, JoinHandle, JoinSet}};
    use tracing_subscriber::fmt::writer::BoxMakeWriter;

    pub const PACKET_BUFFER_SIZE: usize = 64;
    pub const SIGNAL_BUFFER_SIZE: usize = 8;
    #[pymodule_export]
    pub const PACKET_DATA_SIZE: usize = 2048;
    /// Maximum amount of data packets a connection can safely buffer.
    pub const CONNECTION_BUFFER_SIZE: usize = 64;

    #[derive(Clone, Debug)]
    pub enum LogDestination {
        Stdout,
        Stderr,
        File(std::path::PathBuf)
    }

    impl<'a, 'py> FromPyObject<'a, 'py> for LogDestination {
        type Error = PyErr;
        fn extract(obj: Borrowed<'a, 'py, PyAny>) -> PyResult<Self> {
            let sys = obj.py().import("sys")?;
            if obj.is(sys.getattr("stdout")?) {
                return Ok(Self::Stdout);
            }
            if obj.is(sys.getattr("stderr")?) {
                return Ok(Self::Stderr);
            }
            match obj.extract::<std::path::PathBuf>() {
                Ok(path) => Ok(Self::File(path)),
                Err(_) => Err(PyValueError::new_err("Invalid log destination. Expected sys.stdout, sys.stderr or a path"))
            }
        }
    }

    #[pyclass(from_py_object, frozen, eq)]
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum LogLevel {
        TRACE,
        DEBUG,
        INFO,
        WARN,
        ERROR
    }

    #[pyfunction]
    #[pyo3(signature = (dest, level = LogLevel::INFO))]
    fn set_logger(dest: LogDestination, level: LogLevel) -> PyResult<()> {
        let (make_writer, ansi) = match dest {
            LogDestination::Stdout => (BoxMakeWriter::new(std::io::stdout), std::io::stdout().is_terminal()),
            LogDestination::Stderr => (BoxMakeWriter::new(std::io::stderr), std::io::stderr().is_terminal()),
            LogDestination::File(path) => {
                let file = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)
                    .map_err(|error| PyFileNotFoundError::new_err(error.to_string()))?;
                (BoxMakeWriter::new(Arc::new(file)), false)
            }
        };
        let level = match level {
            LogLevel::TRACE => tracing::Level::TRACE,
            LogLevel::DEBUG => tracing::Level::DEBUG,
            LogLevel::INFO => tracing::Level::INFO,
            LogLevel::WARN => tracing::Level::WARN,
            LogLevel::ERROR => tracing::Level::ERROR
        };
        let subscriber = tracing_subscriber::fmt()
            .with_writer(make_writer)
            .with_ansi(ansi)
            .with_max_level(level)
            .finish();
        tracing::subscriber::set_global_default(subscriber)
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))
    }


    #[derive(FromPyObject, IntoPyObject, Clone)]
    pub enum Host {
        Domain(String),
        IpAddr(IpAddr)
    }

    impl Host {
        /// Config util for simply getting the IP of remote host.
        /// 
        /// `None` only when the host is an unresolvable domain.
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

    #[derive(Clone, Copy, Debug)]
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

    #[derive(Debug)]
    struct Connection {
        domain: Option<String>,
        ip: OnceLock<IpAddr>,
        transport: Transport,
        port: u16,
        buffer: Semaphore
    }

    /// Strong reference, general representation of a connection.
    /// A connection is an immutable object with memory identity.
    /// 
    /// The endpoint (host, transport, port) has node-dependent meaning:
    /// - For inbound network connection, the host is remote source.
    /// - For outbound network connection, the host is remote destination.
    /// - For proxied connection, the host is the intended proxy destination.
    /// 
    /// Note that this is purely semantic, and is not enforced by any static nor runtime measure.
    /// This is to reduce complexity and enable certain useful runtime casting behaviours,
    /// like casting inound to proxied or proxied to outbound.
    #[pyclass(from_py_object, frozen, eq, hash, name="Connection")]
    #[derive(Clone, Debug)]
    pub struct ConnectionToken(Arc<Connection>);

    impl Eq for ConnectionToken {}
    impl PartialEq for ConnectionToken {
        // Connection is not `Pin`; Id is not exposed and should not be stored.
        // \neq just guarantees the two compared, existing connection
        // are not the same.
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

    #[derive(Debug)]
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
        /// Get the connection attached to.
        /// 
        /// This field is immutable for attached objects.
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

    #[derive(Clone, Debug)]
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

    #[derive(Debug)]
    pub enum Packet {
        SYN(ConnectionToken),
        Data(ConnectionAttached),
        FIN(ConnectionToken)
    }

    impl Packet {
        pub fn detach(self) -> DetachedPacket {
            match self {
                Packet::SYN(connection) => DetachedPacket::SYN(connection),
                Packet::Data(attached) => DetachedPacket::Data(attached.detach()),
                Packet::FIN(connection) => DetachedPacket::FIN(connection)
            }
        }
        pub fn clone_detached(&self) -> DetachedPacket {
            match self {
                Packet::SYN(connection) => DetachedPacket::SYN(connection.clone()),
                Packet::Data(attached) => DetachedPacket::Data(ConnectionDetached {
                    connection: attached.connection().clone(),
                    data: attached.data.clone()
                }),
                Packet::FIN(connection) => DetachedPacket::FIN(connection.clone())
            }
        }
        pub fn connection(&self) -> &ConnectionToken {
            match self {
                Packet::SYN(token) => token,
                Packet::Data(attached) => attached.connection(),
                Packet::FIN(token) => token
            }
        }
        pub fn is_syn(&self) -> bool {
            matches!(self, Self::SYN(_))
        }
        pub fn is_data(&self) -> bool {
            matches!(self, Self::Data(_))
        }
        pub fn is_fin(&self) -> bool {
            matches!(self, Self::FIN(_))
        }
    }

    #[derive(Clone, Debug)]
    pub enum DetachedPacket {
        SYN(ConnectionToken),
        Data(ConnectionDetached),
        FIN(ConnectionToken)
    }

    impl DetachedPacket {
        pub async fn attach(self) -> Packet {
            match self {
                Self::SYN(connection) => Packet::SYN(connection),
                Self::Data(detached) => Packet::Data(detached.attach().await),
                Self::FIN(connection) => Packet::FIN(connection)
            }
        }
        pub fn try_attach(self) -> Result<Packet, Self> {
            match self {
                Self::SYN(connection) => Ok(Packet::SYN(connection)),
                Self::Data(detached) => match detached.try_attach() {
                    Ok(attached) => Ok(Packet::Data(attached)),
                    Err(detached) => Err(Self::Data(detached))
                },
                Self::FIN(connection) => Ok(Packet::FIN(connection))
            }
        }
        pub fn connection(&self) -> &ConnectionToken {
            match self {
                DetachedPacket::SYN(token) => token,
                DetachedPacket::Data(attached) => &attached.connection,
                DetachedPacket::FIN(token) => token
            }
        }
        pub fn is_syn(&self) -> bool {
            matches!(self, Self::SYN(_))
        }
        pub fn is_data(&self) -> bool {
            matches!(self, Self::Data(_))
        }
        pub fn is_fin(&self) -> bool {
            matches!(self, Self::FIN(_))
        }
    }

    impl<'a, 'py> FromPyObject<'a, 'py> for DetachedPacket {
        type Error = PyErr;
        fn extract(obj: Borrowed<'a, 'py, PyAny>) -> PyResult<Self> {
            match obj.extract::<PyPacket>() {
                Ok(obj) => match obj.payload {
                    PyPayload::SYN => Ok(DetachedPacket::SYN(obj.connection)),
                    PyPayload::Data(data) => Ok(DetachedPacket::Data(ConnectionDetached { connection: obj.connection, data })),
                    PyPayload::FIN => Ok(DetachedPacket::FIN(obj.connection))
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
                Self::SYN(connection) => PyPacket {
                    connection,
                    payload: PyPayload::SYN
                },
                Self::Data(detached) => PyPacket {
                    connection: detached.connection,
                    payload: PyPayload::Data(detached.data)
                },
                Self::FIN(connection) => PyPacket {
                    connection,
                    payload: PyPayload::FIN
                }
            };
            py_packet.into_bound_py_any(py)
        }
    }

    /// Internal python payload type, as native `"SYN" | "FIN" | bytes`.
    /// 
    /// This type already checks `PACKET_DATA_SIZE` on boundary.
    #[derive(Clone)]
    #[allow(clippy::upper_case_acronyms)]
    enum PyPayload {
        SYN,
        Data(Box<[u8]>),
        FIN
    }

    impl<'a, 'py> FromPyObject<'a, 'py> for PyPayload {
        type Error = PyErr;
        fn extract(obj: Borrowed<'a, 'py, PyAny>) -> PyResult<Self> {
            if let Ok(obj) = obj.cast::<PyString>() {
                return match obj.to_str() {
                    Ok("SYN") => Ok(Self::SYN),
                    Ok("FIN") => Ok(Self::FIN),
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
                Self::SYN => Ok(PyString::new(py, "SYN").into_any()),
                Self::FIN => Ok(PyString::new(py, "FIN").into_any()),
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
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
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

    impl<'a, 'py> FromPyObject<'a, 'py> for Signal {
        type Error = PyErr;
        fn extract(obj: Borrowed<'a, 'py, PyAny>) -> PyResult<Self> {
            match obj.cast::<PyString>() {
                Ok(obj) => match obj.to_str() {
                    Ok("SIGTERM") => Ok(Self::SIGTERM),
                    Ok("SIGUSR1") => Ok(Self::SIGUSR1),
                    Ok("SIGUSR2") => Ok(Self::SIGUSR2),
                    _ => Err(PyValueError::new_err("Invalid Value"))
                },
                _ => Err(PyValueError::new_err("Invalid Value"))
            }
        }
    }

    impl<'py> IntoPyObject<'py> for Signal {
        type Error = PyErr;
        type Target = PyAny;
        type Output = Bound<'py, Self::Target>;
        fn into_pyobject(self, py: Python<'py>) -> Result<Self::Output, Self::Error> {
            match self {
                Self::SIGTERM => Ok(PyString::new(py, "SIGTERM").into_any()),
                Self::SIGUSR1 => Ok(PyString::new(py, "SIGUSR1").into_any()),
                Self::SIGUSR2 => Ok(PyString::new(py, "SIGUSR2").into_any())
            }
        }
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

    #[derive(Debug)]
    pub enum TokenAccessError {
        Occupied,
        Empty
    }

    impl std::fmt::Display for TokenAccessError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::Occupied => write!(f, "Token access is occupied"),
                Self::Empty => write!(f, "Token is empty")
            }
        }
    }

    impl std::error::Error for TokenAccessError {}

    impl From<TokenAccessError> for PyErr {
        fn from(error: TokenAccessError) -> Self {
            match error {
                TokenAccessError::Empty => PyValueError::new_err("Token is empty"),
                TokenAccessError::Occupied => PyRuntimeError::new_err("Token is occupied")
            }
        }
    }

    #[derive(Debug)]
    pub enum GraphError {
        Disconnected,
        Occupied,
        NodeError
    }

    impl std::fmt::Display for GraphError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::Disconnected => write!(f, "Disconnected"),
                Self::Occupied => write!(f, "Occupied"),
                Self::NodeError => write!(f, "Node encountered unknown error")
            }
        }
    }

    impl std::error::Error for GraphError {}

    impl From<GraphError> for PyErr {
        fn from(error: GraphError) -> PyErr {
            match error {
                GraphError::Disconnected => PyRuntimeError::new_err("Disconnected"),
                GraphError::Occupied => PyRuntimeError::new_err("Occupied"),
                GraphError::NodeError => PyRuntimeError::new_err("Node encountered unknown error")
            }
        }
    }

    impl From<TokenAccessError> for GraphError {
        fn from(error: TokenAccessError) -> Self {
            match error {
                TokenAccessError::Empty => Self::Disconnected,
                TokenAccessError::Occupied => Self::Occupied
            }
        }
    }

    #[derive(Debug)]
    struct NodeEnd {
        sender: Sender<Packet>,
        receiver: Arc<MutexTokio<Receiver<Packet>>> // This ArcMutex clones long held OwnedMutex token
    }

    /// General representation of a node end. Can be empty (disconnected).
    #[pyclass(from_py_object, name="NodeEnd")]
    #[derive(Clone, Debug, Default)]
    pub struct NodeEndToken(Arc<MutexStd<Option<NodeEnd>>>); // This Mutex is always short held

    impl NodeEndToken {
        /// Initialize a new, disconnected node end.
        pub fn new() -> Self {
            Self(Arc::new(MutexStd::new(None)))
        }
        /// Get receiver.
        pub fn sender(&self) -> Result<Sender<Packet>, TokenAccessError> {
            let guard = self.0.lock().expect("End is poisoned");
            Ok(guard.as_ref().ok_or(TokenAccessError::Empty)?.sender.clone())
        }
        /// Get receiver.
        pub fn receiver(&self) -> Result<OwnedMutexGuard<Receiver<Packet>>, TokenAccessError> {
            let guard = self.0.lock().expect("End is poisoned");
            guard.as_ref().ok_or(TokenAccessError::Empty)?.receiver.clone().try_lock_owned().map_err(|_| TokenAccessError::Occupied)
        }
        /// Connect the two ends. Overwrites.
        pub fn connect(&self, other: &Self) {
            let mut slf = self.0.lock().expect("End is poisoned");
            let mut other = other.0.lock().expect("End is poisoned");
            let (sender1, receiver1) = channel(PACKET_BUFFER_SIZE);
            let (sender2, receiver2) = channel(PACKET_BUFFER_SIZE);
            *slf = Some(NodeEnd {
                sender: sender1,
                receiver: Arc::new(MutexTokio::new(receiver2))
            });
            *other = Some(NodeEnd {
                sender: sender2,
                receiver: Arc::new(MutexTokio::new(receiver1))
            });
        }
    }

    #[pymethods]
    impl NodeEndToken {
        pub fn connected(&self) -> bool {
            let guard = self.0.lock().expect("End is poisoned");
            guard.is_some()
        }
        fn put_nowait(&self, packet: DetachedPacket) -> PyResult<()> {
            let Ok(packet) = packet.try_attach() else {
                return Err(PyBufferError::new_err("Cannot put new packet into the graph"))
            };
            let sender = self.sender().map_err(PyErr::from)?;
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
            let sender = self.sender().map_err(PyErr::from)?;
            match sender.send(packet).await {
                Ok(_) => Ok(()),
                _ => Err(PyEOFError::new_err("End is closed"))
            }
        }
        /// `NodeEndToken::connect`
        fn __sub__(&self, other: &Self) {
            self.connect(other);
        }
    }

    /// An immutable upstream / downstream interface of a node.
    #[pyclass(from_py_object)]
    #[derive(Clone, Debug)]
    pub struct NodeInterface(Arc<MutexStd<Vec<NodeEndToken>>>); // This Mutex is always short held

    impl NodeInterface {
        pub fn new(ends: Vec<NodeEndToken>) -> Self {
            Self(Arc::new(MutexStd::new(ends)))
        
        }
        pub fn is_empty(&self) -> bool {
            let guard = self.0.lock().expect("Interface is poisoned");
            guard.is_empty()
        }
        pub fn len(&self) -> usize {
            let guard = self.0.lock().expect("Interface is poisoned");
            guard.len()
        }
        /// This is always `Some` unless index out of bounds
        pub fn get(&self, index: usize) -> Option<NodeEndToken> {
            let guard = self.0.lock().expect("Interface is poisoned");
            guard.get(index).cloned()
        }
        /// Clone inside.
        /// 
        /// This is usually fine to use for immutable `NodeInterface`.
        pub fn get_all(&self) -> Vec<NodeEndToken> {
            let guard = self.0.lock().expect("Interface is poisoned");
            guard.clone()
        }
        /// Connect two interfaces in order until either side is full. Does not overwrite connected ends.
        pub fn connect(&self, other: &Self) -> Result<(), TokenAccessError> {
            let self_disconnected_indices = {
                let self_guard = self.0.lock().map_err(|_| TokenAccessError::Occupied)?;
                let mut indices = Vec::new();
                for (index, self_end) in self_guard.iter().enumerate() {
                    if !self_end.connected() {
                        indices.push(index);
                    }
                }
                indices
            };
            let other_disconnected_indices = {
                let other_guard = other.0.lock().map_err(|_| TokenAccessError::Occupied)?;
                let mut indices = Vec::new();
                for (index, other_end) in other_guard.iter().enumerate() {
                    if !other_end.connected() {
                        indices.push(index);
                    }
                }
                indices
            };
            for (self_index, other_index) in self_disconnected_indices.into_iter().zip(other_disconnected_indices) {
                let downstream = self.get(self_index).expect("Getting an out of bound enumerated index");
                let upstream = other.get(other_index).expect("Getting an out of bound enumerated index");
                NodeEndToken::connect(&downstream, &upstream);
            }
            Ok(())
        }
    }

    #[pymethods]
    impl NodeInterface {
        fn __getitem__(&self, index: usize) -> PyResult<NodeEndToken> {
            self.get(index).ok_or(PyIndexError::new_err("Node end index out of bounds"))
        }
        fn __len__(&self) -> usize {
            self.len()
        }
        /// `NodeInterface::connect`
        fn __sub__(&self, other: &Self) -> PyResult<()> {
            self.connect(other).map_err(PyErr::from)
        }
    }

    /// Basic node interface.
    /// 
    /// Any or pyclass class methods can be used to escape this interface,
    /// if necessary.
    #[async_trait]
    pub trait Node: Any + Send + std::fmt::Debug {
        async fn run(&mut self) -> Result<Option<Signal>, GraphError>;
    }

    /// General representation of a node.
    #[pyclass(from_py_object, name="Node")]
    #[derive(Clone, Debug)]
    pub struct NodeToken {
        node: Arc<MutexTokio<Box<dyn Node>>>,
        signal_sender: Sender<Signal>,
        upstreams: NodeInterface,
        downstreams: NodeInterface
    }

    impl NodeToken {
        pub fn new(node: Box<dyn Node>, signal_sender: Sender<Signal>, upstreams: NodeInterface, downstreams: NodeInterface) -> Self {
            Self {
                node: Arc::new(MutexTokio::new(node)),
                signal_sender,
                upstreams,
                downstreams
            }
        }
        
        /// Lock & run as rust `Future`.
        /// 
        /// Returns occupied token error if node is already running.
        pub async fn run(&self) -> Result<Result<Option<Signal>, GraphError>, TokenAccessError> {
            Ok(self.node.try_lock().map_err(|_| TokenAccessError::Occupied)?.run().await)
        }

        /// Merge nodes or graphs.
        /// 
        /// If both have `nodes()`, nodes in second are stolen to first.
        /// 
        /// If only one have `nodes()`, the other is pushed front / back.
        /// 
        /// If none have `nodes()`, a new default `GraphNode` containing
        /// the two nodes is constructed.
        pub fn merge(first: &Self, second: &Self) -> Result<Self, TokenAccessError> {
            // Avoid borrow lifetime problems
            let first_token = first.clone();
            let second_token = second.clone();
            let mut first_guard = first.node.try_lock().or(Err(TokenAccessError::Occupied))?;
            let mut second_guard = second.node.try_lock().or(Err(TokenAccessError::Occupied))?;
            let first_node: &mut dyn Any = &mut **first_guard;
            let second_node: &mut dyn Any = &mut **second_guard;
            match (first_node.downcast_mut::<GraphNode>(), second_node.downcast_mut::<GraphNode>()) {
                (Some(first_graph), Some(second_graph)) => {
                    first_graph.nodes().append(second_graph.nodes());
                    first_graph.update_upstreams_downstreams(&first_token.upstreams, &first_token.downstreams);
                    second_graph.update_upstreams_downstreams(&second_token.upstreams, &second_token.downstreams);
                    Ok(first_token)
                }
                (Some(first_graph), None) => {
                    first_graph.nodes().push(second_token);
                    first_graph.update_upstreams_downstreams(&first_token.upstreams, &first_token.downstreams);
                    Ok(first_token)
                }
                (None, Some(second_graph)) => {
                    second_graph.nodes().insert(0, first_token);
                    second_graph.update_upstreams_downstreams(&second_token.upstreams, &second_token.downstreams);
                    Ok(second_token)
                }
                (None, None) => Ok(GraphNode::new(vec![first_token, second_token]))
            }
        }
    }

    #[pymethods]
    impl NodeToken {
        pub fn signal(&self, signal: Signal) {
            let _ = self.signal_sender.try_send(signal); // Silently fail for this last resort
        }
        #[getter]
        pub fn upstreams(&self) -> NodeInterface {
            self.upstreams.clone()
        }
        #[getter]
        pub fn downstreams(&self) -> NodeInterface {
            self.downstreams.clone()
        }
        /// Hand over thread, spawn tokio runtime and run blocked.
        fn spawn(&self, py: Python<'_>) -> PyResult<Option<Signal>> {
            let rt = tokio::runtime::Runtime::new().expect("Cannot spawn tokio runtime");
            py.detach(|| rt.block_on(self.run()))
                .map_err(PyErr::from)?
                .map_err(PyErr::from)
        }
        fn __add__(&self, other: &Self) -> PyResult<Self> {
            Self::merge(self, other).map_err(|error| PyRuntimeError::new_err(error.to_string()))
        }
        fn __sub__(&self, other: &Self) -> PyResult<()> {
            NodeInterface::connect(&self.downstreams, &other.upstreams).map_err(PyErr::from)
        }
        fn __rshift__(&self, other: &Self) -> PyResult<Self> {
            self.__sub__(other)?;
            self.__add__(other)
        }
        fn __lshift__(&self, other: &Self) -> PyResult<Self> {
            Self::__rshift__(other, self)
        }
    }

    /// A special node supporting hierarchical construction.
    /// 
    /// This node is special in two ways:
    /// 1. It changes the behaviour of merge;
    /// 2. It has interfaces of variable length.
    #[pyclass]
    #[derive(Debug)]
    pub struct GraphNode {
        pub nodes: Vec<NodeToken>,
        pub signal_receiver: Receiver<Signal>
    }

    #[async_trait]
    impl Node for GraphNode {
        #[tracing::instrument(name="GraphNode::run", skip_all)]
        async fn run(&mut self) -> Result<Option<Signal>, GraphError> {
            self.signal_receiver.drain();
            for token in &self.nodes {
                if token.node.try_lock().is_err() {
                    tracing::error!("Nodes are already running");
                    return Err(GraphError::Occupied);
                }
            }
            tracing::info!("New graph up");
            let mut tasks: JoinSet<Result<Result<Option<Signal>, GraphError>, TokenAccessError>> = JoinSet::new();
            for token in &self.nodes {
                let token = token.clone();
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
                            if signal == Signal::SIGTERM {
                                return Ok(None);
                            }
                        }
                        None => {
                            tracing::error!("Signal sender was closed");
                            return Err(GraphError::Disconnected)
                        }
                    },
                    joined = tasks.join_next() => match joined {
                        None => {
                            tracing::info!("All nodes in graph retured, recursively returning");
                            return Ok(None)
                        },
                        Some(Ok(Ok(Ok(Some(signal))))) => {
                            tracing::warn!("Node returned with broadcast signal {:?}", signal);
                            for token in &self.nodes {
                                let _ = token.signal(signal);
                            }
                        }
                        Some(Ok(Ok(Err(error)))) => {
                            tracing::warn!("Node returned with error {error}, broadcasting SIGTERM");
                            for token in &self.nodes {
                                let _ = token.signal(Signal::SIGTERM);
                            }
                        }
                        Some(Ok(Ok(Ok(None)))) => tracing::info!("Node returned silent (Ok)"),
                        _ => {
                            tracing::error!("Join set failed");
                            for token in &self.nodes {
                                let _ = token.signal(Signal::SIGTERM);
                            }
                            return Err(GraphError::NodeError)
                        }
                    }
                }
            }
        }
    }

    impl GraphNode {
        fn nodes(&mut self) -> &mut Vec<NodeToken> {
            &mut self.nodes
        }
        fn update_upstreams_downstreams(&self, upstreams: &NodeInterface, downstreams: &NodeInterface) {
            let mut new_upstreams = Vec::new();
            let mut new_downstreams = Vec::new();
            for node in &self.nodes {
                let node_upstreams = node.upstreams.0.lock().expect("Interface is poisoned");
                for upstream in &*node_upstreams {
                    new_upstreams.push(upstream.clone());
                }
                let node_downstreams = node.downstreams.0.lock().expect("Interface is poisoned");
                for downstream in &*node_downstreams {
                    new_downstreams.push(downstream.clone());
                }
            }
            let mut upstreams = upstreams.0.lock().expect("Interface is poisoned");
            let mut downstreams = downstreams.0.lock().expect("Interface is poisoned");
            *upstreams = new_upstreams;
            *downstreams = new_downstreams;
        }
    }

    #[pymethods]
    impl GraphNode {
        #[new]
        #[pyo3(signature = (nodes = Vec::new()))]
        #[allow(clippy::new_ret_no_self)]
        pub fn new(nodes: Vec<NodeToken>) -> NodeToken {
            let (signal_sender, signal_receiver) = channel(SIGNAL_BUFFER_SIZE);
            let graph_node = Self {
                nodes,
                signal_receiver
            };
            let upstreams = NodeInterface(Arc::new(MutexStd::new(Vec::new())));
            let downstreams = NodeInterface(Arc::new(MutexStd::new(Vec::new())));
            graph_node.update_upstreams_downstreams(&upstreams, &downstreams);
            NodeToken {
                node: Arc::new(MutexTokio::new(Box::new(graph_node))),
                signal_sender,
                upstreams,
                downstreams
            }
        }
    }

    /// A python-compatible utility enum with "both" option.
    #[derive(Copy, Clone, Debug)]
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

    #[derive(Debug)]
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

    #[derive(Debug)]
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

    #[derive(Debug)]
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

