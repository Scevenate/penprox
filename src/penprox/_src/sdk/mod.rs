#[pyo3::pymodule]
pub mod sdk {
    use std::{hash::{Hash, Hasher}, net::IpAddr, pin::Pin, sync::{Arc, OnceLock, Mutex as MutexStd}};
    use async_trait::async_trait;
    use futures::future::select_all;
    use pyo3::{Borrowed, FromPyObject, IntoPyObject, PyErr, PyResult, exceptions::{PyBufferError, PyEOFError, PyRuntimeError, PyValueError}, prelude::*, pyclass, pymethods, types::{PyBytes, PyString}};
    use tokio::{sync::{Mutex, OwnedMutexGuard, Semaphore, mpsc::{Receiver, Sender, channel, error::TrySendError}}, task::JoinSet};

    /// Maximum amount of data packets a connection can safely buffer.
    pub const ON_FLIGHT_SIZE: usize = 64;

    /// Exposed connection Host type.
    /// 
    /// Connection host is mutable only for DNS resolution.
    #[derive(FromPyObject, IntoPyObject, Clone)]
    pub enum Host {
        Domain(String),
        IpAddr(IpAddr)
    }

    /// Immutable connection transport type.
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
        fn into_pyobject(self: Self, py: Python<'py>) -> Result<Self::Output, Self::Error> {
            match self {
                Transport::TCP => Ok(PyString::new(py, "TCP").into_any()),
                Transport::UDP => Ok(PyString::new(py, "UDP").into_any()),
            }
        }
    }

    /// Opaque identity of a connection.
    struct Connection {
        domain: Option<String>,
        ip: OnceLock<IpAddr>,
        transport: Transport,
        port: u16,
        buffer: Semaphore
    }

    /// General representation of a connection.
    #[pyclass(from_py_object, frozen, eq, hash, name="Connection")]
    #[derive(Clone)]
    pub struct ConnectionToken(Arc<Connection>);

    impl Eq for ConnectionToken {}
    impl PartialEq for ConnectionToken {
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
        async fn acquire(&self) {
            self.0.buffer.acquire().await.expect("Semaphore was closed").forget();
        }
        fn try_acquire(&self) -> Result<(), ()> {
            match self.0.buffer.try_acquire() {
                Ok(permit) => {
                    permit.forget();
                    Ok(())
                },
                _ => Err(())
            }
        }
        fn release(&self) {
            self.0.buffer.add_permits(1);
        }
    }

    #[pymethods]
    impl ConnectionToken {
        /// Idempotently set IP.
        pub fn resolve(&self, ip_addr: IpAddr) {
            let _ = self.0.ip.set(ip_addr);
        }
        /// Initialize new connection.
        #[new]
        pub fn new(host: Host, transport: Transport, port: u16) -> Self {
            match host {
                Host::Domain(domain) => Self(Arc::new(Connection {
                    domain: Some(domain),
                    ip: OnceLock::new(),
                    transport,
                    port,
                    buffer: Semaphore::new(ON_FLIGHT_SIZE)
                })),
                Host::IpAddr(ip_addr) => Self(Arc::new(Connection {
                    domain: None,
                    ip: OnceLock::from(ip_addr),
                    transport,
                    port,
                    buffer: Semaphore::new(ON_FLIGHT_SIZE)
                }))
            }
        }
        #[getter]
        pub fn host(&self) -> PyResult<Host> {
            match self.0.ip.get() {
                Some(ip_addr) => Ok(Host::IpAddr(*ip_addr)),
                None => Ok(Host::Domain(self.0.domain.clone().expect("Connection has no host")))
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

    /// Payload, field owned by a packet.
    #[derive(Clone)]
    pub enum Payload {
        SYN,
        FIN,
        Data(Box<[u8]>)
    }

    impl<'a, 'py> FromPyObject<'a, 'py> for Payload {
        type Error = PyErr;
        fn extract(obj: Borrowed<'a, 'py, PyAny>) -> PyResult<Self> {
            if let Ok(obj) = obj.cast::<PyString>() {
                match obj.to_str() {
                    Ok("SYN") => return Ok(Payload::SYN),
                    Ok("FIN") => return Ok(Payload::FIN),
                    _ => return Err(PyValueError::new_err("Invalid Value"))
                };
            };
            match obj.cast::<PyBytes>() {
                Ok(obj) => Ok(Payload::Data(Box::from(obj.as_bytes()))),
                _ => Err(PyValueError::new_err("Invalid Value"))
            }
        }
    }

    impl<'py> IntoPyObject<'py> for Payload {
        type Error = PyErr;
        type Target = PyAny;
        type Output = Bound<'py, Self::Target>;
        fn into_pyobject(self: Self, py: Python<'py>) -> Result<Self::Output, Self::Error> {
            match self {
                Payload::SYN => Ok(PyString::new(py, "SYN").into_any()),
                Payload::FIN => Ok(PyString::new(py, "FIN").into_any()),
                Payload::Data(obj) => Ok(PyBytes::new(py, &obj).into_any())
            }
        }
    }

    pub struct Packet {
        connection: ConnectionToken,
        pub payload: Payload
    }

    impl Drop for Packet {
        fn drop(&mut self) {
            self.connection.release();
        }
    }

    impl Packet {
        pub async fn new(connection: ConnectionToken, payload: Payload) -> Self {
            connection.acquire().await;
            Self {
                connection,
                payload
            }
        }
        pub fn try_new(connection: ConnectionToken, payload: Payload) -> Result<Self, ()> {
            connection.try_acquire()?;
            Ok(Self {
                connection,
                payload
            })
        }
        pub fn connection(&self) -> &ConnectionToken {
            &self.connection
        }
        pub fn to_pypacket(&self) -> PyPacket {
            PyPacket {
                connection: self.connection.clone(),
                payload: self.payload.clone()
            }
        }
    }

    /// Rust, in-graph packet.
    /// 
    /// The total amount of packets a connection can buffer is limited.
    #[pyclass(name="Packet", from_py_object)]
    #[derive(Clone)]
    pub struct PyPacket {
        connection: ConnectionToken,
        payload: Payload
    }

    impl PyPacket {
        pub async fn into_packet(self) -> Packet {
            Packet::new(self.connection, self.payload).await
        }

        pub fn try_to_packet<'py>(self) -> Result<Packet, ()> {
            Packet::try_new(self.connection.clone(), self.payload.clone())
        }
    }

    /// Python packet detached from the graph.
    #[pymethods]
    impl PyPacket {
        #[new]
        fn python_new(connection: ConnectionToken, payload: Payload) -> Self {
            Self {
                connection,
                payload
            }
        }
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

    /// Inner data struct of a node end.
    struct NodeEnd {
        receiver: Arc<Mutex<Receiver<Packet>>>,
        sender: Sender<Packet>
    }

    /// General representation of a node end.
    /// 
    /// The lock is only for edge manipulation and is always short held.
    #[pyclass(from_py_object)]
    #[derive(Clone)]
    pub struct NodeEndToken(Arc<MutexStd<Option<NodeEnd>>>);

    impl NodeEndToken {
        pub fn new() -> Self {
            Self(Arc::new(MutexStd::new(None)))
        }
        pub fn set(&self, sender: Sender<Packet>, receiver: Receiver<Packet>) {
            let mut guard = self.0.lock().expect("End is poisoned");
            *guard = Some(NodeEnd {
                receiver: Arc::new(Mutex::new(receiver)),
                sender
            })
        }
        pub fn sender(&self) -> Option<Sender<Packet>> {
            let guard = self.0.lock().expect("End is poisoned");
            match guard.as_ref() {
                Some(node_end) => Some(node_end.sender.clone()),
                None => None
            }
        }
        pub fn receiver(&self) -> Result<OwnedMutexGuard<Receiver<Packet>>, &'static str> {
            let guard = self.0.lock().expect("End is poisoned");
            match guard.as_ref() {
                Some(node_end) => node_end.receiver.clone().try_lock_owned().or(Err("End is occupied")),
                None => Err("End is none")
            }
        }
    }

    #[pymethods]
    impl NodeEndToken {
        pub fn is_none(&self) -> PyResult<bool> {
            let Ok(guard) = self.0.lock() else {
                return Err(PyRuntimeError::new_err("End is poisoned"));
            };
            Ok(guard.is_none())
        }
        fn put_nowait<'py>(&self, packet: PyPacket) -> PyResult<()> {
            let Ok(packet) = packet.try_to_packet() else {
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
        async fn put<'py>(&self, packet: PyPacket) -> PyResult<()> {
            let packet = packet.into_packet().await;
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
            let (sender1, receiver1) = channel(32);
            let (sender2, receiver2) = channel(32);
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
                Err(err) => match err {
                    TrySendError::Closed(_) => Err(PyRuntimeError::new_err("Signal receiver is closed")),
                    TrySendError::Full(_) => Err(PyRuntimeError::new_err("Signal receiver is full"))
                }
            }
        }
        /// Spawn tokio runtime and run blocked.
        pub fn spawn(&mut self) -> PyResult<Option<Signal>> {
            let Ok(rt) = tokio::runtime::Runtime::new() else {
                return Err(PyRuntimeError::new_err("Cannot spawn tokio runtime"))
            };
            Ok(rt.block_on(self.run())
                .map_err(|err| PyRuntimeError::new_err(err))?
                .map_err(|err| PyRuntimeError::new_err(err))?)
        }
        fn __rshift__(&mut self, other: &mut NodeToken) -> PyResult<NodeToken> {
            NodeToken::connect_all(self, other).map_err(|err| PyRuntimeError::new_err(err))?;
            Ok(NodeToken::merge(self, other).map_err(|err| PyRuntimeError::new_err(err))?)
        }
        fn __add__(&mut self, other: &mut NodeToken) -> PyResult<NodeToken> {
            Ok(NodeToken::merge(self, other).map_err(|err| PyRuntimeError::new_err(err))?)
        }
    }

    /// A special node supporting hierarchical construction.
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
            while self.signal_receiver.try_recv().is_ok() {}
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
        pub fn new(nodes: Option<Vec<NodeToken>>) -> NodeToken {
            let (signal_sender, signal_receiver) = channel(8);
            NodeToken {
                node: Arc::new(Mutex::new(Box::new(Self {
                    nodes: match nodes {
                        Some(nodes) => nodes,
                        None => Vec::new()
                    },
                    signal_receiver
                }))),
                signal_sender,
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
    enum PyPacketSignalError {
        PyPacket(PyPacket),
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

    #[pyfunction]
    fn get_python_node_upstreams(node: &NodeToken) -> PyResult<Vec<NodeEndToken>> {
        match node.node.try_lock().as_mut() {
            Ok(node) => Ok(node.upstreams()),
            _ => Err(PyRuntimeError::new_err("Node is running"))
        }
    }

    #[pyfunction]
    fn get_python_node_downstreams(node: &NodeToken) -> PyResult<Vec<NodeEndToken>> {
        match node.node.try_lock().as_mut() {
            Ok(node) => Ok(node.downstreams()),
            _ => Err(PyRuntimeError::new_err("Node is running"))
        }
    }

    #[pymethods]
    impl PythonNode {
        #[new]
        pub fn new<'py>(callback: Bound<'py, PyAny>, upstreams: usize, downstreams: usize) -> PyResult<NodeToken> {
            if !callback.is_callable() {
                return Err(PyValueError::new_err("Callback not callable"));
            }
            let mut u = Vec::with_capacity(upstreams);
            let mut d = Vec::with_capacity(downstreams);
            u.resize_with(upstreams, || NodeEndToken(Arc::new(MutexStd::new(None))));
            d.resize_with(downstreams, || NodeEndToken(Arc::new(MutexStd::new(None))));
            let (signal_sender, signal_receiver) = channel(8);
            Ok(NodeToken {
                node: Arc::new(Mutex::new(Box::new(Self {
                    upstreams: u,
                    downstreams: d,
                    signal_receiver,
                    callback: callback.unbind()
                }))),
                signal_sender
            })
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
            let mut upstreams: Vec<OwnedMutexGuard<Receiver<Packet>>> = Vec::with_capacity(self.upstreams.len());
            for upstream in &mut self.upstreams {
                upstreams.push(upstream.receiver()?);
            }
            let mut downstreams: Vec<OwnedMutexGuard<Receiver<Packet>>> = Vec::with_capacity(self.downstreams.len());
            for downstream in &mut self.downstreams {
                downstreams.push(downstream.receiver()?);
            }
            loop {
                let ((channel_type, index), outcome) = {
                    let mut tags: Vec<(ChannelType, usize)> = Vec::with_capacity(upstreams.len() + downstreams.len());
                    let mut packets: Vec<Pin<Box<dyn Future<Output = PyPacketSignalError> + Send + '_>>> = Vec::with_capacity(upstreams.len() + downstreams.len());
                    for (index, receiver) in upstreams.iter_mut().enumerate() {
                        tags.push((ChannelType::Upstream, index));
                        packets.push(Box::pin(async move {
                            match receiver.recv().await {
                                Some(packet) => PyPacketSignalError::PyPacket(packet.to_pypacket()),
                                None => PyPacketSignalError::Error(())
                            }
                        }));
                    }
                    for (index, receiver) in downstreams.iter_mut().enumerate() {
                        tags.push((ChannelType::Downstream, index));
                        packets.push(Box::pin(async move {
                            match receiver.recv().await {
                                Some(packet) => PyPacketSignalError::PyPacket(packet.to_pypacket()),
                                None => PyPacketSignalError::Error(())
                            }
                        }));
                    }
                    if packets.is_empty() {
                        match self.signal_receiver.recv().await {
                            Some(signal) => ((ChannelType::Signal, 0), PyPacketSignalError::Signal(signal)),
                            None => return Err("Signal handle closed")
                        }
                    } else {
                        tokio::select! {
                            biased;
                            signal = self.signal_receiver.recv() => match signal {
                                Some(signal) => ((ChannelType::Signal, 0), PyPacketSignalError::Signal(signal)),
                                None => return Err("Signal handle closed")
                            },
                            (outcome, position, _) = select_all(packets) => (tags[position], outcome),
                        }
                    }
                };
                if matches!(&outcome, PyPacketSignalError::Error(())) {
                    return Err("End is closed");
                }
                let result = Python::attach(|py| {
                    let channel_type = Py::new(py, channel_type)?;
                    let object = self.callback.call1(py, (channel_type, index, outcome))?;
                    object.bind(py).extract::<PythonCallbackReturnCode>()
                });
                match result {
                    Ok(PythonCallbackReturnCode::Control(control)) => match control {
                        false => continue,
                        true => return Ok(None)
                    },
                    Ok(PythonCallbackReturnCode::Signal(signal)) => return Ok(Some(signal)),
                    Err(_) => return Ok(Some(Signal::SIGTERM)),
                }
            }
        }
    }
}

