#[pyo3::pymodule]
pub mod sdk {
    use std::{hash::{Hash, Hasher}, net::IpAddr, sync::{Arc, OnceLock, Mutex as MutexStd}, future::Future, pin::Pin};
    use async_trait::async_trait;
    use pyo3::{Borrowed, FromPyObject, IntoPyObject, PyErr, PyResult, exceptions::{PyBufferError, PyEOFError, PyRuntimeError, PyValueError}, prelude::*, pyclass, pymethods, types::{PyBytes, PyList, PyString}};
    use tokio::{sync::{Mutex as MutexTokio, mpsc::{Receiver, Sender, channel, error::TrySendError}}, task::JoinSet};
    use futures::future::select_all;

    /// Just `IPv4Address | IPv6Address | str` python type.
    #[derive(FromPyObject, IntoPyObject)]
    pub enum Host {
        Domain(String),
        Ip(IpAddr)
    }

    /// Inner data struct & memory identity of a connection.
    /// 
    /// The connection is generally immutable and has a uncopiable memory identity.
    pub struct Connection {
        pub domain: Option<String>,
        /// This must be set if domain is None.
        pub ip: OnceLock<IpAddr>,
        pub port: u8
    }

    /// General representation of a connection.
    #[pyclass(from_py_object, frozen, eq, hash, name="Connection")]
    #[derive(Clone)]
    pub struct ConnectionToken(Arc<Connection>);

    impl Eq for ConnectionToken {}
    impl PartialEq for ConnectionToken {
        fn eq(&self, other: &Self) -> bool {
            self.id() == other.id()
        }
    }
    impl Hash for ConnectionToken {
        fn hash<H: Hasher>(&self, state: &mut H) {
            state.write_usize(self.id());
        }
    }

    #[pymethods]
    impl ConnectionToken {
        /// Get the memory identity of the connection.
        pub fn id(&self) -> usize {
            self.0.as_ref() as *const Connection as usize
        }
        /// Idempotently set IP.
        pub fn resolve(&self, ip_addr: IpAddr) {
            let _ = self.0.ip.set(ip_addr);
        }
        /// Initialize new connection.
        #[new]
        pub fn new(host: Host, port: u8) -> Self {
            match host {
                Host::Domain(domain) => Self(Arc::new(Connection {
                    domain: Some(domain),
                    ip: OnceLock::new(),
                    port: port
                })),
                Host::Ip(ip_addr) => Self(Arc::new(Connection {
                    domain: None,
                    ip: OnceLock::from(ip_addr),
                    port: port
                }))
            }
        }
        /// Python host getter
        #[getter]
        pub fn host(&self) -> PyResult<Host> {
            match self.0.ip.get() {
                Some(ip_addr) => Ok(Host::Ip(*ip_addr)),
                None => Ok(Host::Domain(self.0.domain.clone().expect("Connection has no host")))
            }
        }
        /// Python port getter
        #[getter]
        pub fn port(&self) -> u8 {
            self.0.port
        }
    }

    /// Payload, field owned by a packet.
    /// 
    /// Also `Literal["SYN", "FIN"] | bytes` python parameter type.
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

    /// General representation of a packet.
    #[pyclass(from_py_object, name="Packet")]
    #[derive(Clone)]
    pub struct Packet {
        #[pyo3(get, set)]
        pub connection: ConnectionToken,
        #[pyo3(get, set)]
        pub payload: Payload
    }

    #[pymethods]
    impl Packet {
        /// Initialize new packet.
        #[new]
        pub fn new(connection: ConnectionToken, payload: Payload) -> Self {
            Self {
                connection: connection,
                payload: payload
            }
        }
    }

    #[pyclass(from_py_object, frozen, eq)]
    #[derive(Clone, Copy, Eq, PartialEq)]
    pub enum Signal {
        SIGKILL,
        SIGUSR1,
        SIGUSR2
    }

    /// Signal handle.
    #[pyclass(from_py_object, frozen)]
    #[derive(Clone)]
    pub struct SignalHandle(pub Sender<Signal>);

    #[pymethods]
    impl SignalHandle {
        pub fn signal(&self, signal: Signal) -> PyResult<()> {
            match self.0.try_send(signal) {
                Ok(()) => Ok(()),
                Err(err) => match err {
                    TrySendError::Full(_) => Err(PyBufferError::new_err("Queue is full")),
                    TrySendError::Closed(_) => Err(PyEOFError::new_err("Queue closed"))
                }
            }
        }
    }

    pub type Upstream = Arc<MutexStd<Option<Receiver<Packet>>>>;
    pub type Downstream = Arc<MutexStd<Option<Sender<Packet>>>>;

    


    /// Basic node interface.
    #[async_trait]
    pub trait Node: Send {
        fn upstreams(&mut self) -> &mut [Upstream];
        fn downstreams(&mut self) -> &mut [Downstream];
        async fn run(&mut self) -> Result<Option<Signal>, &'static str>;
        /// Function for merging graphs
        fn nodes(&mut self) -> Option<&mut Vec<NodeToken>> { None }
    }

    /// General representation of a node.
    /// 
    /// The token points to a unclonable node with memory identity.
    #[pyclass(from_py_object, name="Node")] // `eq` / `hash` requires immutability so we'll custom memory id impl
    #[derive(Clone)]
    pub struct NodeToken {
        /// It's `Some` if you can access it.
        pub node: Arc<MutexTokio<Box<dyn Node>>>,
        /// This handle represents the node's memory identity (with runtime access).
        #[pyo3(get)]
        pub signal_handle: SignalHandle
    }

    impl Eq for NodeToken {}
    impl PartialEq for NodeToken {
        fn eq(&self, other: &Self) -> bool {
            self.id() == other.id()
        }
    }
    impl Hash for NodeToken {
        fn hash<H: Hasher>(&self, state: &mut H) {
            state.write_usize(self.id());
        }
    }

    impl NodeToken {
        /// Lock & run as rust `Future`.
        pub async fn run(&mut self) -> Result<Result<Option<Signal>, &'static str>, &'static str> {
            let mut guard = self.node.try_lock().map_err(|_| "Node is running")?;
            Ok(guard.as_mut().run().await)
        }
        /// Connect a upstream downstream to a downstream upstream.
        pub fn connect(upstream_node: &mut Self, downstream_index: usize, downstream_node: &mut Self, upstream_index: usize) -> Result<(), &'static str> {
            let mut upstream_guard = upstream_node.node.try_lock().map_err(|_| "Node is running")?;
            let mut downstream_guard = downstream_node.node.try_lock().map_err(|_| "Node is running")?;
            let upstream_node = upstream_guard.as_mut();
            let downstream_node = downstream_guard.as_mut();
            let (sender, receiver) = channel(64);
            *upstream_node.downstreams()[downstream_index].lock().unwrap() = Some(sender);
            *downstream_node.upstreams()[upstream_index].lock().unwrap() = Some(receiver);
            Ok(())
        }
        /// Connect upstream empty downstreams to downstream empty upstreams until either side is fully connected.
        pub fn connect_all(upstream_node: &mut Self, downstream_node: &mut Self) -> Result<(), &'static str> {
            let mut upstream_guard = upstream_node.node.try_lock().map_err(|_| "Node is running")?;
            let mut downstream_guard = downstream_node.node.try_lock().map_err(|_| "Node is running")?;
            let upstream_node = upstream_guard.as_mut();
            let downstream_node = downstream_guard.as_mut();
            let downstreams = upstream_node.downstreams();
            let mut upstreams = downstream_node.upstreams().iter();
            for downstream in downstreams.iter() {
                if downstream.lock().unwrap().is_some() {
                    continue;
                }
                let upstream = loop {
                    match upstreams.next() {
                        Some(upstream) if upstream.lock().unwrap().is_none() => break upstream,
                        Some(_) => continue,
                        None => return Ok(())
                    }
                };
                let (sender, receiver) = channel(64);
                *downstream.lock().unwrap() = Some(sender);
                *upstream.lock().unwrap() = Some(receiver);
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
        pub fn merge(first: &mut NodeToken, second: &mut NodeToken) -> Result<NodeToken, &'static str> {
            // Avoid borrow lifetime problems
            let first_token = first.clone();
            let second_token = second.clone();
            let mut first_guard = first.node.try_lock().map_err(|_| "Node is running")?;
            let mut second_guard = second.node.try_lock().map_err(|_| "Node is running")?;
            let first_node = first_guard.as_mut();
            let second_node = second_guard.as_mut();
            match (first_node.nodes(), second_node.nodes()) {
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
        /// Get the memory identity of the node.
        pub fn id(&self) -> usize {
            &self.signal_handle as *const SignalHandle as usize
        }
        // impl on NodeToken so all nodes benefit
        pub fn __hash__(&self) -> usize {
            self.id()
        }
        pub fn __eq__(&self, other: &NodeToken) -> bool {
            self == other
        }
        /// Send signal.
        pub fn signal(&self, signal: Signal) -> PyResult<()> {
            self.signal_handle.signal(signal)
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
        pub fn __rshift__(&mut self, other: &mut NodeToken) -> PyResult<NodeToken> {
            NodeToken::connect_all(self, other).map_err(|err| PyRuntimeError::new_err(err))?;
            Ok(NodeToken::merge(self, other).map_err(|err| PyRuntimeError::new_err(err))?)
        }
        pub fn __add__(&mut self, other: &mut NodeToken) -> PyResult<NodeToken> {
            Ok(NodeToken::merge(self, other).map_err(|err| PyRuntimeError::new_err(err))?)
        }
    }

    /// General representation of a graph, a special reserved node supporting hierarchical construction.
    #[pyclass]
    pub struct GraphNode {
        pub nodes: Vec<NodeToken>,
        pub signal_handler: Receiver<Signal>,
        pub upstreams: Vec<Upstream>,
        pub downstreams: Vec<Downstream>
    }

    #[async_trait]
    impl Node for GraphNode {
        fn upstreams(&mut self) -> &mut [Upstream] {
            let mut flat = Vec::new();
            for token in &self.nodes {
                let mut guard = token.node.try_lock().expect("Node is running");
                let node = guard.as_mut();
                flat.extend(node.upstreams().iter().cloned());
            }
            self.upstreams = flat;
            &mut self.upstreams
        }
        fn downstreams(&mut self) -> &mut [Downstream] {
            let mut flat = Vec::new();
            for token in &self.nodes {
                let mut guard = token.node.try_lock().expect("Node is running");
                let node = guard.as_mut();
                flat.extend(node.downstreams().iter().cloned());
            }
            self.downstreams = flat;
            &mut self.downstreams
        }
        async fn run(&mut self) -> Result<Option<Signal>, &'static str> {
            while self.signal_handler.try_recv().is_ok() {}
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
                    signal = self.signal_handler.recv() => match signal {
                        Some(signal) => {
                            for token in &self.nodes {
                                let _ = token.signal(signal);
                            }
                        }
                        None => return Ok(None)
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
                                let _ = token.signal(Signal::SIGKILL);
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
            let (sender, receiver) = channel(8);
            NodeToken {
                node: Arc::new(MutexTokio::new(Box::new(Self {
                    nodes: match nodes {
                        Some(nodes) => nodes,
                        None => Vec::new()
                    },
                    signal_handler: receiver,
                    upstreams: Vec::new(),
                    downstreams: Vec::new()
                }))),
                signal_handle: SignalHandle(sender),
            }
        }
    }


    /// Python arg type
    #[derive(IntoPyObject)]
    pub enum PacketSignalError {
        Packet(Packet),
        Signal(Signal),
        Error(PyErr)
    }

    /// Python return type
    #[derive(FromPyObject)]
    pub enum PythonCallbackReturnCode {
        Control(bool),
        Signal(Signal)
    }
    
    /// Python arg type
    #[pyclass(skip_from_py_object, frozen)]
    #[derive(Clone)]
    pub struct DownstreamHandle(pub Sender<Packet>);

    #[pymethods]
    impl DownstreamHandle {
        pub fn send(&self, packet: Packet) -> PyResult<()> {
            match self.0.try_send(packet) {
                Ok(()) => Ok(()),
                Err(err) => match err {
                    TrySendError::Full(_) => Err(PyBufferError::new_err("Queue is full")),
                    TrySendError::Closed(_) => Err(PyEOFError::new_err("Queue closed"))
                }
            }
        }
    }

    #[pyclass]
    pub struct PythonNode {
        pub upstreams: Vec<Upstream>,
        pub downstreams: Vec<Downstream>,
        pub signal_handler: Receiver<Signal>,
        pub callback: Py<PyAny>
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
            u.resize_with(upstreams, || Arc::new(MutexStd::new(None)));
            d.resize_with(downstreams, || Arc::new(MutexStd::new(None)));
            let (signal_handle, signal_handler) = channel(8);
            Ok(NodeToken {
                node: Arc::new(MutexTokio::new(Box::new(Self {
                    upstreams: u,
                    downstreams: d,
                    signal_handler: signal_handler,
                    callback: callback.unbind()
                }))),
                signal_handle: SignalHandle(signal_handle)
            })
        }
    }

    #[async_trait]
    impl Node for PythonNode {
        fn upstreams(&mut self) -> &mut [Upstream] {
            &mut self.upstreams[..]
        }
        fn downstreams(&mut self) -> &mut [Downstream] {
            &mut self.downstreams[..]
        }
        async fn run(&mut self) -> Result<Option<Signal>, &'static str> {
            if self.upstreams.iter().any(|upstream| upstream.lock().unwrap().is_none()) {
                return Err("Node is improperly connected");
            }
            if self.downstreams.iter().any(|downstream| downstream.lock().unwrap().is_none()) {
                return Err("Node is improperly connected");
            }
            let mut receivers: Vec<Receiver<Packet>> = self.upstreams.iter()
                .map(|upstream| upstream.lock().unwrap().take().expect("Connection is gone"))
                .collect();
            let downstreams = Python::attach(|py| {
                PyList::new(py, self.downstreams.iter()
                    .map(|downstream| DownstreamHandle(downstream.lock().unwrap().clone().expect("Connection is gone"))))
                    .map(|list| list.unbind())
            }).map_err(|_| "Cannot create downstream handles")?;
            loop {
                let (index, outcome) = {
                    if receivers.is_empty() {
                        let outcome = match self.signal_handler.recv().await {
                            Some(signal) => PacketSignalError::Signal(signal),
                            None => PacketSignalError::Error(PyEOFError::new_err("Signal handle closed"))
                        };
                        break (-1, outcome);
                    }
                    let packets = receivers.iter_mut().map(|upstream| {
                        Box::pin(async move {
                            match upstream.recv().await {
                                Some(packet) => PacketSignalError::Packet(packet),
                                None => PacketSignalError::Error(PyEOFError::new_err("Queue closed"))
                            }
                        }) as Pin<Box<dyn Future<Output = PacketSignalError> + Send + '_>>
                    });
                    tokio::select! {
                        biased;
                        signal = self.signal_handler.recv() => match signal {
                            Some(signal) => (-1, PacketSignalError::Signal(signal)),
                            None => (-1, PacketSignalError::Error(PyEOFError::new_err("Signal handle closed")))
                        },
                        (outcome, index, _) = select_all(packets) => (index as isize, outcome),
                    }
                };
                match Python::attach(|py| {
                    self.callback.call1(py, (index, PacketSignalError::from(outcome), downstreams.clone_ref(py)))
                        .ok()
                        .and_then(|object| object.bind(py).extract::<PythonCallbackReturnCode>().ok())
                        .unwrap_or(PythonCallbackReturnCode::Signal(Signal::SIGKILL))
                }) {
                    PythonCallbackReturnCode::Control(control) => match control {
                        false => continue,
                        true => return Ok(None)
                    },
                    PythonCallbackReturnCode::Signal(signal) => return Ok(Some(signal)),
                }
            };
            unimplemented!()
        }
    }
}

