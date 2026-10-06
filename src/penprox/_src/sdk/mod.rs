#[pyo3::pymodule]
pub mod sdk {
    use std::{hash::{Hash, Hasher}, net::IpAddr, sync::{Arc, OnceLock, Mutex as MutexStd}};
    use async_trait::async_trait;
    use pyo3::{Borrowed, FromPyObject, IntoPyObject, PyErr, PyResult, exceptions::{PyBufferError, PyEOFError, PyRuntimeError, PyValueError}, prelude::*, pyclass, pymethods, types::{PyBytes, PyString}};
    use tokio::{sync::{Mutex as MutexTokio, mpsc::{Receiver, Sender, channel, error::TrySendError}}, task::JoinSet};

    #[derive(FromPyObject, IntoPyObject, Clone)]
    pub enum Host {
        Domain(String),
        Ip(IpAddr)
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
        fn into_pyobject(self: Self, py: Python<'py>) -> Result<Self::Output, Self::Error> {
            match self {
                Transport::TCP => Ok(PyString::new(py, "TCP").into_any()),
                Transport::UDP => Ok(PyString::new(py, "UDP").into_any()),
            }
        }
    }

    /// Inner data struct & memory identity of a connection.
    /// 
    /// The connection is generally immutable and has a uncopiable memory identity.
    pub struct Connection {
        domain: Option<String>,
        /// This must be set if domain is None.
        ip: OnceLock<IpAddr>,
        transport: Transport,
        port: u8
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

    #[pymethods]
    impl ConnectionToken {
        /// Idempotently set IP.
        pub fn resolve(&self, ip_addr: IpAddr) {
            let _ = self.0.ip.set(ip_addr);
        }
        /// Initialize new connection.
        #[new]
        pub fn new(host: Host, transport: Transport, port: u8) -> Self {
            match host {
                Host::Domain(domain) => Self(Arc::new(Connection {
                    domain: Some(domain),
                    ip: OnceLock::new(),
                    transport,
                    port
                })),
                Host::Ip(ip_addr) => Self(Arc::new(Connection {
                    domain: None,
                    ip: OnceLock::from(ip_addr),
                    transport,
                    port
                }))
            }
        }
        #[getter]
        pub fn host(&self) -> PyResult<Host> {
            match self.0.ip.get() {
                Some(ip_addr) => Ok(Host::Ip(*ip_addr)),
                None => Ok(Host::Domain(self.0.domain.clone().expect("Connection has no host")))
            }
        }
        #[getter]
        pub fn transport(&self) -> Transport {
            self.0.transport
        }
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
    #[pyclass(from_py_object)]
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

    /// Inner data struct of a node end.
    pub struct NodeEnd {
        pub receiver: Receiver<Packet>,
        pub sender: Sender<Packet>
    }

    /// General representation of a node end.
    /// 
    /// The lock is short held unless the node is running.
    #[pyclass(from_py_object)]
    #[derive(Clone)]
    pub struct NodeEndToken(pub Arc<MutexStd<Option<NodeEnd>>>);

    #[pymethods]
    impl NodeEndToken {
        pub fn empty(&self) -> PyResult<bool> {
            let Ok(guard) = &mut self.0.try_lock() else {
                return PyResult::Err(PyRuntimeError::new_err("End is occupied"));
            };
            Ok(guard.as_ref().is_some())
        }
        pub fn send(&self, packet: Packet) -> PyResult<()> {
            let Ok(guard) = &mut self.0.try_lock() else {
                return PyResult::Err(PyRuntimeError::new_err("End is occupied"));
            };
            let Some(node_end) = guard.as_mut() else {
                return PyResult::Err(PyRuntimeError::new_err("End is empty"));
            };
            match node_end.sender.try_send(packet) {
                Ok(_) => Ok(()),
                Err(err) => match err {
                    TrySendError::Closed(_) => Err(PyEOFError::new_err("End is closed")),
                    TrySendError::Full(_) => Err(PyBufferError::new_err("End is full")) 
                }
            }
        }
    }

    /// Basic node interface.
    /// 
    /// Unfortunately trait cannot be pymethods, so additional helper methods are added.
    #[async_trait]
    pub trait Node: Send {
        fn upstreams(&self) -> Vec<NodeEndToken>;
        fn downstreams(&self) -> Vec<NodeEndToken>;
        async fn run(&mut self) -> Result<Option<Signal>, &'static str>;
        /// Function for merging graphs
        fn nodes(&self) -> Option<Vec<NodeToken>> { None }
    }

    #[pyfunction]
    pub fn get_node_upstreams(node: &NodeToken) -> PyResult<Vec<NodeEndToken>> {
        match node.node.try_lock().as_mut() {
            Ok(node) => Ok(node.upstreams()),
            _ => Err(PyRuntimeError::new_err("Node is running"))
        }
    }

    #[pyfunction]
    pub fn get_node_downstreams(node: &NodeToken) -> PyResult<Vec<NodeEndToken>> {
        match node.node.try_lock().as_mut() {
            Ok(node) => Ok(node.downstreams()),
            _ => Err(PyRuntimeError::new_err("Node is running"))
        }
    }

    #[pyfunction]
    pub fn get_node_nodes(node: &NodeToken) -> PyResult<Option<Vec<NodeToken>>> {
        match node.node.try_lock().as_mut() {
            Ok(node) => Ok(node.nodes()),
            _ => Err(PyRuntimeError::new_err("Node is running"))
        }
    }

    /// General representation of a node.
    /// 
    /// The node lock is long held when running.
    #[pyclass(from_py_object, name="Node")] // `eq` / `hash` requires immutability so we'll custom memory id impl
    #[derive(Clone)]
    pub struct NodeToken {
        pub node: Arc<MutexTokio<Box<dyn Node>>>,
        pub signal_sender: Sender<Signal>
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
            let upstream_downstreams = upstream_guard.as_mut().downstreams();
            let downstream_upstreams = downstream_guard.as_mut().upstreams();
            let mut upstream_downstream = upstream_downstreams[downstream_index].0.try_lock().expect("Cannot lock node end");
            let mut downstream_upstream = downstream_upstreams[upstream_index].0.lock().expect("Cannot lock node end");
            let (sender1, receiver1) = channel(32);
            let (sender2, receiver2) = channel(32);
            *upstream_downstream = Some(NodeEnd {
                sender: sender1,
                receiver: receiver2
            });
            *downstream_upstream = Some(NodeEnd {
                sender: sender2,
                receiver: receiver1
            });
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
        pub fn merge(first: &mut NodeToken, second: &mut NodeToken) -> Result<NodeToken, &'static str> {
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
        fn nodes(&self) -> Option<Vec<NodeToken>> {
            Some(self.nodes.clone())
        }
    }

    #[pymethods]
    impl GraphNode {
        #[new]
        #[pyo3(signature = (nodes = None))]
        pub fn new(nodes: Option<Vec<NodeToken>>) -> NodeToken {
            let (signal_sender, signal_receiver) = channel(8);
            NodeToken {
                node: Arc::new(MutexTokio::new(Box::new(Self {
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
}

