
#[pyo3::pymodule]
mod common {
    use pyo3::prelude::*;
    #[cfg(feature = "library")]
    use crate::sdk::sdk::*;
    #[cfg(not(feature = "library"))]
    use sdk::sdk::*;

    use std::{sync::{Arc, Mutex as MutexStd}, future::Future, pin::Pin};
    use async_trait::async_trait;
    use pyo3::{FromPyObject, IntoPyObject, PyErr, PyResult, exceptions::{PyEOFError, PyValueError}, pyclass, pymethods};
    use tokio::{sync::{Mutex as MutexTokio, mpsc::{Receiver, channel}}};
    use futures::future::select_all;


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

    #[pyclass]
    pub struct PythonNode {
        pub upstreams: Vec<NodeEndToken>,
        pub downstreams: Vec<NodeEndToken>,
        pub signal_receiver: Receiver<Signal>,
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
            u.resize_with(upstreams, || NodeEndToken(Arc::new(MutexStd::new(None))));
            d.resize_with(downstreams, || NodeEndToken(Arc::new(MutexStd::new(None))));
            let (signal_sender, signal_receiver) = channel(8);
            Ok(NodeToken {
                node: Arc::new(MutexTokio::new(Box::new(Self {
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
            if self.upstreams.iter().any(|upstream| upstream.0.lock().unwrap().is_none()) {
                return Err("Node is improperly connected");
            }
            if self.downstreams.iter().any(|downstream| downstream.0.lock().unwrap().is_none()) {
                return Err("Node is improperly connected");
            }
            let mut receivers: Vec<Receiver<Packet>> = self.upstreams.iter()
                .map(|upstream| upstream.0.lock().unwrap().take().expect("Connection is gone").receiver)
                .collect();
            loop {
                let (index, outcome) = match receivers.is_empty() {
                    true => {
                        let outcome = match self.signal_receiver.recv().await {
                            Some(signal) => PacketSignalError::Signal(signal),
                            None => PacketSignalError::Error(PyEOFError::new_err("Signal handle closed"))
                        };
                        (-1, outcome)
                    },
                    false => {
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
                            signal = self.signal_receiver.recv() => match signal {
                                Some(signal) => (-1, PacketSignalError::Signal(signal)),
                                None => (-1, PacketSignalError::Error(PyEOFError::new_err("Signal handle closed")))
                            },
                            (outcome, index, _) = select_all(packets) => (index as isize, outcome),
                        }
                    }
                };
                match Python::attach(|py| {
                    self.callback.call1(py, (index, PacketSignalError::from(outcome)))
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
            }
        }
    }
}
