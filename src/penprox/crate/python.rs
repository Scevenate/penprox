use crate::sdk::*;
use std::{pin::Pin, sync::OnceLock};
use async_trait::async_trait;
use futures::future::select_all;
use pyo3::{FromPyObject, exceptions::{PyRuntimeError, PyValueError}, prelude::*, pyclass, pymethods};
use pyo3_async_runtimes::TaskLocals;
use tokio::{sync::{mpsc::{Receiver, channel}, oneshot}};

/// A process-wide asyncio worker to run async python functions.
/// If you don't like that, don't pass it, and the `OnceLock` will be fine.
fn python_asyncio_worker(py: Python<'_>) -> PyResult<TaskLocals> {
    static PYTHON_ASYNCIO_WORKER: OnceLock<TaskLocals> = OnceLock::new();
    if let Some(locals) = PYTHON_ASYNCIO_WORKER.get() {
        return Ok(locals.clone());
    }
    let event_loop = py.import("asyncio")?.call_method0("new_event_loop")?;
    let locals = TaskLocals::new(event_loop.clone()).copy_context(py)?;
    let event_loop = event_loop.unbind();
    std::thread::Builder::new()
        .name("penprox-asyncio".into())
        .spawn(move || {
            Python::attach(|py| {
                let event_loop = event_loop.bind(py);
                match (|| -> PyResult<()> {
                    py.import("asyncio")?.call_method1("set_event_loop", (&event_loop,))?;
                    // No `asyncio.run` high level side effects, e.g. signal handlers
                    event_loop.call_method0("run_forever")?;
                    Ok(())
                })() {
                    Ok(()) => tracing::error!("Asyncio loop exited unexpectedly"),
                    Err(error) => {
                        error.print_and_set_sys_last_vars(py);
                        tracing::error!("Asyncio loop failed");
                    }
                }
            })
        })
        .map_err(|error| PyRuntimeError::new_err(format!("Cannot spawn asyncio thread: {error}")))?;
    if PYTHON_ASYNCIO_WORKER.set(locals.clone()).is_err() { // Race
        return Ok(PYTHON_ASYNCIO_WORKER.get().expect("Asyncio loop must be initialized").clone());
    }
    Ok(locals)
}

/// A function that wraps awaitable into a coroutine,
///  so it can go through `asyncio.run_coroutine_threadsafe`.
fn python_corotine_wrapper(py: Python<'_>) -> PyResult<&'static Py<PyAny>> {
    static WRAPPER: OnceLock<Py<PyAny>> = OnceLock::new();
    if WRAPPER.get().is_none() {
        let module = PyModule::from_code(
            py,
            c"async def into_corotine(awaitable):\n    return await awaitable\n",
            c"penprox_python_coroutine_wrapper.py",
            c"penprox_python_coroutine_wrapper"
        )?;
        let _ = WRAPPER.set(module.getattr("into_corotine")?.unbind());
    }
    Ok(WRAPPER.get().expect("Await driver must be initialized"))
}

/// `AbortOnDropHandle`, but for python task
struct PythonTask(Py<PyAny>);

impl Drop for PythonTask {
    fn drop(&mut self) {
        Python::attach(|py| {
            let future = self.0.bind(py);
            if future.call_method0("done").and_then(|done| done.is_truthy()).unwrap_or(true) {
                return;
            }
            let _ = future.call_method0("cancel");
        });
    }
}

/// Minimal python callback to send the result from asyncio back to tokio.
#[pyclass]
struct PythonTaskCompleter {
    sender: Option<oneshot::Sender<PyResult<Py<PyAny>>>>
}

#[pymethods]
impl PythonTaskCompleter {
    fn __call__(&mut self, future: Bound<'_, PyAny>) -> PyResult<()> {
        if let Some(sender) = self.sender.take() {
            let _ = sender.send(future.call_method0("result").map(Bound::unbind));
        }
        Ok(())
    }
}

/// High level handle to send python future into asyncio worker, wait for result or abort on drop.
#[allow(clippy::type_complexity)]
fn python_task(
    py: Python<'_>,
    locals: &TaskLocals,
    awaitable: Bound<'_, PyAny>
) -> PyResult<Pin<Box<dyn Future<Output = PyResult<Py<PyAny>>> + Send>>> {
    let coroutine = python_corotine_wrapper(py)?.bind(py).call1((awaitable,))?;
    let future = py.import("asyncio")?.call_method1("run_coroutine_threadsafe", (coroutine, locals.event_loop(py)))?;
    let (sender, receiver) = oneshot::channel();
    future.call_method1("add_done_callback", (PythonTaskCompleter { sender: Some(sender) },))?;
    let task = PythonTask(future.unbind());
    Ok(Box::pin(async move {
        let _task = task; // Cancels on drop if the caller aborts mid-await
        match receiver.await {
            Ok(result) => result,
            Err(_) => Python::attach(|py| {
                Err(PyErr::from_value(py.import("asyncio")?.call_method0("CancelledError")?))
            })
        }
    }))
}

#[derive(IntoPyObject, Debug)]
enum PythonCallbackArgumentObject {
    Packet(PyPacketToken),
    Signal(Signal),
    /// This value is just used to pass error within rust, it will not reach python
    Error(())
}

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
    pub callback: Py<PyAny>,
    pub locals: Option<TaskLocals>
}

impl PythonNode {
    #[allow(clippy::new_ret_no_self)]
    pub fn new<'py>(callback: Bound<'py, PyAny>, upstreams: usize, downstreams: usize) -> Result<NodeToken, &'static str> {
        if !callback.is_callable() {
            tracing::error!("Callback is not callable");
            return Err("Callback is not callable");
        }
        let locals = match callback
            .py()
            .import("inspect")
            .and_then(|inspect| inspect.call_method1("iscoroutinefunction", (&callback,)))
            .and_then(|is_coroutine| is_coroutine.extract::<bool>())
        {
            Ok(true) => match python_asyncio_worker(callback.py()) {
                Ok(locals) => Some(locals),
                Err(error) => {
                    tracing::error!("Cannot start asyncio runtime: {error}");
                    return Err("Cannot start asyncio runtime");
                }
            },
            Ok(false) => None,
            Err(error) => {
                tracing::error!("Cannot inspect callback: {error}");
                return Err("Cannot inspect callback");
            }
        };
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
                callback: callback.unbind(),
                locals
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
            let (channel_object, channel_index) = {
                let mut node_ends: Vec<Pin<Box<dyn Future<Output = (PythonCallbackArgumentObject, usize)> + Send + '_>>> = Vec::with_capacity(upstreams.len() + downstreams.len());
                for (index, receiver) in upstreams.iter_mut().enumerate() {
                    node_ends.push(Box::pin(async move {
                        match receiver.recv().await {
                            Some(packet) => (PythonCallbackArgumentObject::Packet(packet.into()), index),
                            None => (PythonCallbackArgumentObject::Error(()), 0) // This error is mapped to actual error later in loop
                        }
                    }));
                }
                for (index, receiver) in downstreams.iter_mut().enumerate() {
                    node_ends.push(Box::pin(async move {
                        match receiver.recv().await {
                            Some(packet) => (PythonCallbackArgumentObject::Packet(packet.into()), index),
                            None => (PythonCallbackArgumentObject::Error(()), 0)
                        }
                    }));
                }
                if node_ends.is_empty() {
                    match self.signal_receiver.recv().await {
                        Some(signal) => (PythonCallbackArgumentObject::Signal(signal), 0),
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
                                (PythonCallbackArgumentObject::Signal(signal), 0)
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
            if matches!(&channel_object, PythonCallbackArgumentObject::Error(())) {
                tracing::error!("End is closed");
                return Err(GraphError::Disconnected);
            }
            // Need to call it syncly first anyway
            let object = Python::attach(|py| -> PyResult<Py<PyAny>> {
                self.callback.call1(py, (channel_object, channel_index))
            });
            let result: PyResult<PythonCallbackReturnCode> = match object {
                Err(error) => Err(error),
                // There can be stuff like async `__call__`, unwrapped decorators that misses initial detection
                // So we treat init as early fetch and still do decisive branch at runtime here
                Ok(object) => match Python::attach(|py| object.bind(py).hasattr("__await__")) {
                    Err(error) => Err(error),
                    Ok(false) => Python::attach(|py| object.bind(py).extract::<PythonCallbackReturnCode>()),
                    Ok(true) => {
                        let locals = match &self.locals {
                            Some(locals) => Ok(locals.clone()),
                            None => Python::attach(python_asyncio_worker)
                        };
                        match locals {
                            Err(error) => Err(error),
                            Ok(locals) => match Python::attach(|py| {
                                python_task(py, &locals, object.into_bound(py))
                            }) {
                                Err(error) => Err(error),
                                // The future cancels its task if `run` is dropped mid-await
                                // This await is outside attached context
                                // Maybe should call it "surrounded" to be precise
                                Ok(future) => match future.await {
                                    Err(error) => Err(error),
                                    Ok(value) => Python::attach(|py| value.bind(py).extract::<PythonCallbackReturnCode>())
                                }
                            }
                        }
                    }
                }
            };
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
