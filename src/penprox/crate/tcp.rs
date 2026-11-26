use crate::sdk::*;
use std::{collections::HashMap, net::{IpAddr, SocketAddr}, time::Duration};
use async_trait::async_trait;
use pyo3::{prelude::*};
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::{TcpListener, TcpStream}, sync::mpsc::{Receiver, Sender, channel}, task::JoinSet};

pub const TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
pub const TCP_TIMEOUT: Duration = Duration::from_secs(300);

#[pyfunction]
#[pyo3(name = "TCPNode", signature = (address=None))]
pub(crate) fn tcp_node(address: Option<(IpAddr, u16)>) -> NodeToken {
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
