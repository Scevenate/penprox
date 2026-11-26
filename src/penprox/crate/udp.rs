use crate::sdk::*;
use std::{collections::HashMap, net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr}, time::Duration};
use async_trait::async_trait;
use pyo3::{FromPyObject, prelude::*};
use tokio::{net::{UdpSocket}, sync::mpsc::{Receiver, channel}, time::{Instant, sleep_until}};

pub const UDP_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Clone, Copy, FromPyObject, Debug)]
pub(crate) enum UDPNodeMode {
    Upstream(IpAddr, u16),
    Downstream(AddressMode)
}

#[pyfunction]
#[pyo3(name = "UDPNode", signature = (mode=UDPNodeMode::Downstream(AddressMode::V4V6)))]
pub(crate) fn udp_node(mode: UDPNodeMode) -> NodeToken {
    match mode {
        UDPNodeMode::Upstream(ip, port) => UDPUpstreamNode::new(SocketAddr::new(ip, port)),
        UDPNodeMode::Downstream(mode) => UDPDownstreamNode::new(mode)
    }
}

/// Upstream UDP node that binds a port. Has one downstream.
#[derive(Debug)]
pub struct UDPUpstreamNode {
    end: NodeDownstreamEndToken,
    signal_receiver: Receiver<Signal>,
    address: SocketAddr
}

impl UDPUpstreamNode {
    #[allow(clippy::new_ret_no_self)]
    pub fn new(address: SocketAddr) -> NodeToken {
        let (signal_sender, signal_receiver) = channel(SIGNAL_BUFFER_SIZE);
        let end = NodeDownstreamEndToken::new();
        NodeToken::new(
            Box::new(Self {
                end: end.clone(),
                signal_receiver,
                address
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
impl Node for UDPUpstreamNode {
    async fn run(&mut self) -> Result<Option<Signal>, GraphError> {
        let sender = self.end.sender().map_err(GraphError::from)?;
        let mut receiver = self.end.receiver().map_err(GraphError::from)?;
        self.signal_receiver.clear();
        let socket = UdpSocket::bind(self.address).await.map_err(|error| {
            tracing::error!("Cannot bind address: {error}");
            GraphError::NodeError
        })?;
        self.address = socket.local_addr().map_err(|_| GraphError::Occupied)?;
        let mut connections: HashMap<SocketAddr, (ConnectionToken, Instant)> = HashMap::new();
        let mut buffer = [0u8; PACKET_DATA_SIZE];
        loop {
            let deadline = connections.values().map(|(_, deadline)| *deadline).min();
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
                packet = receiver.recv() => match packet {
                    Some(UpwardPacket::SYN(connection)) => {
                        sender.send(DownwardPacket::FIN(connection)).await?;
                        continue;
                    }
                    Some(UpwardPacket::FIN(connection)) => {
                        if let Host::IpAddr(ip_addr) = connection.host() {
                            connections.remove(&SocketAddr::new(ip_addr, connection.port()));
                        }
                    },
                    Some(UpwardPacket::Data(upward)) => {
                        match upward.connection().host() {
                            Host::Domain(_) => sender.send(DownwardPacket::FIN(upward.connection().clone())).await?,
                            Host::IpAddr(ip_addr) => {
                                socket.send_to(&upward.data[..], SocketAddr::new(ip_addr, upward.connection().port())).await.map_err(|error| {
                                    tracing::error!("UDP socket closed: {error}");
                                    GraphError::NodeError
                                })?;
                                if let Some((_, deadline)) = connections.get_mut(&SocketAddr::new(ip_addr, upward.connection().port())) {
                                    *deadline = Instant::now() + UDP_TIMEOUT;
                                }
                            }
                        }
                    },
                    None => return Ok(Some(Signal::SIGTERM))
                },
                accepted = socket.recv_from(&mut buffer) => {
                    let (count, peer) = match accepted {
                        Ok(result) => result,
                        Err(error) => {
                            tracing::error!("UDP receive failed: {error}");
                            return Ok(Some(Signal::SIGTERM));
                        }
                    };
                    let connection = match connections.get_mut(&peer) {
                        Some((connection, deadline)) => {
                            *deadline = Instant::now() + UDP_TIMEOUT;
                            connection.clone()
                        }
                        None => {
                            let connection = ConnectionToken::new(Host::IpAddr(peer.ip()), Transport::UDP, peer.port());
                            sender.send(DownwardPacket::SYN(connection.clone())).await?;
                            connections.insert(peer, (connection.clone(), Instant::now() + UDP_TIMEOUT));
                            connection
                        }
                    };
                    let data = buffer[..count].to_vec().into_boxed_slice();
                    if let Ok(downward) = ConnectionDownward::try_new(connection, data) { // Just drop UDP, it's proper "back pressure"
                        sender.send(DownwardPacket::Data(downward)).await?;
                    }
                },
                _ = async move {
                    match deadline {
                        Some(deadline) => sleep_until(deadline).await,
                        None => std::future::pending::<()>().await
                    }
                } => {
                    let now = Instant::now();
                    let expired: Vec<SocketAddr> = connections.iter()
                        .filter(|(_, (_, deadline))| *deadline <= now)
                        .map(|(peer, _)| *peer)
                        .collect();
                    for peer in expired {
                        if let Some((connection, _)) = connections.remove(&peer) {
                            sender.send(DownwardPacket::FIN(connection)).await?;
                        }
                    }
                }
            }
        }
    }
}

/// Downstream UDP node that serves out going UDP connections.
/// Has one upstream.
#[derive(Debug)]
pub struct UDPDownstreamNode {
    end: NodeUpstreamEndToken,
    signal_receiver: Receiver<Signal>,
    mode: AddressMode
}

impl UDPDownstreamNode {
    #[allow(clippy::new_ret_no_self)]
    pub fn new(mode: AddressMode) -> NodeToken {
        let (signal_sender, signal_receiver) = channel(SIGNAL_BUFFER_SIZE);
        let end = NodeUpstreamEndToken::new();
        NodeToken::new(
            Box::new(Self {
                end: end.clone(),
                signal_receiver,
                mode
            }),
            signal_sender,
            NodeUpstreamInterface::new(vec![end]),
            NodeDownstreamInterface::new(vec![])
        )
    }
}

#[async_trait]
impl Node for UDPDownstreamNode {
    async fn run(&mut self) -> Result<Option<Signal>, GraphError> {
        let sender = self.end.sender().map_err(GraphError::from)?;
        let mut receiver = self.end.receiver().map_err(GraphError::from)?;
        self.signal_receiver.clear();
        let socket_v4 = match self.mode {
            AddressMode::V6 => None,
            _ => Some(UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)).await.map_err(|error| {
                tracing::error!("Cannot bind ipv4 address: {error}");
                GraphError::NodeError
            })?),
            
        };
        let socket_v6 = match self.mode {
            AddressMode::V4 => None,
            _ => Some(UdpSocket::bind(SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)).await.map_err(|error| {
                tracing::error!("Cannot bind ipv6 address: {error}");
                GraphError::NodeError
            })?),
        };
        let mut connections: HashMap<SocketAddr, (ConnectionToken, Instant)> = HashMap::new();
        let mut buffer_v4 = [0u8; PACKET_DATA_SIZE];
        let mut buffer_v6 = [0u8; PACKET_DATA_SIZE];
        loop {
            let deadline = connections.values().map(|(_, deadline)| *deadline).min();
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
                packet = receiver.recv() => match packet {
                    Some(DownwardPacket::SYN(connection)) => {
                        match connection.host() {
                            Host::Domain(_) => sender.send(UpwardPacket::FIN(connection)).await?,
                            Host::IpAddr(ip_addr) => { connections.insert(SocketAddr::new(ip_addr, connection.port()), (connection, Instant::now() + UDP_TIMEOUT)); }
                        };
                    }
                    Some(DownwardPacket::FIN(connection)) => {
                        if let Host::IpAddr(ip_addr) = connection.host() {
                            connections.remove(&SocketAddr::new(ip_addr, connection.port()));
                        }
                    },
                    Some(DownwardPacket::Data(attached)) => {
                        match attached.connection().host() {
                            Host::Domain(_) => sender.send(UpwardPacket::FIN(attached.connection().clone())).await?,
                            Host::IpAddr(ip_addr) => {
                                let socket = match ip_addr {
                                    IpAddr::V4(_) => socket_v4.as_ref(),
                                    IpAddr::V6(_) => socket_v6.as_ref()
                                };
                                if let Some(socket) = socket {
                                    socket.send_to(&attached.data[..], SocketAddr::new(ip_addr, attached.connection().port())).await.map_err(|error| {
                                        tracing::error!("UDP socket closed: {error}");
                                        GraphError::NodeError
                                    })?;
                                };
                                if let Some((_, deadline)) = connections.get_mut(&SocketAddr::new(ip_addr, attached.connection().port())) {
                                    *deadline = Instant::now() + UDP_TIMEOUT;
                                }
                            }
                        }
                    },
                    None => return Ok(Some(Signal::SIGTERM))
                },
                accepted_v4 = socket_v4.as_ref().expect("Unwrapping None which is Some").recv_from(&mut buffer_v4), if socket_v4.is_some() => {
                    let (count, peer) = match accepted_v4 {
                        Ok(result) => result,
                        Err(error) => {
                            tracing::error!("UDP receive failed: {error}");
                            return Ok(Some(Signal::SIGTERM));
                        }
                    };
                    let connection = match connections.get_mut(&peer) {
                        Some((connection, deadline)) => {
                            *deadline = Instant::now() + UDP_TIMEOUT;
                            connection.clone()
                        }
                        None => continue
                    };
                    let data = buffer_v4[..count].to_vec().into_boxed_slice();
                    if let Ok(upward) = ConnectionUpward::try_new(connection, data) { // Just drop UDP, it's proper "back pressure"
                        sender.send(UpwardPacket::Data(upward)).await?;
                    }
                },
                accepted_v6 = socket_v6.as_ref().expect("Unwrapping None which is Some").recv_from(&mut buffer_v6), if socket_v6.is_some() => {
                    let (count, peer) = match accepted_v6 {
                        Ok(result) => result,
                        Err(error) => {
                            tracing::error!("UDP receive failed: {error}");
                            return Ok(Some(Signal::SIGTERM));
                        }
                    };
                    let connection = match connections.get_mut(&peer) {
                        Some((connection, deadline)) => {
                            *deadline = Instant::now() + UDP_TIMEOUT;
                            connection.clone()
                        }
                        None => continue
                    };
                    let data = buffer_v6[..count].to_vec().into_boxed_slice();
                    if let Ok(attached) = ConnectionUpward::try_new(connection, data) { // Just drop UDP, it's proper "back pressure"
                        sender.send(UpwardPacket::Data(attached)).await?;
                    }
                },
                _ = async move {
                    match deadline {
                        Some(deadline) => sleep_until(deadline).await,
                        None => std::future::pending::<()>().await
                    }
                } => {
                    let now = Instant::now();
                    let expired: Vec<SocketAddr> = connections.iter()
                        .filter(|(_, (_, deadline))| *deadline <= now)
                        .map(|(peer, _)| *peer)
                        .collect();
                    for peer in expired {
                        if let Some((connection, _)) = connections.remove(&peer) {
                            sender.send(UpwardPacket::FIN(connection)).await?;
                        }
                    }
                }
            }
        }
    }
}
