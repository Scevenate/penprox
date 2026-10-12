#[pyo3::pymodule]
mod common {
    #[cfg(feature = "library")]
    use crate::sdk::sdk::*;
    #[cfg(not(feature = "library"))]
    use sdk::sdk::*;

    use std::{collections::{HashMap}, net::{IpAddr, SocketAddr}};
    use async_trait::async_trait;
    use pyo3::{pyclass, pymethods};
    use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::{TcpListener, TcpStream}, sync::{mpsc::{Receiver, Sender, channel}}, task::JoinSet};

    async fn tcp_handler(
        mut stream: TcpStream,
        sender: Sender<Packet>,
        mut receiver: Receiver<Packet>,
        connection: ConnectionToken
    ) -> (ConnectionToken, Option<Signal>) {
        let _ = sender.send(Packet::new(connection.clone(), Payload::SYN).await).await;
        loop {
            let mut buffer = [0u8; 2048];
            tokio::select! {
                biased;
                packet = receiver.recv() => match packet {
                    Some(packet) => match &packet.payload {
                        Payload::SYN => {
                            let _ = sender.send(Packet::new(connection.clone(), Payload::FIN).await).await;
                            return (connection, None);
                        }
                        Payload::FIN => return (connection, None),
                        Payload::Data(data) => {
                            if stream.write_all(data).await.is_err() {
                                return (connection, None);
                            }
                        }
                    }
                    None => return (connection, Some(Signal::SIGTERM))
                },
                read = stream.read(&mut buffer) => match read {
                    Ok(0) | Err(_) => {
                        let _ = sender.send(Packet::new(connection.clone(), Payload::FIN).await).await;
                        return (connection, None);
                    }
                    Ok(count) => {
                        let data = buffer[..count].to_vec().into_boxed_slice();
                        if sender.send(Packet::new(connection.clone(), Payload::Data(data)).await).await.is_err() {
                            return (connection, Some(Signal::SIGTERM));
                        }
                    }
                }
            }
        }
    }

    /// Node that listens on one TCP socket and exposes one downstream edge.
    #[pyclass]
    pub struct UpstreamTCPNode {
        downstream: NodeEndToken,
        signal_receiver: Receiver<Signal>,
        address: SocketAddr
    }

    #[pymethods]
    impl UpstreamTCPNode {
        #[new]
        pub fn new(host: IpAddr, port: u16) -> NodeToken {
            let (signal_sender, signal_receiver) = channel(8);
            NodeToken::new(
                Box::new(Self {
                    downstream: NodeEndToken::new(),
                    signal_receiver,
                    address: SocketAddr::new(host, port)
                }),
                signal_sender
            )
        }
    }

    #[async_trait]
    impl Node for UpstreamTCPNode {
        fn upstreams(&self) -> Vec<NodeEndToken> {
            Vec::new()
        }
        fn downstreams(&self) -> Vec<NodeEndToken> {
            vec![self.downstream.clone()]
        }
        async fn run(&mut self) -> Result<Option<Signal>, &'static str> {
            let sender = self.downstream.sender().ok_or("Node is improperly connected")?;
            let mut receiver = self.downstream.receiver()?;
            while self.signal_receiver.try_recv().is_ok() {}
            let listener = TcpListener::bind(self.address).await.map_err(|_| "Cannot bind address")?;
            self.address = listener.local_addr().map_err(|_| "Cannot get address")?;
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
                        None => panic!("Awaiting non-empty join set that is empty"),
                        Some(Err(_)) => continue,
                        Some(Ok((connection, signal))) => {
                            dispatch.remove(&connection);
                            if let Some(signal) = signal {
                                return Ok(Some(signal));
                            }
                            continue;
                        }
                    },
                    accepted = listener.accept() => match accepted {
                        Ok((stream, peer)) => {
                            let connection = ConnectionToken::new(Host::IpAddr(peer.ip()), Transport::TCP, peer.port());
                            let (dispatch_sender, dispatch_receiver) = channel(ON_FLIGHT_SIZE);
                            dispatch.insert(connection.clone(), dispatch_sender);
                            handlers.spawn(tcp_handler(
                                stream,
                                sender.clone(),
                                dispatch_receiver,
                                connection
                            ));
                        },
                        _ => continue
                    },
                    packet = receiver.recv() => match packet {
                        Some(packet) => {
                            if let Some(sender) = dispatch.get(packet.connection()) {
                                let _ = sender.send(packet).await;
                            }
                        },
                        None => return Ok(None)
                    }
                }
            }
        }
    }
}
