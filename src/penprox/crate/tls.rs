use crate::sdk::*;
use std::{collections::HashMap, io::{ErrorKind, Read, Write}, path::PathBuf, sync::Arc};
use async_trait::async_trait;
use pyo3::{exceptions::{PyFileNotFoundError, PyValueError}, prelude::*};
use rustls::{ClientConfig, ClientConnection, Connection as TLSConnection, RootCertStore, ServerConfig, ServerConnection, pki_types::{CertificateDer, PrivateKeyDer, ServerName}};
use tokio::{sync::{OwnedMutexGuard, mpsc::{Receiver, Sender, channel}}, task::JoinSet};

/// `ClientConfig` or `ServerConfig`
#[derive(Clone, Debug)]
enum TLSMode {
    Server(Arc<ServerConfig>),
    Client(Arc<ClientConfig>)
}

/// TLS server node with one cipher upstream and one plaintext downstream.
#[derive(Debug)]
pub struct TLSServerNode {
    cipher: NodeUpstreamEndToken,
    clear: NodeDownstreamEndToken,
    signal_receiver: Receiver<Signal>,
    config: Arc<ServerConfig>
}

impl TLSServerNode {
    #[allow(clippy::new_ret_no_self)]
    pub fn new(certificates: Vec<CertificateDer<'static>>, key: PrivateKeyDer<'static>) -> Result<NodeToken, String> {
        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certificates, key)
            .map_err(|error| format!("Invalid certificate or private key: {error}"))?;
        let (signal_sender, signal_receiver) = channel(SIGNAL_BUFFER_SIZE);
        let cipher = NodeUpstreamEndToken::new();
        let clear = NodeDownstreamEndToken::new();
        Ok(NodeToken::new(
            Box::new(Self {
                cipher: cipher.clone(),
                clear: clear.clone(),
                signal_receiver,
                config: Arc::new(config)
            }),
            signal_sender,
            NodeUpstreamInterface::new(vec![cipher]),
            NodeDownstreamInterface::new(vec![clear])
        ))
    }
}

/// TLS client node, has one upstream (clear) and one downstream (cipher).
#[derive(Debug)]
pub struct TLSClientNode {
    clear: NodeUpstreamEndToken,
    cipher: NodeDownstreamEndToken,
    signal_receiver: Receiver<Signal>,
    config: Arc<ClientConfig>
}

impl TLSClientNode {
    #[allow(clippy::new_ret_no_self)]
    pub fn new() -> NodeToken {
        let config = ClientConfig::builder()
            .with_root_certificates(RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() })
            .with_no_client_auth();
        let (signal_sender, signal_receiver) = channel(SIGNAL_BUFFER_SIZE);
        let clear = NodeUpstreamEndToken::new();
        let cipher = NodeDownstreamEndToken::new();
        NodeToken::new(
            Box::new(Self {
                clear: clear.clone(),
                cipher: cipher.clone(),
                signal_receiver,
                config: Arc::new(config)
            }),
            signal_sender,
            NodeUpstreamInterface::new(vec![clear]),
            NodeDownstreamInterface::new(vec![cipher])
        )
    }
}

/// The server certificate chain and private key are loaded from PEM files.
/// The certificate file may contain the whole chain; the key file may be
/// PKCS#1, PKCS#8 or SEC1.
#[pyfunction]
#[pyo3(name = "TLSNode", signature = (cert_and_key=None))]
pub(crate) fn tls_node(cert_and_key: Option<(PathBuf, PathBuf)>) -> PyResult<NodeToken> {
    let Some((certificate, key)) = cert_and_key else {
        return Ok(TLSClientNode::new());
    };
    let certificate_bytes = std::fs::read(&certificate).map_err(PyFileNotFoundError::new_err)?;
    let mut certificate_reader = &certificate_bytes[..];
    let certificate_chain = rustls_pemfile::certs(&mut certificate_reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| PyValueError::new_err(format!("Cannot parse certificate: {error}")))?;
    if certificate_chain.is_empty() {
        return Err(PyValueError::new_err("No certificate found"));
    }
    let key_bytes = std::fs::read(&key).map_err(PyFileNotFoundError::new_err)?;
    let mut key_reader = &key_bytes[..];
    let key_der = rustls_pemfile::private_key(&mut key_reader)
        .map_err(|error| PyValueError::new_err(format!("Cannot parse private key: {error}")))?
        .ok_or(PyValueError::new_err("No private key found"))?;
    TLSServerNode::new(certificate_chain, key_der).map_err(PyValueError::new_err)
}

#[async_trait]
impl Node for TLSServerNode {
    #[tracing::instrument(name="TLSServerNode::run", skip_all)]
    async fn run(&mut self) -> Result<Option<Signal>, GraphError> {
        let cipher_sender = self.cipher.sender().map_err(GraphError::from)?;
        let cipher_receiver = self.cipher.receiver().map_err(GraphError::from)?;
        let clear_sender = self.clear.sender().map_err(GraphError::from)?;
        let clear_receiver = self.clear.receiver().map_err(GraphError::from)?;
        tls_run::<Downward>(
            cipher_sender,
            cipher_receiver,
            clear_sender,
            clear_receiver,
            &mut self.signal_receiver,
            TLSMode::Server(self.config.clone())
        ).await
    }
}

#[async_trait]
impl Node for TLSClientNode {
    #[tracing::instrument(name="TLSClientNode::run", skip_all)]
    async fn run(&mut self) -> Result<Option<Signal>, GraphError> {
        let clear_sender = self.clear.sender().map_err(GraphError::from)?;
        let clear_receiver = self.clear.receiver().map_err(GraphError::from)?;
        let cipher_sender = self.cipher.sender().map_err(GraphError::from)?;
        let cipher_receiver = self.cipher.receiver().map_err(GraphError::from)?;
        tls_run::<Upward>(
            cipher_sender,
            cipher_receiver,
            clear_sender,
            clear_receiver,
            &mut self.signal_receiver,
            TLSMode::Client(self.config.clone())
        ).await
    }
}

/// Shared runtime for both TLS server and client.
///
/// Downward `D` is server (decrypting).
#[allow(clippy::mutable_key_type)]
#[tracing::instrument(name="tls_run", skip_all)]
async fn tls_run<D: Direction>(
    cipher_sender: Sender<D::BackwardPacket>,
    mut cipher_receiver: OwnedMutexGuard<Receiver<D::ForwardPacket>>,
    clear_sender: Sender<D::ForwardPacket>,
    mut clear_receiver: OwnedMutexGuard<Receiver<D::BackwardPacket>>,
    signal_receiver: &mut Receiver<Signal>,
    mode: TLSMode
) -> Result<Option<Signal>, GraphError> {
    signal_receiver.clear();
    let trigger_is_cipher = matches!(&mode, TLSMode::Server(_));
    #[allow(clippy::type_complexity)]
    let mut dispatch: HashMap<ConnectionToken, (Sender<D::ForwardPacket>, Sender<D::BackwardPacket>)> = HashMap::new();
    let mut handlers: JoinSet<(ConnectionToken, Option<Signal>)> = JoinSet::new();
    loop {
        tokio::select! {
            biased;
            signal = signal_receiver.recv() => match signal {
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
                    tracing::warn!("TLS handler task failed: {error}");
                    continue;
                }
                Some(Ok((connection, signal))) => {
                    dispatch.remove(&connection);
                    if let Some(signal) = signal {
                        tracing::warn!("TLS handler returned signal {:?}, propagating", signal);
                        return Ok(Some(signal));
                    }
                    continue;
                }
            },
            packet = cipher_receiver.recv() => match packet {
                Some(packet) if packet.is_syn() && trigger_is_cipher => {
                    if !matches!(packet.connection().transport(), Transport::TCP) {
                        tracing::debug!("TLS is only supported over TCP");
                        cipher_sender.send(D::BackwardPacket::new_fin(packet.connection().clone())).await?;
                        continue;
                    }
                    let connection = packet.connection().clone();
                    let (cipher_dispatch, cipher_handler) = channel(CONNECTION_BUFFER_SIZE);
                    let (clear_dispatch, clear_handler) = channel(CONNECTION_BUFFER_SIZE);
                    dispatch.insert(connection.clone(), (cipher_dispatch, clear_dispatch));
                    handlers.spawn(tls_handler::<D>(
                        connection,
                        cipher_handler,
                        clear_handler,
                        cipher_sender.clone(),
                        clear_sender.clone(),
                        mode.clone()
                    ));
                },
                Some(packet) if packet.is_syn() => {
                    tracing::debug!("Received invalid SYN packet");
                    cipher_sender.send(D::BackwardPacket::new_fin(packet.connection().clone())).await?;
                },
                Some(packet) => {
                    match dispatch.get(packet.connection()) {
                        Some((sender, _)) => { let _ = sender.send(packet).await; },
                        None if !packet.is_fin() => {
                            tracing::debug!("Received packet that does not belong");
                            cipher_sender.send(D::BackwardPacket::new_fin(packet.connection().clone())).await?;
                        },
                        None => continue
                    }
                },
                None => return Ok(None)
            },
            packet = clear_receiver.recv() => match packet {
                Some(packet) if packet.is_syn() && !trigger_is_cipher => {
                    if !matches!(packet.connection().transport(), Transport::TCP) {
                        tracing::debug!("TLS is only supported over TCP");
                        clear_sender.send(D::ForwardPacket::new_fin(packet.connection().clone())).await?;
                        continue;
                    }
                    let connection = packet.connection().clone();
                    let (cipher_dispatch, cipher_handler) = channel(CONNECTION_BUFFER_SIZE);
                    let (clear_dispatch, clear_handler) = channel(CONNECTION_BUFFER_SIZE);
                    dispatch.insert(connection.clone(), (cipher_dispatch, clear_dispatch));
                    handlers.spawn(tls_handler::<D>(
                        connection,
                        cipher_handler,
                        clear_handler,
                        cipher_sender.clone(),
                        clear_sender.clone(),
                        mode.clone()
                    ));
                },
                Some(packet) if packet.is_syn() => {
                    tracing::debug!("Received invalid SYN packet");
                    clear_sender.send(D::ForwardPacket::new_fin(packet.connection().clone())).await?;
                },
                Some(packet) => {
                    match dispatch.get(packet.connection()) {
                        Some((_, sender)) => { let _ = sender.send(packet).await; },
                        None if !packet.is_fin() => {
                            tracing::debug!("Received packet that does not belong");
                            clear_sender.send(D::ForwardPacket::new_fin(packet.connection().clone())).await?;
                        },
                        None => continue
                    }
                },
                None => return Ok(None)
            }
        }
    }
}

/// Util: Close the one / two (established) side connections with catch `Signal` failure
async fn tls_close<D: Direction>(
    connection: ConnectionToken,
    cipher_sender: &Sender<D::BackwardPacket>,
    clear_sender: &Sender<D::ForwardPacket>,
    established: bool
) -> Option<Signal> {
    if cipher_sender.send(D::BackwardPacket::new_fin(connection.clone())).await.is_err() {
        return Some(Signal::SIGTERM);
    }
    if established && clear_sender.send(D::ForwardPacket::new_fin(connection)).await.is_err() {
        return Some(Signal::SIGTERM);
    }
    None
}

/// A rustls connection bundled with some missing buffers, and a simple interface.
///
/// Flush on write is necessary due to how rustls works. Follows the usual direction convention.
struct TLSStream {
    connection: TLSConnection,
    /// Ciphertext in
    cipher_buffer: Vec<u8>
}

impl TLSStream {
    fn new(mut connection: TLSConnection) -> Self {
        // A buffer large enough.
        //
        // Because we flush on write, this is only to buffer plaintext
        // during hanshake.
        connection.set_buffer_limit(Some(CONNECTION_BUFFER_SIZE * PACKET_DATA_SIZE));
        Self {
            connection,
            cipher_buffer: Vec::new()
        }
    }

    fn is_handshaking(&self) -> bool {
        self.connection.is_handshaking()
    }

    fn send_close_notify(&mut self) {
        self.connection.send_close_notify();
    }

    /// Push to cipher buffer.
    fn push_cipher(&mut self, data: &[u8]) {
        self.cipher_buffer.extend_from_slice(data);
    }

    /// Push to plaintext buffer.
    /// 
    /// Fails when buffer is full. However, the buffer is large enough that
    /// this should not happen if connection buffer rules are followed.
    fn push_plaintext(&mut self, data: &[u8]) -> Result<(), ()> {
        self.connection.writer().write_all(data).map_err(|error| {
            tracing::debug!("TLS write failed: {error}");
        })
    }

    /// Flush cipher out (rustls to sender) and cipher in (buffer to rustls).
    async fn flush_cipher<D: Direction>(
        &mut self,
        cipher_sender: &Sender<D::BackwardPacket>,
        connection: &ConnectionToken
    ) -> Result<(), Option<Signal>> {
        let mut tls_buffer = [0u8; PACKET_DATA_SIZE];
        loop {
            while self.connection.wants_write() {
                let Ok(count) = self.connection.write_tls(&mut &mut tls_buffer[..]) else {
                    tracing::warn!("TLS write failed");
                    return Err(None);
                };
                if count == 0 { // EOF
                    return Err(None);
                }
                if cipher_sender.send(D::BackwardPacket::new_data(connection.clone(), tls_buffer[..count].to_vec().into_boxed_slice()).await).await.is_err() {
                    return Err(Some(Signal::SIGTERM));
                }
            }
            if self.cipher_buffer.is_empty() || !self.connection.wants_read() {
                return Ok(());
            }
            let Ok(count) = self.connection.read_tls(&mut self.cipher_buffer.as_slice()) else {
                tracing::debug!("TLS read failed");
                return Err(None);
            };
            if count == 0 { // close_notify
                return Err(None);
            }
            self.cipher_buffer.drain(..count);
            if let Err(error) = self.connection.process_new_packets() {
                tracing::debug!("TLS processing failed: {error}");
                return Err(None);
            }
        }
    }

    /// Flush plaintext out (send).
    ///
    /// Plaintext in is directly written into rustls in initial push.
    async fn flush_plaintext<D: Direction>(
        &mut self,
        clear_sender: &Sender<D::ForwardPacket>,
        connection: &ConnectionToken
    ) -> Result<(), Option<Signal>> {
        let mut plain_buffer = [0u8; PACKET_DATA_SIZE];
        loop {
            let data = {
                let mut reader = self.connection.reader();
                match reader.read(&mut plain_buffer) {
                    Ok(0) => return Ok(()),
                    Ok(count) => plain_buffer[..count].to_vec().into_boxed_slice(),
                    Err(error) if error.kind() == ErrorKind::WouldBlock => return Ok(()),
                    Err(_) => {
                        tracing::debug!("TLS plaintext read failed");
                        return Err(None);
                    }
                }
            };
            if clear_sender.send(D::ForwardPacket::new_data(connection.clone(), data).await).await.is_err() {
                return Err(Some(Signal::SIGTERM));
            }
        }
    }

    /// Full flush.
    async fn flush<D: Direction>(
        &mut self,
        cipher_sender: &Sender<D::BackwardPacket>,
        clear_sender: &Sender<D::ForwardPacket>,
        connection: &ConnectionToken
    ) -> Result<(), Option<Signal>> {
        loop { // rustls needs a clear out buffer so alternating loop is necessary
            self.flush_cipher::<D>(cipher_sender, connection).await?;
            self.flush_plaintext::<D>(clear_sender, connection).await?;
            if self.cipher_buffer.is_empty() || !self.connection.wants_read() {
                return Ok(());
            }
        }
    }
}

/// Takes over control until handshake is finished.
#[tracing::instrument(name="tls_handshake", skip_all)]
async fn tls_handshake<D: Direction>(
    connection: ConnectionToken,
    cipher_receiver: &mut Receiver<D::ForwardPacket>,
    clear_receiver: &mut Receiver<D::BackwardPacket>,
    cipher_sender: &Sender<D::BackwardPacket>,
    clear_sender: &Sender<D::ForwardPacket>,
    mode: TLSMode
) -> Result<TLSStream, Option<Signal>> {
    let is_client = matches!(&mode, TLSMode::Client(_));
    let mut established = false;
    let connection_tls = match &mode {
        TLSMode::Server(config) => match ServerConnection::new(config.clone()) {
            Ok(tls) => TLSConnection::Server(tls),
            Err(error) => {
                tracing::debug!("Cannot create TLS connection: {error}");
                if cipher_sender.send(D::BackwardPacket::new_fin(connection)).await.is_err() {
                    return Err(Some(Signal::SIGTERM));
                }
                return Err(None);
            }
        },
        TLSMode::Client(config) => {
            let server_name = match connection.host() {
                Host::Domain(domain) => ServerName::try_from(domain).ok(),
                Host::IpAddr(ip_addr) => Some(ServerName::from(ip_addr))
            };
            let Some(server_name) = server_name else {
                tracing::debug!("Cannot derive TLS server name");
                return Err(tls_close::<D>(connection, cipher_sender, clear_sender, established).await);
            };
            match ClientConnection::new(config.clone(), server_name) {
                Ok(tls) => TLSConnection::Client(tls),
                Err(error) => {
                    tracing::debug!("Cannot create TLS connection: {error}");
                    return Err(tls_close::<D>(connection, cipher_sender, clear_sender, established).await);
                }
            }
        }
    };
    let mut tls = TLSStream::new(connection_tls);
    let mut queue: Vec<D::BackwardPacket> = Vec::new(); // emptied carriers for clear data already handed to rustls during the handshake; holding them keeps the connection permits backpressuring the clear side
    if is_client {
        if cipher_sender.send(D::BackwardPacket::new_syn(connection.clone())).await.is_err() {
            return Err(Some(Signal::SIGTERM));
        }
        established = true;
        match tls.flush_cipher::<D>(cipher_sender, &connection).await {
            Ok(()) => {}
            Err(Some(signal)) => return Err(Some(signal)),
            Err(None) => return Err(tls_close::<D>(connection, cipher_sender, clear_sender, established).await)
        }
    }
    loop {
        tokio::select! {
            biased;
            packet = cipher_receiver.recv() => {
                let Some(packet) = packet else {
                    return Err(tls_close::<D>(connection, cipher_sender, clear_sender, established).await);
                };
                let detached: DetachedPacket = packet.into();
                match detached {
                    DetachedPacket::Data(attached) => {
                        tls.push_cipher(&attached.data);
                        match tls.flush_cipher::<D>(cipher_sender, &connection).await {
                            Ok(()) => {}
                            Err(Some(signal)) => return Err(Some(signal)),
                            Err(None) => return Err(tls_close::<D>(connection, cipher_sender, clear_sender, established).await)
                        }
                        if !tls.is_handshaking() {
                            break;
                        }
                    },
                    DetachedPacket::FIN(_) => return Err(tls_close::<D>(connection, cipher_sender, clear_sender, established).await),
                    DetachedPacket::SYN(_) => {
                        tracing::debug!("Received invalid SYN packet");
                        if cipher_sender.send(D::BackwardPacket::new_fin(connection)).await.is_err() {
                            return Err(Some(Signal::SIGTERM));
                        }
                        return Err(None);
                    }
                }
            },
            packet = clear_receiver.recv() => {
                let Some(mut packet) = packet else {
                    return Err(tls_close::<D>(connection, cipher_sender, clear_sender, established).await);
                };
                if packet.is_syn() {
                    if clear_sender.send(D::ForwardPacket::new_fin(connection)).await.is_err() {
                        return Err(Some(Signal::SIGTERM));
                    }
                    return Err(None);
                } else if packet.is_fin() {
                    return Err(tls_close::<D>(connection, cipher_sender, clear_sender, established).await);
                } else {
                    // Keep emptied packets attached to backpressure
                    let data = std::mem::replace(packet.data_mut().expect("Clear data packet has data"), Vec::new().into_boxed_slice());
                    if tls.push_plaintext(&data).is_err() {
                        return Err(tls_close::<D>(connection, cipher_sender, clear_sender, established).await);
                    }
                    queue.push(packet);
                }
            }
        }
    }
    tracing::debug!("Established TLS connection");
    if !is_client {
        if clear_sender.send(D::ForwardPacket::new_syn(connection.clone())).await.is_err() {
            return Err(Some(Signal::SIGTERM));
        }
        established = true;
    }
    match tls.flush::<D>(cipher_sender, clear_sender, &connection).await {
        Ok(()) => {}
        Err(Some(signal)) => return Err(Some(signal)),
        Err(None) => return Err(tls_close::<D>(connection, cipher_sender, clear_sender, established).await)
    }
    queue.clear();
    Ok(tls)
}

/// Actual handler of the TLS connection. Handshake + forward loop.
#[tracing::instrument(name="tls_handler", skip_all)]
async fn tls_handler<D: Direction>(
    connection: ConnectionToken,
    mut cipher_receiver: Receiver<D::ForwardPacket>,
    mut clear_receiver: Receiver<D::BackwardPacket>,
    cipher_sender: Sender<D::BackwardPacket>,
    clear_sender: Sender<D::ForwardPacket>,
    mode: TLSMode
) -> (ConnectionToken, Option<Signal>) {
    let mut tls = match tls_handshake::<D>(connection.clone(), &mut cipher_receiver, &mut clear_receiver, &cipher_sender, &clear_sender, mode).await {
        Ok(tls) => tls,
        Err(signal) => return (connection, signal)
    };
    // Established: relay transparently.
    loop {
        tokio::select! {
            biased;
            packet = cipher_receiver.recv() => {
                let Some(packet) = packet else {
                    return (connection.clone(), tls_close::<D>(connection, &cipher_sender, &clear_sender, true).await);
                };
                let detached: DetachedPacket = packet.into();
                match detached {
                    DetachedPacket::Data(attached) => {
                        tls.push_cipher(&attached.data);
                        match tls.flush::<D>(&cipher_sender, &clear_sender, &connection).await {
                            Ok(()) => {}
                            Err(Some(signal)) => return (connection, Some(signal)),
                            Err(None) => return (connection.clone(), tls_close::<D>(connection, &cipher_sender, &clear_sender, true).await)
                        }
                    },
                    DetachedPacket::FIN(_) => {
                        tls.send_close_notify();
                        let _ = tls.flush::<D>(&cipher_sender, &clear_sender, &connection).await;
                        return (connection.clone(), tls_close::<D>(connection, &cipher_sender, &clear_sender, true).await);
                    },
                    DetachedPacket::SYN(_) => {
                        tracing::debug!("Received invalid SYN packet");
                        if cipher_sender.send(D::BackwardPacket::new_fin(connection.clone())).await.is_err() {
                            return (connection, Some(Signal::SIGTERM));
                        }
                        return (connection, None);
                    }
                }
            },
            packet = clear_receiver.recv() => {
                let Some(packet) = packet else {
                    return (connection.clone(), tls_close::<D>(connection, &cipher_sender, &clear_sender, true).await);
                };
                let detached: DetachedPacket = packet.into();
                match detached {
                    DetachedPacket::Data(attached) => {
                        if tls.push_plaintext(&attached.data).is_err() {
                            return (connection.clone(), tls_close::<D>(connection, &cipher_sender, &clear_sender, true).await);
                        }
                        match tls.flush::<D>(&cipher_sender, &clear_sender, &connection).await {
                            Ok(()) => {}
                            Err(Some(signal)) => return (connection, Some(signal)),
                            Err(None) => return (connection.clone(), tls_close::<D>(connection, &cipher_sender, &clear_sender, true).await)
                        }
                    },
                    DetachedPacket::FIN(_) => {
                        tls.send_close_notify();
                        let _ = tls.flush::<D>(&cipher_sender, &clear_sender, &connection).await;
                        return (connection.clone(), tls_close::<D>(connection, &cipher_sender, &clear_sender, true).await);
                    },
                    DetachedPacket::SYN(_) => {
                        if clear_sender.send(D::ForwardPacket::new_fin(connection.clone())).await.is_err() {
                            return (connection, Some(Signal::SIGTERM));
                        }
                        return (connection, None);
                    }
                }
            }
        }
    }
}
