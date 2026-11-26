pub mod sdk;
pub mod tcp;
pub mod udp;
pub mod socks5;
pub mod dns;
pub mod python;
pub mod tls;

#[pyo3::pymodule]
mod penprox {
    #[pymodule_export] // Does not work on use const export
    const PACKET_DATA_SIZE: usize = super::sdk::PACKET_DATA_SIZE;

    #[pymodule_export]
    use super::sdk::{
        LogLevel,
        set_logger,
        ConnectionToken,
        PyPacketToken,
        NodeUpstreamEndToken,
        NodeDownstreamEndToken,
        NodeUpstreamInterface,
        NodeDownstreamInterface,
        NodeToken,
        GraphNode
    };
    #[pymodule_export]
    use super::tcp::{tcp_node};
    #[pymodule_export]
    use super::udp::{udp_node};
    #[pymodule_export]
    use super::socks5::{socks5_node};
    #[pymodule_export]
    use super::dns::{DNSNode};
    #[pymodule_export]
    use super::python::{PythonNode};
    #[pymodule_export]
    use super::tls::{tls_node};
}
