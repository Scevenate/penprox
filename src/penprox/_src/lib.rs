mod _sdk;
mod _common;
mod _socks5;

pub use _sdk::sdk;
pub use _common::common;
pub use _socks5::socks5;

#[pyo3::pymodule]
mod penprox {
    #[pymodule_export]
    pub use crate::_sdk::sdk;
    #[pymodule_export]
    pub use crate::_common::common;
    #[pymodule_export]
    pub use crate::_socks5::socks5;

    use pyo3::prelude::*;

    #[pymodule_init]
    fn init(_py: &Bound<'_, PyModule>) -> PyResult<()> {
        tracing::info!("Penprox ok");
        Ok(())
    }
}
