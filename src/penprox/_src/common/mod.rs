
#[pyo3::pymodule]
mod common {
    use pyo3::prelude::*;
    #[cfg(feature = "library")]
    use crate::sdk::sdk::*;
    #[cfg(not(feature = "library"))]
    use sdk::sdk::*;


}
