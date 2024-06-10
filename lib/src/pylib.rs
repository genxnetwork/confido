use pyo3::prelude::*;
use pyo3::wrap_pyfunction;
use crate::ATLS;

use tokio::runtime::Runtime;

#[pymodule]
fn atls_py(_py: Python, m: &PyModule) -> PyResult<()> {
    #[pyclass]
    pub struct ATLS {
        // fields go here
    }

    #[pymethods]
    impl ATLS {
        #[staticmethod]
        fn connect(host: &str) -> PyResult<Self> {
            let rt = Runtime::new()?;
            let atls = rt.block_on(crate::ATLS::connect(host))?;
            Ok(atls)
        }

        // Add other methods here
    }

    m.add_class::<ATLS>()?;

    Ok(())
}