use crate::atls::{
    aTLS_connect_with_registry, atls_debug as rust_atls_debug, DEFAULT_TRS_REGISTRY,
};
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use pyo3::wrap_pyfunction;
use tokio::runtime::Runtime;

#[pyfunction]
#[pyo3(signature = (host, trs_registry=None))]
fn aTLS_connect_py(
    py: Python<'_>,
    host: &str,
    trs_registry: Option<&str>,
) -> PyResult<Py<PyBytes>> {
    let bytes = py.allow_threads(|| {
        let rt = Runtime::new()
            .map_err(|err| pyo3::exceptions::PyRuntimeError::new_err(err.to_string()))?;
        let certificate = rt
            .block_on(aTLS_connect_with_registry(
                host,
                trs_registry.unwrap_or(DEFAULT_TRS_REGISTRY),
            ))
            .map_err(|err| {
                pyo3::exceptions::PyRuntimeError::new_err(format!("Failed to connect: {}", err))
            })?;
        certificate
            .to_der()
            .map_err(|err| pyo3::exceptions::PyRuntimeError::new_err(err.to_string()))
    })?;
    Ok(PyBytes::new(py, &bytes).into())
}

#[pyfunction]
fn atls_debug_py() {
    rust_atls_debug();
}

#[pyfunction]
fn atls_debug() {
    rust_atls_debug();
}

#[pymodule]
fn confido(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(aTLS_connect_py, m)?)?;
    m.add_function(wrap_pyfunction!(atls_debug_py, m)?)?;
    m.add_function(wrap_pyfunction!(atls_debug, m)?)?;
    Ok(())
}
