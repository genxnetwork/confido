use pyo3::prelude::*;
use pyo3::wrap_pyfunction;
use crate::aTLS_connect;
// use openssl::x509::X509;
use tokio::runtime::Runtime;
use pyo3::types::PyBytes;

// rust function definition:
// pub async fn aTLS_connect(host: &str) -> Result<X509, Box<dyn Error>> 

#[pyfunction]
fn aTLS_connect_py(host: &str) -> PyResult<Py<PyBytes>> {
    let rt = Runtime::new().unwrap();
    match rt.block_on(aTLS_connect(host)) {
        Ok(result) => {
            pyo3::Python::with_gil(|py| {
                let x509_bytes = result.to_der().unwrap(); // Convert X509 to byte array
                Ok(PyBytes::new(py, &x509_bytes).into()) // Return byte array as Python bytes object
            })
        },
        Err(e) => Err(pyo3::exceptions::PyRuntimeError::new_err(format!("Failed to connect: {}", e))),
    }
}

#[pymodule]
fn confido(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(aTLS_connect_py, m)?)?;
    Ok(())
}
