#![allow(non_snake_case)] // Preserve the published Python compatibility name.
use crate::atls::{
    aTLS_connect_with_registry, atls_debug as rust_atls_debug, DEFAULT_TRS_REGISTRY,
};
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use pyo3::wrap_pyfunction;
use tokio::runtime::Runtime;

#[allow(non_snake_case)] // Published compatibility name.
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

/// A live, origin-scoped client. Offline appraisal cannot construct this class.
#[pyclass]
struct AttestedSession {
    runtime: Runtime,
    client: Option<crate::appraisal::AppraisedClient>,
    result: String,
}
#[pymethods]
impl AttestedSession {
    #[getter]
    fn result_json(&self) -> String {
        self.result.clone()
    }

    fn request(
        &self,
        py: Python<'_>,
        method: &str,
        url: &str,
        headers: Vec<(String, String)>,
        body: &[u8],
    ) -> PyResult<(u16, Vec<(String, String)>, Py<PyBytes>)> {
        let client = self.client.as_ref().ok_or_else(|| {
            pyo3::exceptions::PyRuntimeError::new_err("Application admission was withheld")
        })?;
        let (status, headers, body) = py
            .allow_threads(|| {
                self.runtime
                    .block_on(client.request(method, url, &headers, body.to_vec()))
                    .map_err(|e| e.to_string())
            })
            .map_err(pyo3::exceptions::PyRuntimeError::new_err)?;
        Ok((status, headers, PyBytes::new(py, &body).into()))
    }
}
fn py_error(e: impl ToString) -> PyErr {
    pyo3::exceptions::PyRuntimeError::new_err(e.to_string())
}

#[pyfunction]
fn discover_py(py: Python<'_>, config_json: &str) -> PyResult<String> {
    let config = serde_json::from_str(config_json).map_err(py_error)?;
    py.allow_threads(|| {
        Runtime::new()
            .map_err(|e| e.to_string())?
            .block_on(crate::appraisal::discover(&config))
            .map(|v| v.to_string())
            .map_err(|e| e.to_string())
    })
    .map_err(py_error)
}

#[pyfunction]
#[pyo3(signature = (config_json, preview_json, bundle_path=None))]
fn connect_py(
    py: Python<'_>,
    config_json: &str,
    preview_json: &str,
    bundle_path: Option<&str>,
) -> PyResult<AttestedSession> {
    let config = serde_json::from_str(config_json).map_err(py_error)?;
    let preview = serde_json::from_str(preview_json).map_err(py_error)?;
    let runtime = Runtime::new().map_err(py_error)?;
    rust_atls_debug();
    let _run_log = match bundle_path {
        Some(path) => Some(
            crate::run_log::Guard::open(
                &std::path::Path::new(path).with_extension("attestation.log"),
            )
            .map_err(py_error)?,
        ),
        None => None,
    };
    let outcome =
        py.allow_threads(|| runtime.block_on(crate::appraisal::connect(&config, preview)));
    if let Some(path) = bundle_path {
        let path = std::path::Path::new(path);
        if let Some(bundle) = &outcome.bundle {
            crate::appraisal::save_private_json(path, bundle).map_err(py_error)?;
        }
        crate::appraisal::save_private_json(&path.with_extension("result.json"), &outcome.result)
            .map_err(py_error)?;
    }
    Ok(AttestedSession {
        runtime,
        client: outcome.client,
        result: serde_json::to_string(&outcome.result).map_err(py_error)?,
    })
}

#[pyfunction]
fn appraise_offline_py(
    py: Python<'_>,
    bundle_json: &str,
    config_json: &str,
    evaluation_time: i64,
) -> PyResult<String> {
    if bundle_json.len() > crate::appraisal::MAX_BUNDLE {
        return Err(py_error("Bundle exceeds 16 MiB"));
    }
    let bundle = serde_json::from_str(bundle_json).map_err(py_error)?;
    let config = serde_json::from_str(config_json).map_err(py_error)?;
    let result = py.allow_threads(|| crate::appraisal::appraise(&bundle, &config, evaluation_time));
    serde_json::to_string(&result).map_err(py_error)
}

#[pymodule]
fn confido(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    m.add_class::<AttestedSession>()?;
    m.add_function(wrap_pyfunction!(discover_py, m)?)?;
    m.add_function(wrap_pyfunction!(connect_py, m)?)?;
    m.add_function(wrap_pyfunction!(appraise_offline_py, m)?)?;
    m.add_function(wrap_pyfunction!(aTLS_connect_py, m)?)?;
    m.add_function(wrap_pyfunction!(atls_debug_py, m)?)?;
    m.add_function(wrap_pyfunction!(atls_debug, m)?)?;
    Ok(())
}
