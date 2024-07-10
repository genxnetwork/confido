
// use pyo3::pyclass;
// use wasm_bindgen::prelude::*;
pub mod evidence;
pub mod nonce;
pub mod atls;

extern crate crypto;
mod pcr; 
mod trs;
mod pylib;

// use pyo3::pymodule;
// use pyo3::Python;
// use pyo3::types::PyModule;
// use pyo3::PyResult;

// #[pymodule]
// fn confido(_py: Python, m: &PyModule) -> PyResult<()> {
//     m.add_class::<ATLS>()?;
//     Ok(())
// }
