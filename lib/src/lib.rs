// use pyo3::pyclass;
// use wasm_bindgen::prelude::*;
pub mod atls;
pub mod evidence;
mod kds;
pub mod nonce;

extern crate crypto;
mod pcr;
mod quote;
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

pub mod vtpm;
