use wasm_bindgen::prelude::*;
#[wasm_bindgen]
pub fn verify(
    report: &[u8],
    amd_chain: &[u8],
    vcek: &[u8],
    reference: &[u8],
    policy: &[u8],
    expected_nonce: &[u8],
    evaluation_time: f64,
) -> Result<String, JsValue> {
    if !evaluation_time.is_finite()
        || evaluation_time.fract() != 0.0
        || !(0.0..=253402300799.0).contains(&evaluation_time)
    {
        return Err(JsValue::from_str("Invalid evaluation time"));
    }
    let nonce: [u8; 32] = expected_nonce
        .try_into()
        .map_err(|_| JsValue::from_str("Expected 32-byte nonce"))?;
    let r = confido::verify(
        confido::VerificationInput {
            report_json: report,
            amd_chain_pem: amd_chain,
            vcek_der: vcek,
            reference_json: reference,
        },
        policy,
        &confido::VerificationContext {
            expected_nonce: nonce,
            evaluation_unix_seconds: evaluation_time as i64,
        },
    )
    .map_err(|e| JsValue::from_str(&e.to_string()))?;
    serde_json::to_string(&r).map_err(|e| JsValue::from_str(&e.to_string()))
}
#[wasm_bindgen]
pub fn inspect_requirements(report: &[u8]) -> Result<String, JsValue> {
    serde_json::to_string(
        &confido::inspect_requirements(report).map_err(|e| JsValue::from_str(&e.to_string()))?,
    )
    .map_err(|e| JsValue::from_str(&e.to_string()))
}

#[wasm_bindgen]
pub fn build_info() -> String {
    (serde_json::json!({"core": confido::build_info(), "wrapper": {
    "version": env!("CARGO_PKG_VERSION"), "source_sha256": env!("CONFIDO_SOURCE_SHA256"),
    "target": env!("CONFIDO_TARGET"), "rustc": env!("CONFIDO_RUSTC"), "flags": env!("CONFIDO_BUILD_FLAGS"), "features": env!("CONFIDO_BUILD_FEATURES"), "build_profile": env!("CONFIDO_BUILD_PROFILE")}})).to_string()
}
