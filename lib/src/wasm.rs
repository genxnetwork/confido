use wasm_bindgen::prelude::*;
use confido::ATLS;

#[wasm_bindgen]
pub struct WasmATLS {
    atls: ATLS,
}

#[wasm_bindgen]
impl WasmATLS {
    #[wasm_bindgen]
    pub async fn connect(host: &str) -> Result<WasmATLS, JsValue> {
        let atls = ATLS::connect(host).await.map_err(|e| JsValue::from_str(&e.to_string()))?;
        Ok(WasmATLS { atls })
    }

    #[wasm_bindgen]
    pub async fn get(&self, url: &str) -> Result<String, JsValue> {
        self.atls.get(url).await.map_err(|e| JsValue::from_str(&e.to_string()))
    }

    #[wasm_bindgen]
    pub async fn post(&self, url: &str, body: &str) -> Result<String, JsValue> {
        self.atls.post(url, body).await.map_err(|e| JsValue::from_str(&e.to_string()))
    }

    #[wasm_bindgen]
    pub async fn put(&self, url: &str, body: &str) -> Result<String, JsValue> {
        self.atls.put(url, body).await.map_err(|e| JsValue::from_str(&e.to_string()))
    }

    #[wasm_bindgen]
    pub async fn patch(&self, url: &str, body: &str) -> Result<String, JsValue> {
        self.atls.patch(url, body).await.map_err(|e| JsValue::from_str(&e.to_string()))
    }

    #[wasm_bindgen]
    pub async fn delete(&self, url: &str, body: &str) -> Result<String, JsValue> {
        self.atls.delete(url, body).await.map_err(|e| JsValue::from_str(&e.to_string()))
    }

    #[wasm_bindgen]
    pub async fn head(&self, url: &str, body: &str) -> Result<String, JsValue> {
        self.atls.head(url, body).await.map_err(|e| JsValue::from_str(&e.to_string()))
    }
}
