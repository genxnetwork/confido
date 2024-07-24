use crate::trs::TRS;
use crate::nonce::{Nonce, Base64}; 
use serde::{Serialize, Deserialize};
use log::{info, debug, error};
use openssl::x509::X509;
use std::error::Error;
use crate::evidence::Evidence;
use anyhow::Context;

#[derive(Deserialize, Serialize)]
pub struct AttestationRequest {
    pub nonce: Base64, // todo change to Nonce
}

#[derive(Deserialize, Serialize)]
pub struct ModuleLoadOrder {
    pub kernel: String,
    pub order: Vec<String>,
}

#[derive(Deserialize, Serialize)]
pub struct AttestationResponse {
    pub evidence: Evidence,
    pub certificate: Vec<u8>, // can't use X509 as it non-serializable
    pub module_load_order: ModuleLoadOrder, // New field for module load order
    pub cgpu_attestation: serde_json::Value, // New field for GPU attestation
}

pub struct ATLS {
    // certificate: X509, read once from server and initilised into http client
    http_client: reqwest::Client,
}

pub async fn aTLS_connect(host: &str) -> Result<X509, Box<dyn Error>> {
    info!("fn aTLS_connect: {:?}", host.to_string());
    let mut nonce: Nonce = Nonce::generate();
    let request = AttestationRequest {
        nonce: nonce.clone().into(),
    };

    info!("Connecting to {} to gather evidence, nonce: {:?}", host, nonce.as_string());
    let body = reqwest::Client::new()
        .post(format!("{}/aTLS", host))
        .json(&serde_json::json!(request))
        .send().await?
        .text().await?;

    let response: AttestationResponse = serde_json::from_str(&body).context("Failed to deserialize JSON")?;
    debug!("aTLS response: {:#?}", response.evidence);
    info!("aTLS response successfully received");

    let super_nonce = nonce.extend(&X509::from_pem(&response.certificate).unwrap());
    response.evidence.verify(super_nonce)
        .map_err(|err| format!("Failed to verify evidence. Error: {}", err))?;

    let trs = TRS::get(&host).await?;
    let golden_aggregate_hex = trs.get_boot_aggregate_hash()?;

    let algo = response.evidence.get_algo().ok_or("Failed to determine evidence PCRs algorithm")?;
    let server_boot_aggregate_hash = response.evidence.get_boot_aggregate_hash(algo.clone())?;

    if golden_aggregate_hex == server_boot_aggregate_hash {
        info!("Boot aggregate hash matches");
    } else {
        return Err(format!("Boot aggregate hash mismatch: expected {}, got {}", golden_aggregate_hex, server_boot_aggregate_hash).into());
    }

    let (algo_name, expected_pcr10_value) = match trs.ima_calculate() {
        Ok(result) => result,
        Err(e) => {
            error!("Error calculating IMA: {}", e);
            return Err(e.into());
        }
    };
    let expected_pcr10_value_hex = hex::encode(&expected_pcr10_value);
    debug!("Expected PCR 10: {}: 0x{}", algo_name.to_str(), expected_pcr10_value_hex);
    
    let actual_pcr10_value_hex = match response.evidence.get_pcr(algo, 10) {
        Ok(pcr) => hex::encode(pcr),
        Err(e) => {
            error!("Failed to get PCR 10: {}", e);
            String::from("PCR 10 not found")
        }
    };
    debug!("Server's PCR 10: {}: 0x{}", algo_name.to_str(), actual_pcr10_value_hex);

    if expected_pcr10_value_hex == actual_pcr10_value_hex {
        info!("PCR 10 matches");
    } else {
        return Err(format!("PCR 10 mismatch: expected 0x{}, got 0x{}", hex::encode(&expected_pcr10_value), actual_pcr10_value_hex).into());
    }

    let certificate = X509::from_pem(&response.certificate)
        .map_err(|err| format!("Failed to parse aTLS certificate. Error: {}", err))?;
    info!("aTLS certificate verification successful");

    Ok(certificate)
}

impl ATLS {
    pub async fn connect(host: &str) -> Result<ATLS, Box<dyn Error>> {
        let certificate: X509 = aTLS_connect(host).await?;
        let reqwest_cert = reqwest::Certificate::from_der(&certificate.to_der().unwrap()).unwrap();
        let http_client = reqwest::Client::builder()
            .use_native_tls()
            .add_root_certificate(reqwest_cert)
            .build()?;
        
        Ok(ATLS {
            http_client: http_client
        })
    }

    async fn request(
        &self, 
        method: reqwest::Method, 
        url: &str, 
        body: Option<&str>
    ) -> Result<String, Box<dyn std::error::Error>> {
        log::debug!("Requesting URL: {}", url);
        let mut request_builder = self.http_client.request(method, url);
        if let Some(body) = body {
            request_builder = request_builder.body(body.to_string());
        }
        let res = request_builder.send().await.map_err(|e| {
            log::error!("Failed to send request: {}", e);
            e
        })?;
        let body = res.text().await.map_err(|e| {
            log::error!("Failed to read response body: {}", e);
            e
        })?;
        Ok(body)
    }

    pub async fn get(&self, url: &str) -> Result<String, Box<dyn std::error::Error>> {
        self.request(reqwest::Method::GET, url, None).await
    }
    
    pub async fn post(&self, url: &str, body: &str) -> Result<String, Box<dyn std::error::Error>> {
        self.request(reqwest::Method::POST, url, Some(body)).await
    }
    
    pub async fn put(&self, url: &str, body: &str) -> Result<String, Box<dyn std::error::Error>> {
        self.request(reqwest::Method::PUT, url, Some(body)).await
    }

    pub async fn patch(&self, url: &str, body: &str) -> Result<String, Box<dyn std::error::Error>> {
        self.request(reqwest::Method::PATCH, url, Some(body)).await
    }

    pub async fn delete(&self, url: &str, body: &str) -> Result<String, Box<dyn std::error::Error>> {
        self.request(reqwest::Method::DELETE, url, Some(body)).await
    }

    pub async fn head(&self, url: &str, body: &str) -> Result<String, Box<dyn std::error::Error>> {
        self.request(reqwest::Method::HEAD, url, Some(body)).await
    }
}