use crate::evidence::Evidence;
use crate::nonce::{Base64, Nonce};
use anyhow::Context;
use log::{debug, info};
use openssl::x509::X509;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::time::Duration;

pub const DEFAULT_TRS_REGISTRY: &str = "genxnetwork/confido-trusted-repository";

#[cfg(test)]
mod tests;

pub fn atls_debug() {
    let _ = env_logger::Builder::new()
        .filter_level(log::LevelFilter::Debug)
        .try_init();
}

#[derive(Deserialize, Serialize)]
pub struct AttestationRequest {
    pub nonce: Base64, // todo change to Nonce
}

#[derive(Deserialize, Serialize, Debug)]
pub struct ModuleLoadOrder {
    pub kernel: String,
    pub order: Vec<String>,
}

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Eq)]
pub struct IMALogEntry {
    pub name: String,
    #[serde(rename = "PCR")]
    pub pcr: u32,
    pub template_hash: String,
    pub ima_template: String,
    pub filedata_alg: String,
    pub filedata_hash: String,
    pub filename_hint: String,
}

#[derive(Deserialize, Serialize)]
pub struct AttestationResponse {
    pub evidence: Evidence,
    pub certificate: Vec<u8>, // can't use X509 as it non-serializable
}

#[derive(Deserialize)]
struct ServiceInfoDiscovery {
    #[serde(rename = "teeReport")]
    tee_report: TEEReportAdvertisement,
}

#[derive(Deserialize)]
struct TEEReportAdvertisement {
    endpoint: String,
    method: String,
    nonce: TEEReportNonce,
    response: TEEReportResponse,
}

#[derive(Deserialize)]
struct TEEReportNonce {
    name: String,
    #[serde(rename = "in")]
    location: String,
    encoding: String,
    #[serde(rename = "sizeBytes")]
    size_bytes: usize,
}

#[derive(Deserialize)]
struct TEEReportResponse {
    #[serde(rename = "evidenceField")]
    evidence_field: String,
    #[serde(rename = "certificateField")]
    certificate_field: String,
}

pub struct ATLS {
    // certificate: X509, read once from server and initilised into http client
    http_client: reqwest::Client,
}

pub async fn aTLS_connect(host: &str) -> Result<X509, Box<dyn Error>> {
    aTLS_connect_with_registry(host, DEFAULT_TRS_REGISTRY).await
}

pub async fn aTLS_connect_with_registry(
    host: &str,
    trs_registry: &str,
) -> Result<X509, Box<dyn Error>> {
    info!("fn aTLS_connect: {:?}", host.to_string());
    let mut nonce: Nonce = Nonce::generate();
    let request = AttestationRequest {
        nonce: nonce.clone().into(),
    };

    info!(
        "Connecting to {} to gather evidence, nonce: {:?}",
        host,
        nonce.as_string()
    );
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;

    let service_info_url =
        reqwest::Url::parse(&format!("{}/service-info", host.trim_end_matches('/')))?;
    let discovery: ServiceInfoDiscovery = client
        .get(service_info_url.clone())
        .send()
        .await?
        .error_for_status()?
        .json()
        .await
        .context("Failed to parse service-info TEE report advertisement")?;
    let ad = discovery.tee_report;
    if ad.endpoint != "/tee-report"
        || ad.method != "POST"
        || ad.nonce.name != "nonce"
        || ad.nonce.location != "body"
        || ad.nonce.encoding != "base64"
        || ad.nonce.size_bytes != 32
        || ad.response.evidence_field != "evidence"
        || ad.response.certificate_field != "certificate"
    {
        return Err("Unsupported service-info TEE report advertisement".into());
    }
    let report_url = service_info_url.join(&ad.endpoint)?;
    if report_url.origin() != service_info_url.origin() {
        return Err("TEE report endpoint must share the service-info origin".into());
    }
    let body = client
        .post(report_url)
        .json(&request)
        .send()
        .await?
        .error_for_status()?
        .text()
        .await?;

    let response: AttestationResponse =
        serde_json::from_str(&body).context("Failed to deserialize JSON")?;
    debug!("aTLS response: {:#?}", response.evidence);
    info!("aTLS response successfully received");

    let certificate =
        X509::from_pem(&response.certificate).context("Failed to parse aTLS certificate")?;
    let ima_binding = Evidence::ima_binding(&response.evidence.ima_measurements)?;
    let super_nonce = nonce.extend_binding(&certificate, &ima_binding);
    response
        .evidence
        .verify(super_nonce, host, trs_registry)
        .await
        .map_err(|err| format!("Failed to verify evidence. Error: {}", err))?;

    info!("aTLS certificate verification successful");

    Ok(certificate)
}

impl ATLS {
    pub async fn connect(host: &str) -> Result<ATLS, Box<dyn Error>> {
        let certificate: X509 = aTLS_connect(host).await?;
        Self::from_certificate(&certificate)
    }

    fn from_certificate(certificate: &X509) -> Result<ATLS, Box<dyn Error>> {
        let reqwest_cert = reqwest::Certificate::from_der(&certificate.to_der()?)?;
        let http_client = reqwest::Client::builder()
            .use_native_tls()
            .tls_built_in_root_certs(false)
            .add_root_certificate(reqwest_cert)
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(30))
            .build()?;

        Ok(ATLS { http_client })
    }

    async fn request(
        &self,
        method: reqwest::Method,
        url: &str,
        body: Option<&str>,
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

    pub async fn delete(
        &self,
        url: &str,
        body: &str,
    ) -> Result<String, Box<dyn std::error::Error>> {
        self.request(reqwest::Method::DELETE, url, Some(body)).await
    }

    pub async fn head(&self, url: &str, body: &str) -> Result<String, Box<dyn std::error::Error>> {
        self.request(reqwest::Method::HEAD, url, Some(body)).await
    }
}
