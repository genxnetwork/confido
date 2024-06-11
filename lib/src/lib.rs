use az_snp_vtpm::certs::Vcek;
use az_snp_vtpm::hcl::HclReport;
use az_snp_vtpm::report::{AttestationReport, Validateable};
use openssl::pkey::PKey;
use az_snp_vtpm::{amd_kds, imds, vtpm};
use serde::{Serialize, Deserialize};
use rand::Rng;
use std::fmt::Debug;
use log::{info, debug, error};
use openssl::x509::X509;
use std::error::Error;
// use pyo3::pyclass;
// use wasm_bindgen::prelude::*;

#[derive(Serialize, Deserialize, Debug)]
pub struct Evidence {
    report: Vec<u8>,
    quote: vtpm::Quote,
    certs: imds::Certificates,
}

impl Evidence {
    pub fn new(report: Vec<u8>, quote: vtpm::Quote, certs: imds::Certificates) -> Self {
        Evidence {report, quote, certs}
    }
}

pub struct Verifier;

impl Verifier {
    pub fn verify(nonce: &Nonce, evidence: &Evidence) -> Result<(), Box<dyn Error>> {
        let Evidence { quote, report, .. } = evidence;
    
        let hcl_report = HclReport::new(report.clone())?;
        let var_data_hash = hcl_report.var_data_sha256();
        let ak_pub = hcl_report.ak_pub()?;
        let snp_report: AttestationReport = hcl_report.try_into()?;
    
        let cert_chain = amd_kds::get_cert_chain()?;
        let vcek = Vcek::from_pem(&evidence.certs.vcek)?;
    
        cert_chain.validate()?;
        vcek.validate(&cert_chain)?;
        snp_report.validate(&vcek)?;
    
        if var_data_hash != snp_report.report_data[..32] {
            return Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other, "var_data_hash mismatch")));
        }
        let der = ak_pub.key.try_to_der()?;
        let pub_key = PKey::public_key_from_der(&der)?;
        quote.verify(&pub_key, nonce.as_bytes())?;
    
        Ok(())
    }
}

#[derive(Deserialize, Serialize)]
pub struct Base64(String);

impl Base64 {
    pub fn from_base64(base64: String) -> Self {
        Base64(base64)
    }

    pub fn to_base64(&self) -> &String {
        &self.0
    }

    pub fn as_bytes(&self) -> Result<Vec<u8>, base64::DecodeError> {
        base64::decode(&self.0)
    }
}

#[derive(Clone)] 
pub struct Nonce {
    nonce: Vec<u8>,
}

impl Nonce {
    pub fn generate() -> Self {
        let mut rng = rand::thread_rng();
        let nonce: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
        Nonce { nonce }
    }

    pub fn read(base64: &Base64) -> Result<Self, &'static str> {
        match base64.as_bytes() {
            Ok(decoded) => {
                if decoded.len() != 32 {
                    Err("Nonce is not 32 bytes")
                } else {
                    Ok(Nonce { nonce: decoded })
                }
            },
            Err(_) => {
                Err("Failed to decode nonce")
            }
        }
    }

    pub fn extend(&mut self, certificate: &X509) -> &Nonce {
        let certificate_bytes = certificate.to_der().unwrap();
        let _ = self.nonce.iter().chain(certificate_bytes.iter()).cloned().collect::<Vec<u8>>();
        self
    }

    pub fn as_bytes(&self) -> &Vec<u8> {
        &self.nonce
    }

    pub fn as_string(&self) -> String {
        base64::encode(&self.nonce)
    }
}

impl Into<Base64> for Nonce {
    fn into(self) -> Base64 {
        let base64_encoded = base64::encode(&self.nonce);
        Base64::from_base64(base64_encoded)
    }
}

#[derive(Deserialize, Serialize)]
pub struct AttestationRequest {
    pub nonce: Base64,
}

#[derive(Deserialize, Serialize)]
pub struct AttestationResponse {
    pub evidence: Evidence,
    pub certificate: Vec<u8>, // can't use X509 as it non-serializable
}

pub struct ATLS {
    // certificate: X509, read once from server and initilised into http client
    http_client: reqwest::Client,
}

impl ATLS {
    pub async fn connect(host: &str) -> Result<ATLS, Box<dyn Error>> {
        let mut nonce: Nonce = Nonce::generate();
        let request = AttestationRequest {
            nonce: nonce.clone().into(),
        };
        debug!("nonce: {:?}", nonce.as_string());
        let client = reqwest::Client::new();
        let url = format!("{}/aTLS", host);
        info!("Connecting to {} to gather evidence", url);
        let res = client.post(url)
            .json(&serde_json::json!(request))
            .send()
            .await?;

        let body = res.text().await?;
        // debug!("response body: {:#?}", body);
        
        let result: Result<AttestationResponse, _> = serde_json::from_str(&body);
        let response = result.map_err(|err| {
            error!("Failed to deserialize JSON: {}", err);
            Box::new(err)
        })?;
        info!("aTLS response successfuly received");
        // debug!("{:#?}", response.evidence);
        // debug!("{:#?}", response.certificate);
        
        Verifier::verify(nonce.extend(&X509::from_pem(&response.certificate).unwrap()), &response.evidence)
            .map_err(|e| {
                error!("Failed to verify evidence: {}", e);
                e as Box<dyn std::error::Error>
            })?;
        
        let certificate = X509::from_pem(&response.certificate).map_err(|e| {
            error!("Failed to parse aTLS certificate: {}", e);
            Box::new(e)
        })?;
        info!("aTLS certificate verification successful");

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

// use pyo3::pymodule;
// use pyo3::Python;
// use pyo3::types::PyModule;
// use pyo3::PyResult;

// #[pymodule]
// fn confido(_py: Python, m: &PyModule) -> PyResult<()> {
//     m.add_class::<ATLS>()?;
//     Ok(())
// }
