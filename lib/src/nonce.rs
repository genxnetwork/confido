use serde::{Serialize, Deserialize};
use openssl::x509::X509;
use rand::Rng;

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