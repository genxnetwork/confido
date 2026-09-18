use az_snp_vtpm::hcl::HclReport;
use az_snp_vtpm::report::{AttestationReport, Validateable};
use az_snp_vtpm::{amd_kds, vtpm};
use openssl::pkey::PKey;
use std::error::Error;
use log::{info, debug, error};
use crate::nonce;
use nonce::Nonce;
use serde::{Serialize, Deserialize};
use std::fmt;
use crate::atls::{IMALogEntry, ModuleLoadOrder};
use crate::trs::TRS;

#[derive(Serialize, Deserialize)]
pub struct Evidence {
    pub report: Vec<u8>,
    quote: vtpm::Quote,
    cgpu_attestation: serde_json::Value,
    module_load_order: ModuleLoadOrder,
    pub ima_measurements: Vec<IMALogEntry>,
}

impl fmt::Debug for Evidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let report_hex = hex::encode(&self.report);

        f.debug_struct("Evidence")
            .field("report", &report_hex)
            .field("quote", &self.quote)
            .finish()
    }
}

impl Evidence {
    pub fn new(report: Vec<u8>, quote: vtpm::Quote, cgpu_attestation: serde_json::Value, module_load_order: ModuleLoadOrder, ima_measurements: Vec<IMALogEntry>) -> Self {
        Evidence {report, quote, cgpu_attestation, module_load_order, ima_measurements}
    }

    pub fn ima_binding(measurements: &[IMALogEntry]) -> Result<Vec<u8>, serde_json::Error> {
        let serialized = serde_json::to_vec(measurements)?;
        Ok(ring::digest::digest(&ring::digest::SHA256, &serialized).as_ref().to_vec())
    }

    pub async fn verify(&self, nonce: &Nonce, host: &str, trs_registry: &str) -> Result<(), Box<dyn Error>> {
        let hcl_report = HclReport::new(self.report.clone())?;
        let var_data_hash = hcl_report.var_data_sha256();
        let ak_pub = hcl_report.ak_pub()?;
        let snp_report: AttestationReport = hcl_report.try_into()?;
    
        let cert_chain = amd_kds::get_cert_chain()?;
        // let vcek = Vcek::from_pem(&evidence.certs.vcek)?;
        let vcek = amd_kds::get_vcek(&snp_report)?;
    
        cert_chain.validate()?;
        vcek.validate(&cert_chain)?;
        snp_report.validate(&vcek)?;
    
        if var_data_hash != snp_report.report_data[..32] {
            return Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other, "var_data_hash mismatch")));
        }
        let der = ak_pub.key.try_to_der()?;
        let pub_key = PKey::public_key_from_der(&der)?;
        self.quote.verify(&pub_key, nonce.as_bytes())?;

        // part 2
        let trs = TRS::get(&host, trs_registry).await?;
        let mismatches = trs.compare_measurements(&self.ima_measurements);
        if !mismatches.is_empty() {
            for mismatch in &mismatches {
                error!("IMA measurement mismatch: {}", mismatch);
            }
            return Err("IMA measurements do not match the trusted record".into());
        }
        info!("IMA measurements match the trusted record");
        let golden_aggregate_hex = trs.get_boot_aggregate_hash()?;
    
        let algo = self.get_algo().ok_or("Failed to determine evidence PCRs algorithm")?;
        let server_boot_aggregate_hash = self.get_boot_aggregate_hash(algo.clone())?;
    
        if golden_aggregate_hex == server_boot_aggregate_hash {
            info!("Boot aggregate hash matches");
        } else {
            return Err(format!("Boot aggregate hash mismatch").into());
        }
    
        let actual_pcr10_value_hex = match self.get_pcr(algo.clone(), 10) {
            Ok(pcr) => hex::encode(pcr),
            Err(e) => {
                error!("Failed to get PCR 10: {}", e);
                return Err(e.into());
            }
        };

        let expected_pcr10_value_hex = if let Some(expected) = trs.pcr10_sha256.as_deref() {
            if algo != vtpm::Algorithm::Sha256 {
                return Err("TRS contains SHA-256 PCR 10 but quote uses another PCR bank".into());
            }
            if expected.len() != 64 || !expected.chars().all(|character| character.is_ascii_hexdigit()) {
                return Err("TRS SHA-256 PCR 10 has an invalid format".into());
            }
            expected.to_ascii_lowercase()
        } else {
            let (algo_name, expected_pcr10_value) = match trs.ima_calculate(&self.module_load_order, algo.clone()) {
                Ok(result) => result,
                Err(e) => {
                    error!("Error calculating IMA: {}", e);
                    return Err(e.into());
                }
            };
            let expected = hex::encode(&expected_pcr10_value);
            debug!("Expected PCR 10: {}: 0x{}", algo_name.to_str(), expected);
            expected
        };

        debug!("Server's PCR 10: {}: 0x{}", algo.to_str(), actual_pcr10_value_hex);
    
        if expected_pcr10_value_hex != actual_pcr10_value_hex {
            error!("PCR 10 mismatch");
            error!("Expected: {}", expected_pcr10_value_hex);
            error!("Actual:   {}", actual_pcr10_value_hex);
            return Err("PCR 10 mismatch".into());
        }
        info!("PCR 10 matches");

        info!("Evidence successfully verified");
    
        Ok(())
    }

    pub fn get_boot_aggregate_hash(&self, algo: vtpm::Algorithm) -> Result<String, &'static str> {
        let algo_name = algo.to_str();
        info!("calculating boot_aggregate {} hash using the vTPM Quote PCR values...", algo_name);
        let mut boot_aggregate = ring::digest::Context::new(algo.digest());  

        let max_pcr_number = match algo_name {
            "sha1" => 8,
            "sha256" => 10,
            _ => return Err("Unsupported algorithm".into()),
        };
    
        match self.quote.get_pcr_bank(algo) {
            Some(pcr_bank) => {
                for (pcr_number, pcr_value) in pcr_bank.pcr_values.iter().enumerate() {
                    if pcr_number < max_pcr_number {
                        debug!("PCR {}: {}", pcr_number, hex::encode(pcr_value));
                        boot_aggregate.update(pcr_value);
                    }
                }
                let boot_aggregate_hash = boot_aggregate.finish();
                let boot_aggregate_hex = hex::encode(boot_aggregate_hash.as_ref());
                info!("calculated boot_aggregate {} hash: {}", algo_name, boot_aggregate_hex);
                Ok(boot_aggregate_hex.to_string())
            },
            None => Err("No PCR bank found"),
        }
    }

    pub fn get_algo(&self) -> Option<vtpm::Algorithm> {
        if let Some(pcr_bank) = self.quote.get_pcr_bank(vtpm::Algorithm::Sha1) {
            Some(pcr_bank.algo.clone())
        } else if let Some(pcr_bank) = self.quote.get_pcr_bank(vtpm::Algorithm::Sha256) {
            Some(pcr_bank.algo.clone())
        } else {
            None
        }
    }

    pub fn get_pcr(&self, algo: vtpm::Algorithm, pcr_number: usize) -> Result<Vec<u8>, &'static str> {
        match self.quote.get_pcr_bank(algo) {
            Some(pcr_bank) => {
                match pcr_bank.get(pcr_number) {
                    Some(pcr_value) => Ok(pcr_value.clone()),
                    None => Err("No PCR value found"),
                }
            },
            None => Err("No PCR bank found"),
        }
    }

}