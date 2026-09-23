use crate::atls::{IMALogEntry, ModuleLoadOrder};
use crate::nonce;
use crate::trs::TRS;
use crate::vtpm;
use az_snp_vtpm::hcl::HclReport;
use az_snp_vtpm::report::{AttestationReport, Validateable};
use log::{debug, error, info};
use nonce::Nonce;
use openssl::pkey::PKey;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt;

#[derive(Serialize, Deserialize)]
pub struct Evidence {
    pub report: Vec<u8>,
    quote: vtpm::Quote,
    cgpu_attestation: serde_json::Value,
    module_load_order: ModuleLoadOrder,
    pub ima_measurements: Vec<IMALogEntry>,
}

#[cfg(test)]
#[path = "evidence_tests.rs"]
mod tests;

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
    pub fn new(
        report: Vec<u8>,
        quote: vtpm::Quote,
        cgpu_attestation: serde_json::Value,
        module_load_order: ModuleLoadOrder,
        ima_measurements: Vec<IMALogEntry>,
    ) -> Self {
        Evidence {
            report,
            quote,
            cgpu_attestation,
            module_load_order,
            ima_measurements,
        }
    }

    pub fn ima_binding(measurements: &[IMALogEntry]) -> Result<Vec<u8>, serde_json::Error> {
        let serialized = serde_json::to_vec(measurements)?;
        Ok(ring::digest::digest(&ring::digest::SHA256, &serialized)
            .as_ref()
            .to_vec())
    }

    pub async fn verify(
        &self,
        nonce: &Nonce,
        host: &str,
        trs_registry: &str,
    ) -> Result<(), Box<dyn Error>> {
        let (snp_report, var_data_hash, pub_key) = self.parse_report()?;

        let cert_chain = crate::kds::get_cert_chain().await?;
        let vcek = crate::kds::get_vcek(&snp_report).await?;

        cert_chain.validate()?;
        vcek.validate(&cert_chain)?;
        snp_report.validate(&vcek)?;

        if var_data_hash != snp_report.report_data[..32] {
            return Err("var_data_hash mismatch".into());
        }
        crate::quote::verify(&self.quote, &pub_key, nonce.as_bytes())?;

        let trs = TRS::get(host, trs_registry).await?;
        self.verify_measurements(&trs)?;
        info!("Evidence successfully verified");
        Ok(())
    }

    fn parse_report(
        &self,
    ) -> Result<(AttestationReport, [u8; 32], PKey<openssl::pkey::Public>), Box<dyn Error>> {
        // The current HCL dependency uses unchecked slices and panics for
        // unsupported hash types. Contain those failures at the network input
        // boundary until its parsing accessors return checked Results.
        std::panic::catch_unwind(|| {
            let hcl_report = HclReport::new(self.report.clone())?;
            let var_data_hash = hcl_report.var_data_sha256();
            let ak_pub = hcl_report.ak_pub()?;
            let snp_report: AttestationReport = hcl_report.try_into()?;
            let der = ak_pub.key.try_to_der()?;
            let pub_key = PKey::public_key_from_der(&der)?;
            Ok((snp_report, var_data_hash, pub_key))
        })
        .map_err(|_| "Invalid HCL report metadata")?
    }

    fn verify_measurements(&self, trs: &TRS) -> Result<(), Box<dyn Error>> {
        let mismatches = trs.compare_measurements(&self.ima_measurements);
        if !mismatches.is_empty() {
            for mismatch in &mismatches {
                error!("IMA measurement mismatch: {}", mismatch);
            }
            return Err("IMA measurements do not match the trusted record".into());
        }
        info!("IMA measurements match the trusted record");
        let golden_aggregate_hex = trs.get_boot_aggregate_hash()?;

        let algo = trs.boot_aggregate_algorithm()?;
        let server_boot_aggregate_hash = self.get_boot_aggregate_hash(algo.clone())?;

        if golden_aggregate_hex.eq_ignore_ascii_case(&server_boot_aggregate_hash) {
            info!("Boot aggregate hash matches");
        } else {
            return Err("Boot aggregate hash mismatch".into());
        }

        let actual_pcr10 = self.get_pcr(algo.clone(), 10)?;
        trs.verify_pcr10(&self.module_load_order, algo, &actual_pcr10)?;

        Ok(())
    }

    pub fn get_boot_aggregate_hash(&self, algo: vtpm::Algorithm) -> Result<String, &'static str> {
        let algo_name = algo.to_str();
        info!(
            "calculating boot_aggregate {} hash using the vTPM Quote PCR values...",
            algo_name
        );
        let mut boot_aggregate = ring::digest::Context::new(algo.digest());

        let max_pcr_number = match algo_name {
            "sha1" => 8,
            "sha256" => 10,
            _ => return Err("Unsupported algorithm".into()),
        };

        match self.quote.get_pcr_bank(algo) {
            Some(pcr_bank) => {
                for pcr_number in 0..max_pcr_number {
                    let pcr_value = pcr_bank
                        .get(pcr_number)
                        .ok_or("Missing boot aggregate PCR")?;
                    if pcr_value.len() != pcr_bank.algo.length() {
                        return Err("Invalid boot aggregate PCR length");
                    }
                    debug!("PCR {}: {}", pcr_number, hex::encode(pcr_value));
                    boot_aggregate.update(pcr_value);
                }
                let boot_aggregate_hash = boot_aggregate.finish();
                let boot_aggregate_hex = hex::encode(boot_aggregate_hash.as_ref());
                info!(
                    "calculated boot_aggregate {} hash: {}",
                    algo_name, boot_aggregate_hex
                );
                Ok(boot_aggregate_hex.to_string())
            }
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

    pub fn get_pcr(
        &self,
        algo: vtpm::Algorithm,
        pcr_number: usize,
    ) -> Result<Vec<u8>, &'static str> {
        match self.quote.get_pcr_bank(algo) {
            Some(pcr_bank) => match pcr_bank.get(pcr_number) {
                Some(pcr_value) => Ok(pcr_value.clone()),
                None => Err("No PCR value found"),
            },
            None => Err("No PCR bank found"),
        }
    }
}
