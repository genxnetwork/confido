use az_snp_vtpm::hcl::HclReport;
use az_snp_vtpm::report::{AttestationReport, Validateable};
use az_snp_vtpm::{amd_kds, vtpm};
use openssl::pkey::PKey;
use std::error::Error;
use log::{info, debug};
use crate::nonce;
use nonce::Nonce;
use serde::{Serialize, Deserialize};
use std::fmt;

#[derive(Serialize, Deserialize)]
pub struct Evidence {
    pub report: Vec<u8>,
    quote: vtpm::Quote,
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
    pub fn new(report: Vec<u8>, quote: vtpm::Quote) -> Self {
        Evidence {report, quote}
    }

    pub fn verify(&self, nonce: &Nonce) -> Result<(), Box<dyn Error>> {    
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
        self.quote.verify(&pub_key, nonce.as_bytes())?; // verifies signature and pcrs

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