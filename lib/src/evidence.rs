// use az_snp_vtpm::certs::Vcek;
use az_snp_vtpm::hcl::HclReport;
use az_snp_vtpm::report::{AttestationReport, Validateable};
use az_snp_vtpm::{amd_kds, imds, vtpm};
use serde::{Serialize, Deserialize};
use openssl::pkey::PKey;
// use openssl::x509::X509;
use std::error::Error;
use log::{info, debug, error};
use ring::digest;
use crate::nonce;
use nonce::Nonce;

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
    
        Ok(())
    }

    pub fn get_boot_aggregate_hash(&self) -> String {
        debug!("calculating boot_aggregate hash from the vTPM Quote PCR values...");
        let pcr_values: Vec<_> = self.quote.pcrs_sha256().collect();
        let mut boot_aggregate = digest::Context::new(&digest::SHA256);  
    
        for (pcr_number, pcr_value) in &pcr_values {
            if *pcr_number < 10 {
                debug!("PCR {}: {}", pcr_number, hex::encode(pcr_value));
                boot_aggregate.update(*pcr_value);
            }
        }
        let mut boot_aggregate_hash = boot_aggregate.finish();
        let boot_aggregate_hex = hex::encode(boot_aggregate_hash.as_ref());
        debug!("boot_aggregate hash calculated using the vTPM Quote PCR values:\n{}", boot_aggregate_hex);
        boot_aggregate_hex.to_string()
    }

    pub fn get_pcr(&self, pcr_number: usize) -> Option<Vec<u8>> {
        self.quote.pcrs_sha256().find(|(number, _)| *number == pcr_number).map(|(_, value)| value.to_vec())
    }
}