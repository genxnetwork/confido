use byteorder::{LittleEndian, WriteBytesExt};
use serde::{Serialize, Deserialize};
use log::{info, debug, error};
use std::io::Write;
use crate::pcr::{PCR};

#[derive(Debug, Serialize, Deserialize)]
struct IMALogEntry {
    #[serde(rename = "PCR")]
    pcr: u32,
    // name: String,
    template_hash: String,
    ima_template: String,
    filedata_alg: String,
    filedata_hash: String,
    filename_hint: String,
}

#[derive(Serialize, Deserialize)]
struct SysInfo {
    architecture: String,
    cpu_op_modes: Vec<String>,
    address_sizes: Vec<String>,
    // other fields...
}

#[derive(Serialize, Deserialize)]
pub struct TRS {
    ima_measurements: Vec<IMALogEntry>,
    // sys_info: SysInfo,
}

impl TRS {
    pub async fn get(url: &str) -> Result<TRS, Box<dyn std::error::Error>> {
        let client = reqwest::Client::new();
        let data = client.get(url)
            .send().await?
            .text().await?;
        let trs: TRS = serde_json::from_str(&data)?;
        Ok(trs)
    }

    pub fn get_boot_aggregate_hash(&self) -> String {
        let entry = self.ima_measurements.iter().find(|&measurement| measurement.filename_hint == "boot_aggregate");
        match entry {
            Some(measurement) => {
                info!("ima template: {}", measurement.ima_template);
                debug!("boot_aggregate filedata_hash from the trusted repo:\n{}", measurement.filedata_hash);
                measurement.filedata_hash.clone()
            }
            None => {
                error!("No entry found with filename_hint = 'boot_aggregate'");
                "".to_string()
            }
        }
    }

    fn ima_sig(&self) -> (String, Vec<u8>) {
        let mut aggregated_pcr = PCR::new(&ring::digest::SHA256, Some(vec![0; 32]));
        for measurement in &self.ima_measurements {
            let mut ima_data = vec![];
    
            let algo = "sha256:";
            let algo_len = 40;//lgo.len() as u32;
            ima_data.write_u32::<LittleEndian>(algo_len).unwrap();
            ima_data.write_all(algo.as_bytes()).unwrap();
            let _ = ima_data.write_u8(0);
    
            let filedata_hash_bytes = hex::decode(&measurement.filedata_hash).unwrap();
            ima_data.write_all(&filedata_hash_bytes).unwrap();
    
            let file = &measurement.filename_hint;
            let file_len = file.len() as u32;
            ima_data.write_u32::<LittleEndian>(file_len + 1).unwrap();
            ima_data.write_all(file.as_bytes()).unwrap();
            for _ in 0..5 { ima_data.write_u8(0).unwrap(); }
    
            let _ima_data_str: String = ima_data.iter().map(|&b| {
                if b.is_ascii() && !b.is_ascii_control() {
                    format!("{}", b as char)
                } else {
                    format!("\\x{:02x}", b)
                }
            }).collect();
            
            aggregated_pcr.extend(&ima_data);
        }
        ("sha256".to_string(), aggregated_pcr.value)
    }

    fn ima_ng(&self) -> (String, Vec<u8>) {
        let mut aggregated_pcr = PCR::new(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, Some(vec![0; 20]));
        for measurement in &self.ima_measurements {
            let agg_pcr_bytes = aggregated_pcr.get().clone();
            let template_hash_bytes = measurement.template_hash.as_bytes();
            aggregated_pcr.extend(&[agg_pcr_bytes.as_slice(), template_hash_bytes].concat());
        }
        ("sha1".to_string(), aggregated_pcr.value)
    }

    pub fn ima_calculate(&self) -> Result<(String, Vec<u8>), &'static str> {
        info!("Calculating the expected PCR10 using the actual boot_aggregate and trusted modules' hashes");

        let template = match self.ima_measurements.get(0) {
            Some(first_measurement) => &first_measurement.ima_template,
            None => {
                return Err("No IMA records found");
            }
        };
    
        if template != "ima-ng" && template != "ima-sig" {
            return Err("No known IMA template found in records");
        }
    
        // Check if all records have the same template
        if self.ima_measurements.iter().all(|measurement| measurement.ima_template == *template) {
            match template.as_str() {
                "ima-ng" => Ok(self.ima_ng()),
                "ima-sig" => Ok(self.ima_sig()),
                _ => Err("No known IMA template found in records"),
            }
        } else {
            Err("Mixed templates found in records")
        }
    }
}
