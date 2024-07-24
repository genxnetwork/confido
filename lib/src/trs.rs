use byteorder::{LittleEndian, WriteBytesExt};
use serde::{Serialize, Deserialize};
use log::{info, debug, error};
use std::io::Write;
use crate::pcr::{PCR};
use az_snp_vtpm::vtpm;
use std::env;
use tokio::net::lookup_host;
use reqwest::Url;

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
        let url = Url::parse(url).unwrap();
        let mut host = url.host_str().unwrap().to_string();
        if host == "127.0.0.1" || host == "localhost" {
            host = reqwest::get("https://api.ipify.org")
                .await?
                .text()
                .await?;
        }
        info!("Fetching TRS for {}", host);
        let home_dir = env::var("HOME")?;
        let token_path = format!("{}/.confido/trs.token", home_dir);
        let pat = std::fs::read_to_string(token_path)?
            .trim()
            .to_string();
        let trs = "genxnetwork/confido-private";
        let url = format!("https://api.github.com/repos/{}/contents/bb-attest-{}.json", trs, host).to_string();
        let client = reqwest::Client::new();
        let data = client.get(&url)
            .header("Accept", "application/vnd.github.raw+json")
            .header("User-Agent", "confido")
            .bearer_auth(pat)
            .send().await?
            .text().await?;
        let trs: TRS = serde_json::from_str(&data)?;
        Ok(trs)
    }

    pub fn get_boot_aggregate_hash(&self) -> Result<String, &'static str> {
        let entry = self.ima_measurements.iter().find(|&measurement| measurement.filename_hint == "boot_aggregate");
        match entry {
            Some(measurement) => {
                info!("TRS ima-template: {}", measurement.ima_template);
                debug!("TRS boot_aggregate template_hash: {}", measurement.template_hash);
                debug!("TRS boot_aggregate filedata_hash: {}", measurement.filedata_hash);
                Ok(measurement.filedata_hash.clone())
            }
            None => {
                Err("No entry found with filename_hint = 'boot_aggregate'")
            }
        }
    }

    fn ima_sig(&self) -> (vtpm::Algorithm, Vec<u8>) {
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
        (vtpm::Algorithm::Sha256, aggregated_pcr.value)
    }

    fn ima_ng(&self) -> (vtpm::Algorithm, Vec<u8>) {
        let mut aggregated_pcr = PCR::new(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, Some(vec![0; 20]));
        for measurement in &self.ima_measurements {
            let agg_pcr_bytes = aggregated_pcr.get().clone();
            let template_hash_bytes = measurement.template_hash.as_bytes();
            aggregated_pcr.extend(&[agg_pcr_bytes.as_slice(), template_hash_bytes].concat());
        }
        (vtpm::Algorithm::Sha1, aggregated_pcr.value)
    }

    pub fn ima_calculate(&self) -> Result<(vtpm::Algorithm, Vec<u8>), &'static str> {
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
