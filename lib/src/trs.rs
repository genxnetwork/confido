use byteorder::{LittleEndian, WriteBytesExt};
use serde::{Serialize, Deserialize};
use log::{info, debug, error};
use std::io::Write;
use crate::pcr::{PCR};
use az_snp_vtpm::vtpm;
use std::env;
use tokio::net::lookup_host;
use reqwest::Url;
use ring::digest::{Context, SHA1_FOR_LEGACY_USE_ONLY};

#[derive(Debug, Serialize, Deserialize)]
struct IMALogEntry {
    name: String,
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
        let pat = match std::fs::read_to_string(token_path) {
            Ok(content) => content.trim().to_string(),
            Err(_) => return Err("Failed to read the token file. Please make sure the token file exists and is readable.".into()),
        };
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

    // fn ima_ng(&self) -> (vtpm::Algorithm, Vec<u8>) {
    //     let mut aggregated_pcr = PCR::new(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, Some(vec![0; 20]));
    //     for measurement in &self.ima_measurements {
    //         let agg_pcr_bytes = hex::encode(aggregated_pcr.get());
            
    //         // let template_hash_bytes = measurement.template_hash;
    //         aggregated_pcr.extend(&[agg_pcr_bytes, measurement.template_hash.clone()].concat().as_bytes());
    //         debug!("ima-ng: {}, {}", measurement.name, hex::encode(aggregated_pcr.get()));
    //     }
    //     (vtpm::Algorithm::Sha1, aggregated_pcr.value)
    // }

    // fn ima_ng(&self) -> (vtpm::Algorithm, Vec<u8>) {
    //     let mut pcr = PCR::new(&SHA1_FOR_LEGACY_USE_ONLY, None); // initial value
    
    //     for measurement in &self.ima_measurements {
    //         let hash_value = measurement.template_hash.clone();
    //         debug!("ima-ng: {}, {}", measurement.name, hash_value);
    
    //         let concatenated_string = format!("{}{}", hex::encode(pcr.get()), hash_value);
    //         debug!("concatenated_string: {}", concatenated_string);
    //         // Convert the hex string to bytes
    //         let data = hex::decode(concatenated_string).expect("Failed to decode hex string");
    
    //         // Extend the PCR with the data
    //         pcr.extend(&data);
    //     }
    
    //     (vtpm::Algorithm::Sha1, pcr.get())
    // }

    fn ima_ng(&self) -> (vtpm::Algorithm, Vec<u8>) {
        let mut aggregated_value = "0000000000000000000000000000000000000000".to_string(); // initial value
    
        for measurement in &self.ima_measurements {
            let hash_value = measurement.template_hash.clone();
            debug!("ima-ng: {}", measurement.name);
    
            // The hexadecimal string to be hashed
            let concatenated_string = aggregated_value + &hash_value;
    
            // Convert the hex string to bytes
            let data = hex::decode(concatenated_string).expect("Failed to decode hex string");
    
            // Create a new SHA-1 hash object
            let mut context = Context::new(&SHA1_FOR_LEGACY_USE_ONLY);
    
            // Update the hash object with the bytes
            context.update(&data);
    
            // Get the bytes of the digest
            aggregated_value = hex::encode(context.finish().as_ref());
        }
    
        (vtpm::Algorithm::Sha1, hex::decode(aggregated_value).expect("Failed to decode hex string"))
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
