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
use crate::atls::{IMALogEntry, ModuleLoadOrder};
use std::net::IpAddr;

#[derive(Debug, Serialize, Deserialize, Clone)]
struct SysInfo {
    architecture: String,
    cpu_op_modes: Vec<String>,
    address_sizes: Vec<String>,
    // other fields...
}

#[derive(Serialize, Deserialize)]
pub struct TRS {
    pub ima_measurements: Vec<IMALogEntry>,
    #[serde(default)]
    pub pcr10_sha256: Option<String>,
    // sys_info: SysInfo,
}

impl TRS {
    pub fn compare_measurements(&self, actual: &[IMALogEntry]) -> Vec<String> {
        let mut mismatches = Vec::new();
        if self.ima_measurements.len() != actual.len() {
            mismatches.push(format!("count trusted={} actual={}", self.ima_measurements.len(), actual.len()));
        }
        for (index, (trusted, observed)) in self.ima_measurements.iter().zip(actual.iter()).enumerate() {
            if trusted != observed {
                if trusted.name != observed.name {
                    mismatches.push(format!("index {} name trusted={} actual={}", index, trusted.name, observed.name));
                } else {
                    mismatches.push(format!("index {} module {} digest differs", index, trusted.name));
                }
            }
        }
        mismatches
    }

    pub async fn get(url: &str, trs_registry: &str) -> Result<TRS, Box<dyn std::error::Error>> {
        let url = Url::parse(url).unwrap();
        let host = url.host_str().ok_or("TRS URL has no host")?;
        let trs_host = if host == "127.0.0.1" || host == "localhost" {
            let public_ip = reqwest::get("https://api.ipify.org")
                .await?
                .text()
                .await?;
            info!("Resolved {} through ipify to {}", host, public_ip);
            public_ip
        } else if host.parse::<IpAddr>().is_ok() {
            host.to_string()
        } else {
            let port = url.port_or_known_default().ok_or("TRS URL has no port")?;
            let address = lookup_host((host, port))
                .await?
                .next()
                .ok_or("TRS host did not resolve")?;
            info!("Resolved {} to {}", host, address.ip());
            address.ip().to_string()
        };
        info!("Fetching TRS for {}", trs_host);
        
        // Try to use GitHub token if available, otherwise skip authentication
        let url = format!("https://api.github.com/repos/{}/contents/bb-attest-{}.json", trs_registry, trs_host).to_string();
        let client = reqwest::Client::new();
        
        let request = client.get(&url)
            .header("Accept", "application/vnd.github.raw+json")
            .header("User-Agent", "confido");
        
        // Only add auth if token file exists
        let request = if let Ok(pat) = std::fs::read_to_string(format!("{}/.confido/trs.token", env::var("HOME").unwrap_or_else(|_| ".".to_string()))) {
            request.bearer_auth(pat.trim())
        } else {
            request
        };
        
        let data = request.send().await?
            .error_for_status()?
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

    fn ima_sort(&self, module_load_order: &ModuleLoadOrder) -> Result<Vec<IMALogEntry>, &'static str> {
        if self.ima_measurements.len() != module_load_order.order.len() {
            return Err("TRS measurement count does not match the server IMA order");
        }

        let sorted_measurements: Vec<IMALogEntry> = module_load_order.order.iter()
            .zip(self.ima_measurements.iter())
            .map(|(expected, measurement)| {
                if expected != &measurement.name {
                    return Err("TRS measurement order does not match the server IMA order");
                }
                Ok(measurement.clone())
            })
            .collect::<Result<_, _>>()?;

        for (ima_measurement, sorted_measurement) in self.ima_measurements.iter().zip(sorted_measurements.iter()) {
            let match_status = if ima_measurement.name == sorted_measurement.name {
                "Match"
            } else {
                "No Match"
            };
            debug!("{:<50} {:<50} {}", ima_measurement.name, sorted_measurement.name, match_status);
        }

        Ok(sorted_measurements)
    }

    fn ima_sig(&self, module_load_order: &ModuleLoadOrder, algo: vtpm::Algorithm) -> Result<(vtpm::Algorithm, Vec<u8>), &'static str> {
        let digest_algo = match algo {
            vtpm::Algorithm::Sha256 => &ring::digest::SHA256,
            _ => &ring::digest::SHA256, // default to SHA256
        };
        
        let mut aggregated_pcr = PCR::new(digest_algo, Some(vec![0; 32]));
        let sorted_measurements = self.ima_sort(module_load_order)?;

        for measurement in sorted_measurements.iter() {
            debug!("ima-sig: {}", measurement.name);
            let mut ima_data = vec![];
    
            let algo_str = "sha256:";
            let algo_len = 40;
            ima_data.write_u32::<LittleEndian>(algo_len).unwrap();
            ima_data.write_all(algo_str.as_bytes()).unwrap();
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
        Ok((algo, aggregated_pcr.value))
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

    fn ima_ng(&self, module_load_order: &ModuleLoadOrder, algo: vtpm::Algorithm) -> Result<(vtpm::Algorithm, Vec<u8>), &'static str> {
        let digest_size = match algo {
            vtpm::Algorithm::Sha1 => 20,
            vtpm::Algorithm::Sha256 => 32,
            _ => return Err("Unsupported PCR algorithm"),
        };
        let sorted_measurements = self.ima_sort(module_load_order)?;

        if sorted_measurements.iter().any(|measurement| {
            measurement.pcr != 10
                || hex::decode(&measurement.template_hash)
                    .map(|digest| digest.len() != digest_size)
                    .unwrap_or(true)
        }) {
            return Err("TRS template hashes do not match the selected PCR bank");
        }

        let initial_hash = match algo {
            vtpm::Algorithm::Sha1 => "0000000000000000000000000000000000000000".to_string(),
            vtpm::Algorithm::Sha256 => "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
            _ => "0000000000000000000000000000000000000000".to_string(), // default to SHA1
        };
        
        let mut aggregated_value = initial_hash;
        for measurement in sorted_measurements.iter() {
            let hash_value = measurement.template_hash.clone();
            debug!("ima-ng: {}, hash_value: {}", measurement.name, hash_value);
    
            let concatenated_string = aggregated_value + &hash_value;
            let data = hex::decode(concatenated_string).expect("Failed to decode hex string");

            aggregated_value = match algo {
                vtpm::Algorithm::Sha1 => {
                    let mut context = Context::new(&SHA1_FOR_LEGACY_USE_ONLY);
                    context.update(&data);
                    hex::encode(context.finish().as_ref())
                },
                vtpm::Algorithm::Sha256 => {
                    let mut context = Context::new(&ring::digest::SHA256);
                    context.update(&data);
                    hex::encode(context.finish().as_ref())
                },
                _ => {
                    let mut context = Context::new(&SHA1_FOR_LEGACY_USE_ONLY);
                    context.update(&data);
                    hex::encode(context.finish().as_ref())
                }
            };
        }
    
        Ok((algo, hex::decode(aggregated_value).expect("Failed to decode hex string")))
    }

    pub fn ima_calculate(&self, module_load_order: &ModuleLoadOrder, algo: vtpm::Algorithm) -> Result<(vtpm::Algorithm, Vec<u8>), &'static str> {
        info!("Calculating PCR10 value from IMA measurements");
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
                "ima-ng" => self.ima_ng(&module_load_order, algo),
                "ima-sig" => self.ima_sig(&module_load_order, algo),
                _ => Err("No known IMA template found in records"),
            }
        } else {
            Err("Mixed templates found in records")
        }
    }
}
