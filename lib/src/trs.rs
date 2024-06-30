use byteorder::{LittleEndian, WriteBytesExt};
use serde::{Serialize, Deserialize};
use log::{info, debug, error};
use ring::{digest};
use std::io::Write;
use crate::pcr::{PCR};

#[derive(Debug, Serialize, Deserialize)]
struct IMALogEntry {
    PCR: u32,
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

const MAX_DIGEST_SIZE: usize = 64;
const TCG_EVENT_NAME_LEN_MAX: usize = 255;
const MAX_TEMPLATE_SIZE: usize = 4096;




// struct Event {
//     header: Vec<u8>,
//     ima_data: Vec<u8>,
//     filename_len: u32,
// }

// impl Event {
//     fn new() -> Event {
//         let header = vec![0; TCG_EVENT_NAME_LEN_MAX + 1];
//         let ima_data = vec![0; TCG_EVENT_NAME_LEN_MAX + 1];
//         let filename_len = 0;
//         Event {
//             header,
//             ima_data,
//             filename_len,
//         }
//     }
// }


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
        debug!("data: {}", data);
        let trs: TRS = serde_json::from_str(&data)?;
        Ok(trs)
    }

    pub fn get_boot_aggregate_hash(&self) -> String {
        let entry = self.ima_measurements.iter().find(|&measurement| measurement.filename_hint == "boot_aggregate");
        match entry {
            Some(measurement) => {
                debug!("ima template:\n{}", measurement.ima_template);
                debug!("boot_aggregate filedata_hash from the trusted repo:\n{}", measurement.filedata_hash);
                measurement.filedata_hash.clone()
            }
            None => {
                debug!("No entry found with filename_hint = 'boot_aggregate'");
                "".to_string()
            }
        }
    }

    fn ima_sig(&self) -> (String, Vec<u8>) {
        let mut AggPCR = PCR::new(&ring::digest::SHA256, Some(vec![0; 32]));
        for measurement in &self.ima_measurements {
            let mut ima_data = vec![];
    
            let algo = "sha256:";
            let algo_len = 40;//lgo.len() as u32;
            ima_data.write_u32::<LittleEndian>(algo_len).unwrap();
            ima_data.write_all(algo.as_bytes()).unwrap();
            ima_data.write_u8(0);
    
            let filedata_hash_bytes = hex::decode(&measurement.filedata_hash).unwrap();
            ima_data.write_all(&filedata_hash_bytes).unwrap();
    
            let file = &measurement.filename_hint;
            let file_len = file.len() as u32;
            ima_data.write_u32::<LittleEndian>(file_len + 1).unwrap();
            ima_data.write_all(file.as_bytes()).unwrap();
            for _ in 0..5 { ima_data.write_u8(0).unwrap(); }
    
            let ima_data_str: String = ima_data.iter().map(|&b| {
                if b.is_ascii() && !b.is_ascii_control() {
                    format!("{}", b as char)
                } else {
                    format!("\\x{:02x}", b)
                }
            }).collect();
            
            AggPCR.extend(&ima_data);
        }
        ("sha256".to_string(), AggPCR.value)
    }

    fn ima_ng(&self) -> (String, Vec<u8>) {
        let mut AggPCR = PCR::new(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, Some(vec![0; 20]));
        for measurement in &self.ima_measurements {
            let agg_pcr_bytes = AggPCR.get().clone();
            let template_hash_bytes = measurement.template_hash.as_bytes();
            AggPCR.extend(&[agg_pcr_bytes.as_slice(), template_hash_bytes].concat());
        }
        ("sha1".to_string(), AggPCR.value)
    }

    pub fn ima_calculate(&self) -> (String, Vec<u8>) {
        debug!("Calculating the expected PCR10 using the actual boot_aggregate and trusted modules' hashes");
        self.ima_ng()
    }
}



// fn ima_measurement(filename: &str, reference_value: &str) {
//     let mut agg_pcr = PCR::new(vec![0; 32]);
//     let ref_pcr = PCR::new(Vec::from_hex(reference_value).unwrap());

//     let mut file = File::open(filename).unwrap();
//     let mut entry_num = 0;

//     loop {
//         let mut event = Event::new();
//         entry_num += 1;

//         if file.read_exact(&mut event.header).is_err() {
//             break;  // End of file
//         }

//         let pcr = LittleEndian::read_u32(&event.header[0..4]);
//         let digest = &event.header[4..24];
//         let name_len = LittleEndian::read_u32(&event.header[24..28]);
//         let mut name = vec![0; name_len as usize];
//         file.read_exact(&mut name).unwrap();

//         // Read the length of the IMA data from the file
//         let ima_data_len = file.read_u32::<LittleEndian>().unwrap();
//         println!("IMA Data len: {}", ima_data_len);

//         // Read the IMA data from the file
//         event.ima_data.resize(ima_data_len as usize, 0);
//         file.read_exact(&mut event.ima_data).unwrap();

//         // Process the IMA data here...

//         agg_pcr.extend(&event.ima_data);
//         println!("PCR Agg: {:?}", agg_pcr.value);
//         println!("PCR Ref: {:?}", ref_pcr.value);
//         println!("Entry {}: PCR Aggregate {} Reference PCR\n", entry_num, if agg_pcr.value != ref_pcr.value { "does not match" } else { "match" });
//     }
// }





// fn ima_ng(&self) -> (String, Vec<u8>) {
//     let mut aggregated_value_str = "0000000000000000000000000000000000000000".to_string();
//     // let current_pcr = initial_pcr_value();
//     // PCR10.update(boot_aggregate_hash.as_ref());
//     let mut AggPCR = PCR::new(Some(vec![0; 32]), "sha1".to_string());
//     for measurement in &self.ima_measurements {
//         // println!("IMA Data:  b'{}'", ima_data_str);

//         AggPCR.print("Aggregated PCR");
//         println!("{:?}", ima_data);

//         let mut filename_hint_bytes = measurement.filename_hint.clone().into_bytes();
//         filename_hint_bytes.resize(256, 0);
        
//         let mut template_data_bytes = filedata_hash_bytes;
//         template_data_bytes.extend(&filename_hint_bytes);
        
//         // Hash the template data
//         let mut context = Context::new(&SHA256);
//         context.update(&template_data_bytes);
//         let template_hash = context.finish();

//         // Extend the current PCR value with this new template hash
//         let current_pcr = extend_pcr(&current_pcr, template_hash.as_ref());
        
//         aggregated_value_str = aggregated_value_str + &hash_value_str;
//         let bytes = hex::decode(&aggregated_value_str).unwrap();
//         let mut context = digest::Context::new(&digest::SHA256); // Create a new SHA-1 hash object
//         context.update(&bytes);
//         let aggregated_value = context.finish();
//         aggregated_value_str = hex::encode(aggregated_value.as_ref());
//     }
//     // debug!("lll {}", hex::encode_upper(current_pcr));
//     // let PCR10_hash = PCR10.finish();
//     // debug!("Expected PCR 10: {}", hex::encode(PCR10_hash.as_ref()));
//     (AggPCR.algo_name, AggPCR.value)