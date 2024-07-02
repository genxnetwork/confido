use std::sync::Arc;
use std::error::Error;
use std::fs;
use std::fs::File;
use std::io::{self, BufRead};
use log::{info, error, debug};
use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use confido::{AttestationRequest, AttestationResponse, Nonce, Evidence, ModuleLoadOrder};
use openssl::x509::X509;
use az_snp_vtpm::{imds, vtpm};
use serde_json::Value;
use regex::Regex;
use std::collections::HashMap;
use std::process::Command;

pub struct Attester;

impl Attester {
    pub fn gather_evidence(nonce: &Nonce) -> Result<Evidence, Box<dyn Error>> {
        let report = vtpm::get_report()?;
        let quote = vtpm::get_quote(nonce.as_bytes())?;
        let certs = imds::get_certs()?;
        Ok(Evidence::new(report, quote, certs))
    }
}

fn parse_gpu_attestation_output(output: &str) -> Result<Value, Box<dyn Error>> {
    let mut result = serde_json::json!({
        "Number of GPUs available": 0,
        "GPUs": [],
        "raw_gpu_report": output,
    });

    let re_number_of_gpus = Regex::new(r"Number of GPUs available : (\d+)").unwrap();
    let re_verifying_gpu = Regex::new(r"VERIFYING GPU : (\d+)").unwrap();
    let re_state = Regex::new(r"GPU is in expected state").unwrap();
    let re_verification = Regex::new(r"GPU (\d+) verified successfully").unwrap();
    let re_attestation = Regex::new(r"GPU Attested Successfully").unwrap();
    let re_driver_version = Regex::new(r"Driver version fetched : (\d+\.\d+\.\d+)").unwrap();
    let re_vbios_version = Regex::new(r"VBIOS version fetched : (\d+\.\d+\.\d+\.\d+)").unwrap();
    let re_attestation_report_signature_verification = Regex::new(r"Attestation report signature verification successful").unwrap();
    let re_attestation_report_verification = Regex::new(r"Attestation report verification successful").unwrap();

    let mut gpu_info = HashMap::new();
    let lines: Vec<&str> = output.lines().collect();
    let mut current_gpu: Option<serde_json::Value> = None;

    for line in lines {
        if let Some(caps) = re_number_of_gpus.captures(line) {
            result["Number of GPUs available"] = caps[1].parse::<i64>().unwrap().into();
        } else if let Some(caps) = re_verifying_gpu.captures(line) {
            if let Some(gpu) = current_gpu.take() {
                result["GPUs"].as_array_mut().unwrap().push(gpu);
            }
            let gpu_num = caps[1].parse::<i64>().unwrap();
            current_gpu = Some(serde_json::json!({
                "GPU": gpu_num,
                "Driver version fetched": "",
                "VBIOS version fetched": "",
                "Attestation report signature verification": "",
                "Attestation report verification": "",
                "attestation": "",
                "state": "",
                "verification": "",
            }));
            gpu_info.insert(gpu_num, serde_json::json!({
                "state": "",
                "verification": "",
                "attestation": "",
            }));
        } else if re_state.is_match(line) {
            let gpu_num = current_gpu.as_ref().unwrap()["GPU"].as_i64().unwrap();
            gpu_info.get_mut(&gpu_num).unwrap()["state"] = "GPU is in expected state.".into();
        } else if let Some(caps) = re_verification.captures(line) {
            let gpu_num = caps[1].parse::<i64>().unwrap();
            gpu_info.get_mut(&gpu_num).unwrap()["verification"] = format!("GPU {} verified successfully.", gpu_num).into();
        } else if re_attestation.is_match(line) {
            let gpu_num = current_gpu.as_ref().unwrap()["GPU"].as_i64().unwrap();
            gpu_info.get_mut(&gpu_num).unwrap()["attestation"] = "GPU Attested Successfully.".into();
        } else if let Some(caps) = re_driver_version.captures(line) {
            current_gpu.as_mut().unwrap()["Driver version fetched"] = caps[1].to_string().into();
        } else if let Some(caps) = re_vbios_version.captures(line) {
            current_gpu.as_mut().unwrap()["VBIOS version fetched"] = caps[1].to_string().into();
        } else if re_attestation_report_signature_verification.is_match(line) {
            current_gpu.as_mut().unwrap()["Attestation report signature verification"] = "successful".into();
        } else if re_attestation_report_verification.is_match(line) {
            current_gpu.as_mut().unwrap()["Attestation report verification"] = "successful".into();
        }
    }

    if let Some(gpu) = current_gpu.take() {
        result["GPUs"].as_array_mut().unwrap().push(gpu);
    }

    for (gpu_num, info) in gpu_info {
        let idx = result["GPUs"].as_array_mut().unwrap().iter().position(|g| g["GPU"] == gpu_num).unwrap();
        result["GPUs"][idx]["state"] = info["state"].clone();
        result["GPUs"][idx]["verification"] = info["verification"].clone();
        result["GPUs"][idx]["attestation"] = info["attestation"].clone();
    }

    Ok(result)
}

fn get_gpu_attestation() -> Result<Value, Box<dyn Error>> {
    let output = Command::new("python3")
        .arg("-m")
        .arg("verifier.cc_admin")
        .output()
        .expect("Failed to execute GPU attestation command");

    if !output.status.success() {
        return Err(Box::new(io::Error::new(io::ErrorKind::Other, "Failed to execute GPU attestation command")));
    }

    let output_str = String::from_utf8(output.stdout)?;
    parse_gpu_attestation_output(&output_str)
}

// Function to read the module load order
fn read_module_load_order() -> Result<(String, Vec<String>), Box<dyn Error>> {
    let path = "/sys/kernel/security/ima/ascii_runtime_measurements";
    let file = File::open(path)?;
    let reader = io::BufReader::new(file);

    let mut module_load_order = Vec::new();
    let mut kernel_version = String::new();

    for line in reader.lines() {
        let line = line?;
        if line.contains("module") {
            // Extract module path and name from the line
            let parts: Vec<&str> = line.split_whitespace().collect();
            if let Some(module_path) = parts.get(4) {
                let parts: Vec<&str> = module_path.split('/').collect();
                if let Some(module_name) = parts.last() {
                    module_load_order.push(module_name.to_string());
                }
                if kernel_version.is_empty() && parts.len() > 4 {
                    kernel_version = parts[4].to_string();
                }
            }
        }
    }

    Ok((kernel_version, module_load_order))
}

async fn atls_http_route(data: web::Json<AttestationRequest>, certificate: Arc<X509>) -> impl Responder {
    info!("Received attestation request");
    let mut nonce = match Nonce::read(&data.nonce) {
        Ok(nonce) => nonce,
        Err(e) => {
            error!("{}", e);
            return HttpResponse::InternalServerError().finish();
        }
    };

    let evidence = match Attester::gather_evidence(&nonce.extend(&certificate)) {
        Ok(evidence) => {
            info!("Successfully gathered evidence");
            evidence
        },
        Err(e) => {
            error!("Failed to gather evidence: {}", e);
            return HttpResponse::InternalServerError().finish();
        }
    };

    let (kernel_version, module_order) = match read_module_load_order() {
        Ok((version, order)) => (version, order),
        Err(e) => {
            error!("Failed to read module load order: {}", e);
            return HttpResponse::InternalServerError().finish();
        }
    };

    let cgpu_attestation = match get_gpu_attestation() {
        Ok(cgpu_attestation) => cgpu_attestation,
        Err(e) => {
            error!("Failed to get GPU attestation: {}", e);
            return HttpResponse::InternalServerError().finish();
        }
    };

    debug!("{:#?}", evidence);
    let response = AttestationResponse {
        evidence: evidence,
        certificate: certificate.to_pem().unwrap().to_vec(),
        module_load_order: ModuleLoadOrder {
            kernel: kernel_version,
            order: module_order,
        },
        cgpu_attestation: cgpu_attestation, // Include the GPU attestation
    };

    HttpResponse::Ok().json(response)
}

#[actix_web::main]
async fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();

    println!("{:?}", Nonce::generate().as_string());

    let matches = clap::App::new("Confido aTLS Server")
        .version("0.1.0")
        .about("A server that generates and provides TEE-backed TLS certificates")
        .arg(clap::Arg::new("host:port")
            .help("Sets the host and port in the format host:port")
            .required(true)
            .index(1))
        .arg(clap::Arg::new("certs")
            .help("Sets the certificate folder")
            .required(true)
            .index(2))
        .get_matches();

    let host_port = matches.value_of("host:port").unwrap();
    let certs_folder = matches.value_of("certs").unwrap();
    let fullchain_path = format!("{}/fullchain.pem", certs_folder);

    let fullchain_pem = fs::read(fullchain_path)?;
    let certificate = X509::from_pem(&fullchain_pem)?;
    let certificate = Arc::new(certificate);

    info!("Starting server at {}", host_port);
    HttpServer::new(move || {
        let certificate = Arc::clone(&certificate);
        App::new().route("/aTLS", web::post().to(move |data: web::Json<AttestationRequest>| {
            info!("http server aTLS route called");
            let certificate = Arc::clone(&certificate);
            atls_http_route(data, certificate)
        }))
    })
    .bind(host_port)?
    .run()
    .await?;

    Ok(())
}
