use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use confido::atls::{AttestationRequest, AttestationResponse, IMALogEntry, ModuleLoadOrder};
use confido::evidence::Evidence;
use confido::nonce::Nonce;
use confido::vtpm;
use log::{debug, error, info};
use openssl::asn1::Asn1Time;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::pkey::Private;
use openssl::rsa::Rsa;
use openssl::x509::extension::SubjectAlternativeName;
use openssl::x509::X509NameBuilder;
use openssl::x509::X509;
use regex::Regex;
use serde_json::Value;
use std::collections::HashMap;
use std::error::Error;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, Write};
use std::net::IpAddr;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::process::Command;
use std::sync::Arc;

pub struct Attester;

impl Attester {
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
        let re_attestation_report_signature_verification =
            Regex::new(r"Attestation report signature verification successful").unwrap();
        let re_attestation_report_verification =
            Regex::new(r"Attestation report verification successful").unwrap();

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
                gpu_info.insert(
                    gpu_num,
                    serde_json::json!({
                        "state": "",
                        "verification": "",
                        "attestation": "",
                    }),
                );
            } else if re_state.is_match(line) {
                let gpu_num = current_gpu.as_ref().unwrap()["GPU"].as_i64().unwrap();
                gpu_info.get_mut(&gpu_num).unwrap()["state"] = "GPU is in expected state.".into();
            } else if let Some(caps) = re_verification.captures(line) {
                let gpu_num = caps[1].parse::<i64>().unwrap();
                gpu_info.get_mut(&gpu_num).unwrap()["verification"] =
                    format!("GPU {} verified successfully.", gpu_num).into();
            } else if re_attestation.is_match(line) {
                let gpu_num = current_gpu.as_ref().unwrap()["GPU"].as_i64().unwrap();
                gpu_info.get_mut(&gpu_num).unwrap()["attestation"] =
                    "GPU Attested Successfully.".into();
            } else if let Some(caps) = re_driver_version.captures(line) {
                current_gpu.as_mut().unwrap()["Driver version fetched"] =
                    caps[1].to_string().into();
            } else if let Some(caps) = re_vbios_version.captures(line) {
                current_gpu.as_mut().unwrap()["VBIOS version fetched"] = caps[1].to_string().into();
            } else if re_attestation_report_signature_verification.is_match(line) {
                current_gpu.as_mut().unwrap()["Attestation report signature verification"] =
                    "successful".into();
            } else if re_attestation_report_verification.is_match(line) {
                current_gpu.as_mut().unwrap()["Attestation report verification"] =
                    "successful".into();
            }
        }

        if let Some(gpu) = current_gpu.take() {
            result["GPUs"].as_array_mut().unwrap().push(gpu);
        }

        for (gpu_num, info) in gpu_info {
            let idx = result["GPUs"]
                .as_array_mut()
                .unwrap()
                .iter()
                .position(|g| g["GPU"] == gpu_num)
                .unwrap();
            result["GPUs"][idx]["state"] = info["state"].clone();
            result["GPUs"][idx]["verification"] = info["verification"].clone();
            result["GPUs"][idx]["attestation"] = info["attestation"].clone();
        }

        Ok(result)
    }

    fn get_gpu_attestation() -> Result<Value, Box<dyn Error>> {
        let cgpu_verifier = "verifier.cc_admin";
        if !Path::new(cgpu_verifier).exists() {
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "cgpu_verifier python module not found",
            )));
        }

        let output = Command::new("python3")
            .arg("-m")
            .arg("verifier.cc_admin")
            .output()
            .expect("Failed to execute GPU attestation command");

        if !output.status.success() {
            return Err(Box::new(io::Error::new(
                io::ErrorKind::Other,
                "Failed to execute GPU attestation command",
            )));
        }

        let output_str = String::from_utf8(output.stdout)?;
        Attester::parse_gpu_attestation_output(&output_str)
    }

    fn read_ima_measurements() -> Result<Vec<IMALogEntry>, Box<dyn Error>> {
        let path = "/sys/kernel/security/ima/ascii_runtime_measurements";
        let file = File::open(path)?;
        Self::parse_ima_measurements(io::BufReader::new(file))
    }

    fn parse_ima_measurements(reader: impl BufRead) -> Result<Vec<IMALogEntry>, Box<dyn Error>> {
        let mut measurements = Vec::new();
        for line in reader.lines() {
            let line = line?;
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.is_empty() {
                continue;
            }
            if parts.len() < 5 {
                return Err("Incomplete IMA measurement".into());
            }
            if parts[2] != "ima-ng" && parts[2] != "ima-sig" {
                return Err("Unsupported IMA template".into());
            }
            let filedata: Vec<&str> = parts[3].splitn(2, ':').collect();
            if filedata.len() != 2 {
                return Err("Invalid IMA measurement".into());
            }
            let filename_hint = parts[4].to_string();
            let name = filename_hint
                .rsplit('/')
                .next()
                .unwrap_or(&filename_hint)
                .to_string();
            measurements.push(IMALogEntry {
                name,
                pcr: parts[0].parse()?,
                template_hash: parts[1].to_string(),
                ima_template: parts[2].to_string(),
                filedata_alg: filedata[0].to_string(),
                filedata_hash: filedata[1].to_string(),
                filename_hint,
            });
        }
        if measurements.is_empty() {
            return Err("No IMA measurements found".into());
        }
        Ok(measurements)
    }

    fn module_load_order(measurements: &[IMALogEntry]) -> ModuleLoadOrder {
        let kernel = measurements
            .iter()
            .find_map(|measurement| {
                let (_, module_path) = measurement.filename_hint.split_once("/modules/")?;
                let (version, _) = module_path.split_once('/')?;
                Some(version.to_string())
            })
            .unwrap_or_default();
        ModuleLoadOrder {
            kernel,
            order: measurements
                .iter()
                .map(|measurement| measurement.name.clone())
                .collect(),
        }
    }

    pub fn gather_evidence(
        nonce: &Nonce,
        certificate: &X509,
        algorithms: Arc<Vec<vtpm::Algorithm>>,
    ) -> Result<Evidence, Box<dyn Error>> {
        let report = vtpm::get_report()?;
        let ima_measurements = Attester::read_ima_measurements()?;
        let ima_binding = Evidence::ima_binding(&ima_measurements)?;
        let mut quote_nonce = nonce.clone();
        quote_nonce.extend_binding(certificate, &ima_binding);
        let quote = vtpm::get_quote(quote_nonce.as_bytes(), algorithms.to_vec())?;
        let module_load_order = Attester::module_load_order(&ima_measurements);

        let cgpu_attestation = match Attester::get_gpu_attestation() {
            Ok(cgpu_attestation) => cgpu_attestation,
            Err(e) => {
                error!("Failed to get GPU attestation: {}", e);
                serde_json::Value::Null
            }
        };
        // info!("module_order: {:?}", module_order);
        Ok(Evidence::new(
            report,
            quote,
            cgpu_attestation,
            module_load_order,
            ima_measurements,
        ))
    }
}

async fn atls_http_route(
    data: web::Json<AttestationRequest>,
    certificate: Arc<X509>,
    algorithms: Arc<Vec<vtpm::Algorithm>>,
) -> impl Responder {
    info!("Received attestation request");
    let nonce = match Nonce::read(&data.nonce) {
        Ok(nonce) => nonce,
        Err(e) => {
            error!("{}", e);
            return HttpResponse::BadRequest().finish();
        }
    };

    let evidence = match Attester::gather_evidence(&nonce, &certificate, Arc::clone(&algorithms)) {
        Ok(evidence) => {
            info!("Successfully gathered evidence");
            evidence
        }
        Err(e) => {
            error!("Failed to gather evidence: {}", e);
            return HttpResponse::InternalServerError().finish();
        }
    };

    debug!("{:#?}", evidence);
    let response = AttestationResponse {
        evidence: evidence,
        certificate: certificate.to_pem().unwrap().to_vec(),
    };

    HttpResponse::Ok()
        .insert_header(("Cache-Control", "no-store"))
        .json(response)
}

fn write_private_key(path: &Path, private_key: &PKey<Private>) -> Result<(), Box<dyn Error>> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(&private_key.private_key_to_pem_pkcs8()?)?;
    Ok(())
}

fn certificate_covers_host(certificate: &X509, hostname: &str) -> bool {
    let Some(names) = certificate.subject_alt_names() else {
        return false;
    };
    match hostname.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => names
            .iter()
            .any(|name| name.ipaddress() == Some(ip.octets().as_slice())),
        Ok(IpAddr::V6(ip)) => names
            .iter()
            .any(|name| name.ipaddress() == Some(ip.octets().as_slice())),
        Err(_) => names.iter().any(|name| {
            name.dnsname()
                .is_some_and(|dns| dns.eq_ignore_ascii_case(hostname))
        }),
    }
}

fn generate_certificate(
    hostname: &str,
) -> Result<(X509, PKey<Private>), openssl::error::ErrorStack> {
    // Generate a new 2048-bit RSA private key
    let rsa = Rsa::generate(2048).unwrap();
    let private_key = PKey::from_rsa(rsa).unwrap();

    // Build the certificate name
    let mut name_builder = X509NameBuilder::new().unwrap();
    name_builder
        .append_entry_by_nid(Nid::COMMONNAME, hostname)
        .unwrap();
    name_builder
        .append_entry_by_nid(Nid::ORGANIZATIONNAME, "GENXT LTD")
        .unwrap();
    name_builder
        .append_entry_by_nid(Nid::ORGANIZATIONALUNITNAME, "IT")
        .unwrap();
    name_builder
        .append_entry_by_nid(Nid::COUNTRYNAME, "GB")
        .unwrap();
    name_builder
        .append_entry_by_nid(Nid::STATEORPROVINCENAME, "Cambridgeshire")
        .unwrap();
    name_builder
        .append_entry_by_nid(Nid::LOCALITYNAME, "Hinxton")
        .unwrap();
    name_builder
        .append_entry_by_nid(Nid::PKCS9_EMAILADDRESS, "info@genxt.ai")
        .unwrap();
    name_builder
        .append_entry_by_nid(
            Nid::POSTALADDRESS,
            "AB318, Biodata Innovation Centre, Wellcome Genome Campus",
        )
        .unwrap();
    name_builder
        .append_entry_by_nid(Nid::POSTALCODE, "CB101DR")
        .unwrap();
    name_builder
        .append_entry_by_nid(Nid::BUSINESSCATEGORY, "Private Ogranisation")
        .unwrap();
    name_builder
        .append_entry_by_nid(Nid::DOMAINCOMPONENT, "genxt.ai")
        .unwrap();

    let name = name_builder.build();

    // Build the certificate
    let mut builder = X509::builder().unwrap();
    builder.set_version(2).unwrap();
    builder.set_subject_name(&name).unwrap();
    builder.set_issuer_name(&name).unwrap();
    builder.set_pubkey(&private_key).unwrap();
    let mut san = SubjectAlternativeName::new();
    if hostname.parse::<IpAddr>().is_ok() {
        san.ip(hostname);
    } else {
        san.dns(hostname);
    }
    let extension = san.build(&builder.x509v3_context(None, None))?;
    builder.append_extension(extension)?;

    // Set the not_before and not_after dates for the certificate
    let not_before = Asn1Time::days_from_now(0).unwrap();
    let not_after = Asn1Time::days_from_now(365).unwrap();
    builder.set_not_before(&not_before).unwrap();
    builder.set_not_after(&not_after).unwrap();

    builder.sign(&private_key, MessageDigest::sha256()).unwrap();
    let certificate = builder.build();
    let certificate_pem = certificate.to_pem().unwrap();
    let certificate_pem_str = String::from_utf8(certificate_pem).unwrap();
    debug!("{}", certificate_pem_str);

    Ok((certificate, private_key))
}

#[actix_web::main]
async fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();

    let matches = clap::App::new("Confido aTLS Server")
        .version(env!("CARGO_PKG_VERSION"))
        .about("A server that generates and provides TEE-backed TLS certificates")
        .arg(
            clap::Arg::new("host:port")
                .help("Sets the host and port in the format host:port")
                .required(true)
                .index(1),
        )
        .arg(
            clap::Arg::new("certs")
                .help("Sets the certificate folder")
                .required(true)
                .index(2),
        )
        .arg(
            clap::Arg::new("algo")
                .help("Sets the algorithm")
                .required(true)
                .index(3)
                .multiple_values(true)
                .possible_values(&["sha1", "sha256"]),
        )
        .arg(
            clap::Arg::new("tls-hostname")
                .long("tls-hostname")
                .help("DNS name or IP address used by the HTTPS application")
                .takes_value(true),
        )
        .get_matches();

    let host_port = matches.value_of("host:port").unwrap_or("127.0.0.1:8080");
    let certs_folder = matches.value_of("certs").unwrap_or("./");
    let tls_hostname = matches.value_of("tls-hostname");
    std::fs::create_dir_all(certs_folder)?;

    // Save private key and certificate into the provided certs_folder
    let private_key_path = format!("{}/private_key.pem", certs_folder);
    let certificate_path = format!("{}/certificate.pem", certs_folder);
    // let fullchain_path = format!("{}/fullchain.pem", certs_folder);

    let key_exists = Path::new(&private_key_path).exists();
    let cert_exists = Path::new(&certificate_path).exists();
    if key_exists != cert_exists {
        return Err("The certificate and private key must both exist, or both be absent".into());
    }

    let (certificate, private_key) = if key_exists {
        // Read the existing private key and certificate.
        if fs::symlink_metadata(&private_key_path)?
            .file_type()
            .is_symlink()
        {
            return Err("The private key path must not be a symlink".into());
        }
        fs::set_permissions(&private_key_path, fs::Permissions::from_mode(0o600))?;
        let private_key_pem = fs::read(&private_key_path)?;
        let private_key = Rsa::private_key_from_pem(&private_key_pem)?;
        let private_key = PKey::from_rsa(private_key)?;

        let certificate_pem = std::fs::read(&certificate_path)?;
        let certificate = X509::from_pem(&certificate_pem)?;

        (certificate, private_key)
    } else {
        // Generate new private key and certificate
        let (certificate, private_key) = generate_certificate(tls_hostname.unwrap_or("localhost"))?;

        // Save private key and certificate into the provided certs_folder
        write_private_key(Path::new(&private_key_path), &private_key)?;
        fs::write(&certificate_path, certificate.to_pem()?)?;

        info!("Private key saved to: {}", private_key_path);
        info!("Certificate saved to: {}", certificate_path);

        (certificate, private_key)
    };

    if !certificate.public_key()?.public_eq(&private_key) {
        return Err("The certificate does not match the private key".into());
    }
    if let Some(hostname) = tls_hostname {
        if !certificate_covers_host(&certificate, hostname) {
            return Err(format!(
                "The certificate does not have a subject alternative name for {hostname}"
            )
            .into());
        }
    }

    // let fullchain_pem = fs::read(fullchain_path)?;
    // let certificate = X509::from_pem(&fullchain_pem)?;
    let certificate = Arc::new(certificate);

    let mut algorithms = Vec::new();
    if let Some(values) = matches.values_of("algo") {
        for algo in values {
            match algo {
                "sha1" => algorithms.push(vtpm::Algorithm::Sha1),
                "sha256" => algorithms.push(vtpm::Algorithm::Sha256),
                _ => unreachable!(),
            }
        }
    }

    if algorithms.is_empty() {
        algorithms.push(vtpm::Algorithm::Sha256);
    }

    let algorithms = Arc::new(algorithms);

    info!("Starting server at {}", host_port);
    HttpServer::new(move || {
        let certificate = Arc::clone(&certificate);
        let algorithms = Arc::clone(&algorithms);
        App::new().route(
            "/tee-report",
            web::post().to(move |data: web::Json<AttestationRequest>| {
                info!("http server report route called");
                atls_http_route(data, Arc::clone(&certificate), Arc::clone(&algorithms))
            }),
        )
    })
    .bind(host_port)?
    .run()
    .await?;

    Ok(())
}

#[cfg(test)]
mod tests;
