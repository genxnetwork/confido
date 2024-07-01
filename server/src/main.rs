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

pub struct Attester;

impl Attester {
    pub fn gather_evidence(nonce: &Nonce) -> Result<Evidence, Box<dyn Error>> {
        let report = vtpm::get_report()?;
        let quote = vtpm::get_quote(nonce.as_bytes())?;
        let certs = imds::get_certs()?;
        Ok(Evidence::new(report, quote, certs))
    }
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

    debug!("{:#?}", evidence);
    let response = AttestationResponse {
        evidence: evidence,
        certificate: certificate.to_pem().unwrap().to_vec(),
        module_load_order: ModuleLoadOrder {
            kernel: kernel_version,
            order: module_order,
        }, // Include the module load order
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
