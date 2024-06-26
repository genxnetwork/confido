use std::sync::Arc;
use std::error::Error;
use std::fs;
use log::{info, error, debug};
use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use confido::{AttestationRequest, AttestationResponse, Nonce, Evidence};
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

    debug!("{:#?}", evidence);
    let response = AttestationResponse {
        evidence: evidence,
        certificate: certificate.to_pem().unwrap().to_vec(),
    };

    HttpResponse::Ok().json(response)
}

#[actix_web::main]
async fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();

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

