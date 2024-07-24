use std::sync::Arc;
use std::error::Error;
use log::{info, error, debug};
use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use confido::atls::{AttestationRequest, AttestationResponse};
use confido::nonce::Nonce;
use confido::evidence::Evidence;
use openssl::x509::X509;
use az_snp_vtpm::vtpm;
use openssl::rsa::Rsa;
use openssl::hash::MessageDigest;
use openssl::asn1::Asn1Time;
use openssl::nid::Nid;
use openssl::x509::X509NameBuilder;
use openssl::pkey::PKey;
use openssl::pkey::Private;

pub struct Attester;

impl Attester {
    pub fn gather_evidence(nonce: &Nonce, algorithms: Arc<Vec<vtpm::Algorithm>>) -> Result<Evidence, Box<dyn Error>> {
        let report = vtpm::get_report()?;
        let quote = vtpm::get_quote(nonce.as_bytes(), algorithms.to_vec())?;
        // let certs = imds::get_certs()?;
        Ok(Evidence::new(report, quote))
    }
}

async fn atls_http_route(data: web::Json<AttestationRequest>, certificate: Arc<X509>, algorithms: Arc<Vec<vtpm::Algorithm>>) -> impl Responder {
    info!("Received attestation request");
    let mut nonce = match Nonce::read(&data.nonce) {
        Ok(nonce) => nonce,
        Err(e) => {
            error!("{}", e);
            return HttpResponse::InternalServerError().finish();
        }
    };

    let evidence = match Attester::gather_evidence(&nonce.extend(&certificate), Arc::clone(&algorithms)) {
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

fn generate_certificate() -> Result<(X509, PKey<Private>), openssl::error::ErrorStack> {
    // Generate a new 2048-bit RSA private key
    let rsa = Rsa::generate(2048).unwrap();
    let private_key = PKey::from_rsa(rsa).unwrap();

    // Build the certificate name
    let mut name_builder = X509NameBuilder::new().unwrap();
    name_builder.append_entry_by_nid(Nid::COMMONNAME, "localhost").unwrap();
    name_builder.append_entry_by_nid(Nid::ORGANIZATIONNAME, "GENXT LTD").unwrap();
    name_builder.append_entry_by_nid(Nid::ORGANIZATIONALUNITNAME, "IT").unwrap();
    name_builder.append_entry_by_nid(Nid::COUNTRYNAME, "GB").unwrap();
    name_builder.append_entry_by_nid(Nid::STATEORPROVINCENAME, "Cambridgeshire").unwrap();
    name_builder.append_entry_by_nid(Nid::LOCALITYNAME, "Hinxton").unwrap();
    name_builder.append_entry_by_nid(Nid::PKCS9_EMAILADDRESS, "info@genxt.ai").unwrap();
    name_builder.append_entry_by_nid(Nid::POSTALADDRESS, "AB318, Biodata Innovation Centre, Wellcome Genome Campus").unwrap();
    name_builder.append_entry_by_nid(Nid::POSTALCODE, "CB101DR").unwrap();
    name_builder.append_entry_by_nid(Nid::BUSINESSCATEGORY, "Private Ogranisation").unwrap();
    name_builder.append_entry_by_nid(Nid::DOMAINCOMPONENT, "genxt.ai").unwrap();

    let name = name_builder.build();

    // Build the certificate
    let mut builder = X509::builder().unwrap();
    builder.set_version(2).unwrap();
    builder.set_subject_name(&name).unwrap();
    builder.set_issuer_name(&name).unwrap();
    builder.set_pubkey(&private_key).unwrap();

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
        .arg(clap::Arg::new("algo")
            .help("Sets the algorithm")
            .required(true)
            .index(3)
            .multiple_values(true)
            .possible_values(&["sha1", "sha256"]))
        .get_matches();

    let host_port = matches.value_of("host:port").unwrap_or("127.0.0.1:8080");
    let certs_folder = matches.value_of("certs").unwrap_or("./");
    std::fs::create_dir_all(certs_folder)?;

    // Save private key and certificate into the provided certs_folder
    let private_key_path = format!("{}/private_key.pem", certs_folder);
    let certificate_path = format!("{}/certificate.pem", certs_folder);
    // let fullchain_path = format!("{}/fullchain.pem", certs_folder);

    let (certificate, private_key) = if std::path::Path::new(&private_key_path).exists() && std::path::Path::new(&certificate_path).exists() {
        // Read the existing private key and certificate
        let private_key_pem = std::fs::read(&private_key_path)?;
        let private_key = Rsa::private_key_from_pem(&private_key_pem)?;
        let private_key = PKey::from_rsa(private_key)?;  
    
        let certificate_pem = std::fs::read(&certificate_path)?;
        let certificate = X509::from_pem(&certificate_pem)?;
        
        (certificate, private_key)
    } else {
        // Generate new private key and certificate
        let (certificate, private_key) = generate_certificate().unwrap();
    
        // Save private key and certificate into the provided certs_folder
        std::fs::write(&private_key_path, private_key.private_key_to_pem_pkcs8().unwrap())?;
        std::fs::write(&certificate_path, certificate.to_pem().unwrap())?;
    
        info!("Private key saved to: {}", private_key_path);
        info!("Certificate saved to: {}", certificate_path);
    
        (certificate, private_key)
    };
    
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
        App::new().route("/aTLS", web::post().to(move |data: web::Json<AttestationRequest>| {
            info!("http server aTLS route called");
            atls_http_route(data, Arc::clone(&certificate), Arc::clone(&algorithms))
        }))
    })
    .bind(host_port)?
    .run()
    .await?;

    Ok(())
}

