// Confido aTLS Server
// usage: server host:port certs-folder.
// generates TLS certificate and saves it to a given folder.
// serves http end-point /attest route at a given host:port
// responds with boottime and runtime attestation evidence and 
// ephemerial public key of the TEE service that is crypgraphicly linked to the evidence.
// the TLS private key can be used by any other service within this TEE.
// the key should be kept pricate within the TEE.

use std::sync::Arc;
use std::error::Error;
use log::{info, error, debug};
use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use confido::{AttestationRequest, AttestationResponse, Nonce, Evidence};
use openssl::rsa::Rsa;
use openssl::x509::{X509, X509NameBuilder};
use openssl::nid::Nid;
use openssl::hash::MessageDigest;
use openssl::asn1::Asn1Time;
use openssl::pkey::PKey;
use openssl::pkey::Private;
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
    info!("Received attestation reques");
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
        .get_matches();

    let host_port = matches.value_of("host:port").unwrap_or("127.0.0.1:8080");
    let certs_folder = matches.value_of("certs").unwrap_or("./");
    std::fs::create_dir_all(certs_folder)?;

    let (certificate, private_key) = generate_certificate().unwrap();

    // Save private key and certificate into the provided certs_folder
    let private_key_path = format!("{}/private_key.pem", certs_folder);
    let certificate_path = format!("{}/certificate.pem", certs_folder);
    std::fs::write(&private_key_path, private_key.private_key_to_pem_pkcs8().unwrap())?;
    std::fs::write(&certificate_path, certificate.to_pem().unwrap())?;

    info!("Private key saved to: {}", private_key_path);
    info!("Certificate saved to: {}", certificate_path);

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
