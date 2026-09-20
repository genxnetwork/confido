use super::*;
use openssl::asn1::Asn1Time;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::ssl::{SslAcceptor, SslMethod};
use openssl::x509::extension::SubjectAlternativeName;
use openssl::x509::X509NameBuilder;
use std::io::{Read, Write};
use std::net::TcpListener;

fn certificate() -> (X509, PKey<Private>) {
    let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "localhost").unwrap();
    let name = name.build();
    let mut builder = X509::builder().unwrap();
    builder.set_version(2).unwrap();
    builder.set_subject_name(&name).unwrap();
    builder.set_issuer_name(&name).unwrap();
    builder.set_pubkey(&key).unwrap();
    builder
        .set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    builder
        .set_not_after(&Asn1Time::days_from_now(1).unwrap())
        .unwrap();
    let san = SubjectAlternativeName::new()
        .dns("localhost")
        .build(&builder.x509v3_context(None, None))
        .unwrap();
    builder.append_extension(san).unwrap();
    builder.sign(&key, MessageDigest::sha256()).unwrap();
    (builder.build(), key)
}

fn serve(cert: &X509, key: &PKey<Private>) -> (u16, std::thread::JoinHandle<()>) {
    let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
    acceptor.set_certificate(cert).unwrap();
    acceptor.set_private_key(key).unwrap();
    let acceptor = acceptor.build();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let thread = std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        if let Ok(mut stream) = acceptor.accept(stream) {
            let mut request = [0; 4096];
            if stream.read(&mut request).is_ok() {
                let _ = stream.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                );
            }
        }
    });
    (port, thread)
}

#[tokio::test]
async fn accepts_attested_certificate_and_rejects_an_unrelated_certificate() {
    let (cert, key) = certificate();
    let client = ATLS::from_certificate(&cert).unwrap();
    let (port, server) = serve(&cert, &key);
    assert_eq!(
        client
            .get(&format!("https://localhost:{port}"))
            .await
            .unwrap(),
        "ok"
    );
    server.join().unwrap();
    let (unrelated_cert, unrelated_key) = certificate();
    let (port, server) = serve(&unrelated_cert, &unrelated_key);
    assert!(client
        .get(&format!("https://localhost:{port}"))
        .await
        .is_err());
    server.join().unwrap();
}

#[tokio::test]
async fn rejects_plain_http_and_wrong_hostname() {
    let (cert, key) = certificate();
    let client = ATLS::from_certificate(&cert).unwrap();
    assert!(client.get("http://127.0.0.1:1").await.is_err());
    let (port, server) = serve(&cert, &key);
    assert!(client
        .get(&format!("https://127.0.0.1:{port}"))
        .await
        .is_err());
    server.join().unwrap();
}
