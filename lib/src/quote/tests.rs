use super::verify;
use crate::atls::IMALogEntry;
use crate::evidence::Evidence;
use crate::nonce::{Base64, Nonce};
use az_snp_vtpm::vtpm::Quote;
use openssl::asn1::Asn1Time;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private, Public};
use openssl::rsa::Rsa;
use openssl::sign::Signer;
use openssl::x509::{X509NameBuilder, X509};

fn certificate(key: &PKey<Private>, name: &str) -> X509 {
    let mut subject = X509NameBuilder::new().unwrap();
    subject.append_entry_by_text("CN", name).unwrap();
    let subject = subject.build();
    let mut builder = X509::builder().unwrap();
    builder.set_version(2).unwrap();
    builder.set_subject_name(&subject).unwrap();
    builder.set_issuer_name(&subject).unwrap();
    builder.set_pubkey(key).unwrap();
    builder
        .set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    builder
        .set_not_after(&Asn1Time::days_from_now(1).unwrap())
        .unwrap();
    builder.sign(key, MessageDigest::sha256()).unwrap();
    builder.build()
}

fn measurements() -> Vec<IMALogEntry> {
    ["boot_aggregate", "module.ko"]
        .iter()
        .map(|name| IMALogEntry {
            name: name.to_string(),
            pcr: 10,
            template_hash: "01".repeat(20),
            ima_template: "ima-ng".into(),
            filedata_alg: "sha256".into(),
            filedata_hash: "02".repeat(32),
            filename_hint: name.to_string(),
        })
        .collect()
}

fn bound_nonce(challenge: &Nonce, cert: &X509, entries: &[IMALogEntry]) -> Nonce {
    let mut nonce = challenge.clone();
    nonce.extend_binding(cert, &Evidence::ima_binding(entries).unwrap());
    nonce
}

// Construct and sign a TPMS_ATTEST quote with PCRs 0..=10. This exercises the
// actual quote verifier without requiring a TPM or AMD certificate service.
fn signed_quote(nonce: &Nonce, key: &PKey<Private>) -> Quote {
    signed_quote_with_selection(nonce, key, [0xff, 0x07, 0])
}

fn signed_quote_with_selection(nonce: &Nonce, key: &PKey<Private>, slots: [u8; 3]) -> Quote {
    let mut message = vec![];
    message.extend_from_slice(&0xff544347u32.to_be_bytes()); // TPM_GENERATED_VALUE
    message.extend_from_slice(&0x8018u16.to_be_bytes()); // TPM_ST_ATTEST_QUOTE
    message.extend_from_slice(&0u16.to_be_bytes()); // qualified signer
    message.extend_from_slice(&(nonce.as_bytes().len() as u16).to_be_bytes());
    message.extend_from_slice(nonce.as_bytes());
    message.extend_from_slice(&[0; 16]); // clock, reset count, restart count
    message.push(1); // safe clock
    message.extend_from_slice(&[0; 8]); // firmware version
    message.extend_from_slice(&1u32.to_be_bytes()); // one PCR selection
    message.extend_from_slice(&0x000bu16.to_be_bytes()); // TPM_ALG_SHA256
    message.push(3);
    message.extend_from_slice(&slots);
    message.extend_from_slice(&32u16.to_be_bytes());
    message.extend_from_slice(&openssl::sha::sha256(&[0; 32 * 11]));
    let mut signer = Signer::new(MessageDigest::sha256(), key).unwrap();
    signer.update(&message).unwrap();
    serde_json::from_value(serde_json::json!({
        "message": message, "signature": signer.sign_to_vec().unwrap(),
        "pcr_banks": [{"algo": "Sha256", "pcr_values": vec![vec![0u8; 32]; 11]}]
    }))
    .unwrap()
}

#[test]
fn quote_accepts_original_binding_and_rejects_changed_challenge_certificate_or_log() {
    let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    let public_key: PKey<Public> =
        PKey::public_key_from_der(&key.public_key_to_der().unwrap()).unwrap();
    let cert = certificate(&key, "original");
    let challenge = Nonce::read(&Base64::from_base64(base64::encode([7; 32]))).unwrap();
    let entries = measurements();
    let nonce = bound_nonce(&challenge, &cert, &entries);
    assert_eq!(nonce.as_bytes().len(), 32);
    assert_ne!(nonce.as_bytes(), challenge.as_bytes());
    let quote = signed_quote(&nonce, &key);
    verify(&quote, &public_key, nonce.as_bytes()).unwrap();

    let different_challenge = Nonce::read(&Base64::from_base64(base64::encode([8; 32]))).unwrap();
    let different_certificate = certificate(&key, "substituted");
    for changed in [
        bound_nonce(&different_challenge, &cert, &entries),
        bound_nonce(&challenge, &different_certificate, &entries),
    ] {
        assert!(verify(&quote, &public_key, changed.as_bytes()).is_err());
    }

    let mut changed_logs = vec![];
    let mut altered = entries.clone();
    altered[1].filedata_hash = "03".repeat(32);
    changed_logs.push(altered);
    let mut reordered = entries.clone();
    reordered.reverse();
    changed_logs.push(reordered);
    changed_logs.push(entries[..1].to_vec());
    let mut duplicated = entries.clone();
    duplicated.push(entries[1].clone());
    changed_logs.push(duplicated);
    for changed in changed_logs {
        let changed_nonce = bound_nonce(&challenge, &cert, &changed);
        assert!(verify(&quote, &public_key, changed_nonce.as_bytes()).is_err());
    }

    let mut changed_pcrs = serde_json::to_value(&quote).unwrap();
    changed_pcrs["pcr_banks"][0]["pcr_values"][10][0] = serde_json::json!(1);
    let changed_quote: Quote = serde_json::from_value(changed_pcrs).unwrap();
    assert!(verify(&changed_quote, &public_key, nonce.as_bytes()).is_err());
}

#[test]
fn rejects_invalid_nonce_encoding_and_lengths() {
    for encoded in [
        "invalid!".to_string(),
        base64::encode([0; 31]),
        base64::encode([0; 33]),
    ] {
        assert!(Nonce::read(&Base64::from_base64(encoded)).is_err());
    }
}

#[test]
fn rejects_unsigned_bank_labels_lengths_and_shifted_pcr_selection() {
    let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    let public_key = PKey::public_key_from_der(&key.public_key_to_der().unwrap()).unwrap();
    let nonce = Nonce::generate();
    let quote = signed_quote(&nonce, &key);

    let mut relabeled = serde_json::to_value(&quote).unwrap();
    relabeled["pcr_banks"][0]["algo"] = serde_json::json!("Sha1");
    let relabeled: Quote = serde_json::from_value(relabeled).unwrap();
    assert!(relabeled.verify(&public_key, nonce.as_bytes()).is_ok());
    assert!(verify(&relabeled, &public_key, nonce.as_bytes()).is_err());

    let mut regrouped = serde_json::to_value(&quote).unwrap();
    regrouped["pcr_banks"][0]["pcr_values"][0] = serde_json::json!(vec![0; 31]);
    regrouped["pcr_banks"][0]["pcr_values"][1] = serde_json::json!(vec![0; 33]);
    let regrouped: Quote = serde_json::from_value(regrouped).unwrap();
    assert!(regrouped.verify(&public_key, nonce.as_bytes()).is_ok());
    assert!(verify(&regrouped, &public_key, nonce.as_bytes()).is_err());

    let shifted = signed_quote_with_selection(&nonce, &key, [0xfe, 0x0f, 0]);
    assert!(shifted.verify(&public_key, nonce.as_bytes()).is_ok());
    assert!(verify(&shifted, &public_key, nonce.as_bytes()).is_err());
}
