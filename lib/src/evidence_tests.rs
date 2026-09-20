use super::*;

fn make_evidence(pcrs: Vec<Vec<u8>>) -> Evidence {
    let quote = serde_json::from_value(serde_json::json!({
        "signature": [], "message": [],
        "pcr_banks": [{"algo": "Sha256", "pcr_values": pcrs}]
    }))
    .unwrap();
    Evidence::new(
        vec![],
        quote,
        serde_json::Value::Null,
        ModuleLoadOrder {
            kernel: String::new(),
            order: vec![],
        },
        vec![],
    )
}

#[test]
fn malformed_hcl_metadata_returns_an_error_instead_of_unwinding() {
    let mut evidence = make_evidence(vec![]);
    assert!(evidence.parse_report().is_err());
    // Azure HCL: 32-byte header, 1184-byte hardware report, then the
    // 20-byte IGVM request header (including hash type and variable size).
    let mut report = vec![0; 1236];
    report[1224..1228].copy_from_slice(&2u32.to_le_bytes()); // SNP
    report[1228..1232].copy_from_slice(&1u32.to_le_bytes()); // SHA-256
    report[1232..1236].copy_from_slice(&u32::MAX.to_le_bytes());
    evidence.report = report.clone();
    assert!(evidence.parse_report().is_err());
    report[1228..1232].copy_from_slice(&2u32.to_le_bytes()); // unsupported SHA-384
    evidence.report = report;
    assert!(evidence.parse_report().is_err());
}

#[test]
fn verifies_the_trusted_bank_even_when_the_quote_also_contains_sha1() {
    let mut evidence = make_evidence(vec![vec![0; 32]; 11]);
    let mut quote = serde_json::to_value(&evidence.quote).unwrap();
    quote["pcr_banks"].as_array_mut().unwrap().insert(
        0,
        serde_json::json!({
            "algo": "Sha1", "pcr_values": vec![vec![0u8; 20]; 11]
        }),
    );
    evidence.quote = serde_json::from_value(quote).unwrap();
    evidence.ima_measurements = vec![IMALogEntry {
        name: "boot_aggregate".into(),
        pcr: 10,
        template_hash: "01".repeat(20),
        ima_template: "ima-ng".into(),
        filedata_alg: "sha256".into(),
        filedata_hash: hex::encode(openssl::sha::sha256(&[0; 320])),
        filename_hint: "boot_aggregate".into(),
    }];
    evidence.module_load_order.order = vec!["boot_aggregate".into()];
    let mut trs = TRS {
        ima_measurements: evidence.ima_measurements.clone(),
        pcr10_sha256: Some("00".repeat(32)),
    };
    evidence.verify_measurements(&trs).unwrap();
    trs.ima_measurements[0].filedata_hash = "ff".repeat(32);
    assert!(evidence.verify_measurements(&trs).is_err());
    evidence.ima_measurements = trs.ima_measurements.clone();
    assert!(evidence.verify_measurements(&trs).is_err()); // same log, wrong boot PCRs
}

#[test]
fn boot_aggregate_requires_every_pcr_with_the_correct_length() {
    let evidence = make_evidence(vec![vec![0; 32]; 10]);
    assert_eq!(
        evidence
            .get_boot_aggregate_hash(vtpm::Algorithm::Sha256)
            .unwrap(),
        hex::encode(openssl::sha::sha256(&[0; 320]))
    );
    assert!(evidence
        .get_boot_aggregate_hash(vtpm::Algorithm::Sha1)
        .is_err());
    assert!(make_evidence(vec![vec![0; 32]; 9])
        .get_boot_aggregate_hash(vtpm::Algorithm::Sha256)
        .is_err());
    assert!(make_evidence(vec![vec![0; 20]; 10])
        .get_boot_aggregate_hash(vtpm::Algorithm::Sha256)
        .is_err());
}
