use super::*;

#[test]
fn reads_ima_order_and_digest_metadata() {
    let log = "10 abc ima-ng sha256:def boot_aggregate\n10 123 ima-ng sha256:456 /lib/modules/6.8.0/kernel/example.ko\n";
    let entries = Attester::parse_ima_measurements(log.as_bytes()).unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].name, "boot_aggregate");
    assert_eq!(entries[1].name, "example.ko");
    assert_eq!(entries[1].pcr, 10);
    assert_eq!(entries[1].template_hash, "123");
    assert_eq!(entries[1].filedata_alg, "sha256");
    assert_eq!(entries[1].filedata_hash, "456");
    assert_eq!(entries[1].filename_hint, "/lib/modules/6.8.0/kernel/example.ko");
    let order = Attester::module_load_order(&entries);
    assert_eq!(order.kernel, "6.8.0");
    assert_eq!(order.order, ["boot_aggregate", "example.ko"]);
}

#[test]
fn rejects_empty_truncated_and_unsupported_measurements() {
    for log in [
        "",
        "\n",
        "10 abc ima-ng\n",
        "10 abc ima-ng invalid /file\n",
        "10 abc ima-buf sha256:def /file\n",
        "bad abc ima-ng sha256:def /file\n",
    ] {
        assert!(
            Attester::parse_ima_measurements(log.as_bytes()).is_err(),
            "{log:?}"
        );
    }
}

#[test]
fn reads_ima_sig_without_reconstructing_or_dropping_its_template_hash() {
    let entries = Attester::parse_ima_measurements(
        "10 abc ima-sig sha256:def /lib/module.ko 030204...\n".as_bytes(),
    )
    .unwrap();
    assert_eq!(entries[0].ima_template, "ima-sig");
    assert_eq!(entries[0].template_hash, "abc");
}
