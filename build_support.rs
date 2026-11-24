// Build-time only. The runtime verifier does not read files or spawn processes.
fn stamp(scope: &str, relative_root: &str) {
    use std::{env, path::Path, process::Command};

    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let root = Path::new(&manifest_dir)
        .join(relative_root)
        .canonicalize()
        .unwrap();
    let fingerprint = Command::new("python3")
        .arg(root.join("scripts/source_fingerprint.py"))
        .arg(&root)
        .arg(scope)
        .output()
        .expect("Python 3 is required to fingerprint build sources");
    assert!(
        fingerprint.status.success(),
        "source fingerprint failed: {}",
        String::from_utf8_lossy(&fingerprint.stderr)
    );
    let output = String::from_utf8(fingerprint.stdout).unwrap();
    let mut lines = output.lines();
    println!(
        "cargo:rustc-env=CONFIDO_SOURCE_SHA256={}",
        lines.next().unwrap()
    );
    for path in lines {
        println!("cargo:rerun-if-changed={path}");
    }

    let rustc = Command::new(env::var("RUSTC").unwrap_or("rustc".into()))
        .arg("--version")
        .output()
        .unwrap();
    println!(
        "cargo:rustc-env=CONFIDO_RUSTC={}",
        String::from_utf8_lossy(&rustc.stdout).trim()
    );
    println!(
        "cargo:rustc-env=CONFIDO_TARGET={}",
        env::var("TARGET").unwrap()
    );
    println!("cargo:rerun-if-env-changed=RUSTFLAGS");
    println!("cargo:rerun-if-env-changed=CARGO_ENCODED_RUSTFLAGS");
    let flags = env::var("CARGO_ENCODED_RUSTFLAGS")
        .unwrap_or_default()
        .replace('\x1f', " ");
    println!("cargo:rustc-env=CONFIDO_BUILD_FLAGS={flags}");

    let mut features: Vec<_> = env::vars()
        .filter_map(|(name, _)| name.strip_prefix("CARGO_FEATURE_").map(str::to_owned))
        .collect();
    features.sort();
    println!(
        "cargo:rustc-env=CONFIDO_BUILD_FEATURES={}",
        features.join(",")
    );
    println!(
        "cargo:rustc-env=CONFIDO_BUILD_PROFILE={}",
        env::var("PROFILE").unwrap()
    );
}
