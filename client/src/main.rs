//! CLI for collecting evidence and invoking the portable verifier.
//!
//! Application transport and admission belong to the caller, not this CLI.
use confido::{
    Status, VerificationContext, VerificationInput, VerifierPolicy, MAX_BODY, MAX_BUNDLE,
    MAX_METADATA,
};
use serde_json::{json, Value};
use std::{
    env,
    error::Error,
    fs,
    io::{Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

const CHALLENGE_DEADLINE: Duration = Duration::from_secs(120);
const USAGE: &str = "Usage:
  confido-cli collect APP_POLICY NEW_ARCHIVE
  confido-cli appraise APP_POLICY NEW_ARCHIVE
  confido-cli verify VERIFIER_POLICY ARCHIVE EXPECTED_NONCE TIME
  confido-cli replay VERIFIER_POLICY ARCHIVE TIME
  confido-cli migrate-archive LEGACY_ARCHIVE NEW_ARCHIVE TIME";

struct LoadedApplicationPolicy {
    settings: Value,
    origin: reqwest::Url,
    verifier_policy_bytes: Vec<u8>,
    verifier_policy: VerifierPolicy,
}

struct ArchiveInputs {
    report: Vec<u8>,
    amd_chain: Vec<u8>,
    vcek: Vec<u8>,
    reference: Vec<u8>,
}

fn read_limited(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err("File exceeds size limit".into());
    }
    Ok(bytes)
}

fn write_new_archive(path: &str, value: &Value) -> Result<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(&serde_json::to_vec_pretty(value)?)?;
    Ok(())
}

fn required_string<'a>(value: &'a Value, field: &str) -> Result<&'a str> {
    value[field]
        .as_str()
        .ok_or_else(|| format!("Missing string {field}").into())
}

fn now_unix_seconds() -> Result<i64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_secs()
        .try_into()?)
}

fn http_client(allow_untrusted_certificates: bool) -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .danger_accept_invalid_certs(allow_untrusted_certificates)
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(30))
        .connect_timeout(Duration::from_secs(10))
        .build()?)
}

async fn read_response_body(mut response: reqwest::Response, limit: usize) -> Result<Vec<u8>> {
    if !response.status().is_success() {
        return Err(format!("HTTP {}", response.status()).into());
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if bytes.len() + chunk.len() > limit {
            return Err("HTTP body exceeds limit".into());
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

async fn fetch_kds(client: &reqwest::Client, url: &str) -> Result<Vec<u8>> {
    tokio::time::timeout(Duration::from_secs(60), async {
        for attempt in 0..3 {
            let response = client.get(url).send().await?;
            if ![429, 500, 502, 503, 504].contains(&response.status().as_u16()) || attempt == 2 {
                return read_response_body(response, MAX_METADATA).await;
            }
            let delay = response
                .headers()
                .get("retry-after")
                .and_then(|value| value.to_str().ok())
                .and_then(|value| {
                    value
                        .parse::<u64>()
                        .ok()
                        .map(Duration::from_secs)
                        .or_else(|| {
                            httpdate::parse_http_date(value).ok().map(|time| {
                                time.duration_since(SystemTime::now()).unwrap_or_default()
                            })
                        })
                })
                .unwrap_or(Duration::from_secs(1 << attempt));
            if delay >= Duration::from_secs(60) {
                return Err("KDS retry exceeds deadline".into());
            }
            tokio::time::sleep(delay).await;
        }
        Err("KDS unavailable".into())
    })
    .await?
}
fn load_application_policy(path: &Path) -> Result<LoadedApplicationPolicy> {
    let application: Value = serde_json::from_slice(&read_limited(path, MAX_METADATA)?)?;
    if application["schema_version"] != 2 {
        return Err("Application policy v2 required".into());
    }

    let origin = reqwest::Url::parse(required_string(&application, "origin")?)?;
    if origin.scheme() != "https"
        || origin.host_str().is_none()
        || origin.path() != "/"
        || !origin.username().is_empty()
        || origin.password().is_some()
        || origin.query().is_some()
        || origin.fragment().is_some()
    {
        return Err("Expected bare HTTPS origin".into());
    }

    let parent = path.parent().unwrap_or(Path::new(".")).canonicalize()?;
    let policy_path = parent
        .join(required_string(&application, "verifier_policy")?)
        .canonicalize()?;
    if !policy_path.starts_with(&parent) {
        return Err("Policy must be local".into());
    }
    let policy_bytes = read_limited(&policy_path, MAX_METADATA)?;
    let verifier_policy: VerifierPolicy = serde_json::from_slice(&policy_bytes)?;
    verifier_policy.validate()?;

    Ok(LoadedApplicationPolicy {
        settings: application,
        origin,
        verifier_policy_bytes: policy_bytes,
        verifier_policy,
    })
}

async fn fetch_reference(client: &reqwest::Client, policy: &VerifierPolicy) -> Result<Vec<u8>> {
    let mut request = client
        .get(format!(
            "https://api.github.com/repos/{}/contents/{}?ref={}",
            policy.reference.repository, policy.reference.path, policy.reference.commit
        ))
        .header("Accept", "application/vnd.github.raw+json")
        .header(
            "User-Agent",
            concat!("confido-caller/", env!("CARGO_PKG_VERSION")),
        );
    if let Ok(token) = env::var("CONFIDO_TRS_TOKEN") {
        request = request.bearer_auth(token);
    }
    read_response_body(request.send().await?, MAX_BODY).await
}

async fn collect_live_inputs(application_policy_path: &Path) -> Result<(Value, Vec<u8>)> {
    let started = tokio::time::Instant::now();
    let loaded = load_application_policy(application_policy_path)?;
    let bootstrap = http_client(
        loaded.settings["allow_untrusted_bootstrap"]
            .as_bool()
            .unwrap_or(false),
    )?;
    let public = http_client(false)?;
    let nonce: [u8; 32] = rand::random();

    let response = bootstrap
        .post(loaded.origin.join("/tee-report")?)
        .json(&json!({"nonce":base64::encode(nonce)}))
        .send()
        .await?;
    if !response
        .headers()
        .get("cache-control")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| {
            v.split(',')
                .any(|s| s.trim().eq_ignore_ascii_case("no-store"))
        })
    {
        return Err("Missing no-store".into());
    }
    let report = read_response_body(response, MAX_BODY).await?;

    // These report fields select the KDS certificate; the verifier checks them later.
    let requirements = confido::inspect_requirements(&report)?;
    let product = requirements
        .product
        .as_deref()
        .unwrap_or(&loaded.verifier_policy.platform.product);
    if product != loaded.verifier_policy.platform.product {
        return Err("Signed SNP processor differs from enrolled product".into());
    }
    let base = format!("https://kdsintf.amd.com/vcek/v1/{product}");
    let amd_chain = fetch_kds(&public, &format!("{base}/cert_chain")).await?;
    let vcek = fetch_kds(
        &public,
        &format!(
            "{base}/{}?blSPL={:02}&teeSPL={:02}&snpSPL={:02}&ucodeSPL={:02}",
            requirements.chip_id,
            requirements.tcb[0],
            requirements.tcb[1],
            requirements.tcb[2],
            requirements.tcb[3]
        ),
    )
    .await?;
    let reference = fetch_reference(&public, &loaded.verifier_policy).await?;
    if started.elapsed() > CHALLENGE_DEADLINE {
        return Err("Challenge deadline expired".into());
    }

    Ok((
        json!({
            "schema_version": 2,
            "mode": "live_collection",
            "origin": loaded.origin.as_str(),
            "inputs": {
                "report": base64::encode(report),
                "amd_chain": base64::encode(amd_chain),
                "vcek": base64::encode(vcek),
                "reference": base64::encode(reference)
            },
            "context": {
                "expected_nonce_base64": base64::encode(nonce),
                "evaluation_unix_seconds": now_unix_seconds()?
            }
        }),
        loaded.verifier_policy_bytes,
    ))
}
fn archive_inputs(archive: &Value) -> Result<ArchiveInputs> {
    match archive["schema_version"].as_i64() {
        Some(1) => Ok(ArchiveInputs {
            report: serde_json::to_vec(&archive["report"])?,
            amd_chain: required_string(archive, "amd_chain_pem")?
                .as_bytes()
                .to_vec(),
            vcek: serde_json::from_value::<Vec<u8>>(archive["vcek_der"].clone())?,
            reference: required_string(archive, "reference_json")?
                .as_bytes()
                .to_vec(),
        }),
        Some(2) => {
            let inputs = &archive["inputs"];
            Ok(ArchiveInputs {
                report: base64::decode(required_string(inputs, "report")?)?,
                amd_chain: base64::decode(required_string(inputs, "amd_chain")?)?,
                vcek: base64::decode(required_string(inputs, "vcek")?)?,
                reference: base64::decode(required_string(inputs, "reference")?)?,
            })
        }
        _ => Err("Unsupported archive schema".into()),
    }
}

fn evaluate_archive(
    archive: &Value,
    policy: &[u8],
    nonce: [u8; 32],
    at: i64,
) -> Result<confido::VerificationResult> {
    let inputs = archive_inputs(archive)?;
    Ok(confido::verify(
        VerificationInput {
            report_json: &inputs.report,
            amd_chain_pem: &inputs.amd_chain,
            vcek_der: &inputs.vcek,
            reference_json: &inputs.reference,
        },
        policy,
        &VerificationContext {
            expected_nonce: nonce,
            evaluation_unix_seconds: at,
        },
    )?)
}

fn decode_nonce(encoded: &str) -> Result<[u8; 32]> {
    base64::decode(encoded)?
        .try_into()
        .map_err(|_| "Expected 32-byte nonce".into())
}

fn migrate_legacy_archive(args: &[String]) -> Result<()> {
    if args.len() != 5 {
        return Err("Usage: migrate-archive LEGACY_ARCHIVE NEW_ARCHIVE TIME".into());
    }
    let old: Value = serde_json::from_slice(&read_limited(Path::new(&args[2]), MAX_BUNDLE)?)?;
    if old["schema_version"] != 1 {
        return Err("Expected legacy archive v1".into());
    }
    let nonce = required_string(&old, "nonce")?;
    decode_nonce(nonce)?;
    let evaluation_time: i64 = args[4].parse()?;

    let migrated = json!({
        "schema_version": 2,
        "mode": "historical_replay",
        "inputs": {
            "report": base64::encode(serde_json::to_vec(&old["report"])?),
            "amd_chain": base64::encode(required_string(&old, "amd_chain_pem")?),
            "vcek": base64::encode(serde_json::from_value::<Vec<u8>>(old["vcek_der"].clone())?),
            "reference": base64::encode(required_string(&old, "reference_json")?)
        },
        "context": {
            "expected_nonce_base64": nonce,
            "evaluation_unix_seconds": evaluation_time
        }
    });
    write_new_archive(&args[3], &migrated)
}

async fn run_collect(args: &[String]) -> Result<()> {
    let (archive, _) = collect_live_inputs(Path::new(&args[2])).await?;
    write_new_archive(&args[3], &archive)
}

async fn run_appraise(args: &[String]) -> Result<confido::VerificationResult> {
    let (mut archive, policy) = collect_live_inputs(Path::new(&args[2])).await?;
    let nonce = decode_nonce(required_string(
        &archive["context"],
        "expected_nonce_base64",
    )?)?;
    let evaluation_time = archive["context"]["evaluation_unix_seconds"]
        .as_i64()
        .ok_or("Missing time")?;
    let result = evaluate_archive(&archive, &policy, nonce, evaluation_time)?;
    archive["verification"] = serde_json::to_value(&result)?;
    write_new_archive(&args[3], &archive)?;
    Ok(result)
}

fn run_archive_check(args: &[String]) -> Result<confido::VerificationResult> {
    let archive: Value = serde_json::from_slice(&read_limited(Path::new(&args[3]), MAX_BUNDLE)?)?;
    let policy = read_limited(Path::new(&args[2]), MAX_METADATA)?;

    let (nonce, evaluation_time) = if args[1] == "replay" {
        let nonce = if archive["schema_version"] == 1 {
            required_string(&archive, "nonce")?
        } else {
            required_string(&archive["context"], "expected_nonce_base64")?
        };
        (
            nonce,
            args.get(4)
                .ok_or("Explicit replay evaluation time required")?,
        )
    } else {
        (
            args.get(4).ok_or("Independent nonce required")?.as_str(),
            args.get(5).ok_or("Evaluation time required")?,
        )
    };

    evaluate_archive(
        &archive,
        &policy,
        decode_nonce(nonce)?,
        evaluation_time.parse()?,
    )
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<_> = env::args().collect();
    if args.get(1).map(String::as_str) == Some("--build-info") {
        println!(
            "{}",
            json!({
                "core": confido::build_info(),
                "wrapper": {
                    "version": env!("CARGO_PKG_VERSION"),
                    "source_sha256": env!("CONFIDO_SOURCE_SHA256"),
                    "target": env!("CONFIDO_TARGET"),
                    "rustc": env!("CONFIDO_RUSTC"),
                    "flags": env!("CONFIDO_BUILD_FLAGS"),
                    "features": env!("CONFIDO_BUILD_FEATURES"),
                    "build_profile": env!("CONFIDO_BUILD_PROFILE")
                }
            })
        );
        return Ok(());
    }

    if args.get(1).map(String::as_str) == Some("--version") {
        println!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    if args.get(1).map(String::as_str) == Some("migrate-archive") {
        return migrate_legacy_archive(&args);
    }
    if args.len() < 4 {
        return Err(USAGE.into());
    }
    let result = match args[1].as_str() {
        "collect" => {
            run_collect(&args).await?;
            return Ok(());
        }
        "appraise" => run_appraise(&args).await?,
        "replay" | "verify" => run_archive_check(&args)?,
        _ => return Err("Unknown command".into()),
    };

    println!("{}", serde_json::to_string_pretty(&result)?);
    if result.status != Status::Verified {
        std::process::exit(2);
    }
    Ok(())
}
