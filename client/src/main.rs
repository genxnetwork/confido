//! Caller-owned retrieval and explicit offline verification. No application client.
use confido::{Status, VerificationContext, VerificationInput, MAX_BODY, MAX_BUNDLE, MAX_METADATA};
use serde_json::{json, Value};
use std::{
    error::Error,
    fs,
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
type Result<T> = std::result::Result<T, Box<dyn Error>>;
fn read(p: &Path, limit: usize) -> Result<Vec<u8>> {
    use std::io::Read;
    let mut b = vec![];
    fs::File::open(p)?
        .take(limit as u64 + 1)
        .read_to_end(&mut b)?;
    if b.len() > limit {
        return Err("File exceeds size limit".into());
    }
    Ok(b)
}
fn save(path: &str, value: &Value) -> Result<()> {
    use std::{io::Write, os::unix::fs::OpenOptionsExt};
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(&serde_json::to_vec_pretty(value)?)?;
    Ok(())
}
fn s<'a>(v: &'a Value, k: &str) -> Result<&'a str> {
    v[k].as_str()
        .ok_or_else(|| format!("Missing string {k}").into())
}
fn now() -> Result<i64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_secs()
        .try_into()?)
}
fn client(untrusted: bool) -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .danger_accept_invalid_certs(untrusted)
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(30))
        .connect_timeout(Duration::from_secs(10))
        .build()?)
}
async fn body(mut r: reqwest::Response, limit: usize) -> Result<Vec<u8>> {
    if !r.status().is_success() {
        return Err(format!("HTTP {}", r.status()).into());
    }
    let mut b = vec![];
    while let Some(c) = r.chunk().await? {
        if b.len() + c.len() > limit {
            return Err("HTTP body exceeds limit".into());
        }
        b.extend_from_slice(&c)
    }
    Ok(b)
}
async fn kds(c: &reqwest::Client, url: &str) -> Result<Vec<u8>> {
    tokio::time::timeout(Duration::from_secs(60), async {
        for attempt in 0..3 {
            let r = c.get(url).send().await?;
            if ![429, 500, 502, 503, 504].contains(&r.status().as_u16()) || attempt == 2 {
                return body(r, MAX_METADATA).await;
            }
            let delay = r
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| {
                    v.parse::<u64>().ok().map(Duration::from_secs).or_else(|| {
                        httpdate::parse_http_date(v)
                            .ok()
                            .map(|t| t.duration_since(SystemTime::now()).unwrap_or_default())
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
fn validate_info(info: &Value, app: &Value) -> Result<()> {
    let ad = json!({"endpoint":"/tee-report","method":"POST","profile":"azure-snp-vtpm-ima/1","wireVersion":1,"nonce":{"name":"nonce","in":"body","encoding":"base64","sizeBytes":32},"response":{"evidenceField":"evidence","certificateField":"certificate"},"sessionBinding":{"supported":false}});
    if info["id"] != app["service_id"] || info["teeReport"] != ad {
        return Err("Incompatible discovery".into());
    }
    Ok(())
}
async fn collect(path: &Path) -> Result<(Value, Vec<u8>)> {
    let started = tokio::time::Instant::now();
    let app: Value = serde_json::from_slice(&read(path, MAX_METADATA)?)?;
    if app["schema_version"] != 2 {
        return Err("Application policy v2 required".into());
    }
    let origin = reqwest::Url::parse(s(&app, "origin")?)?;
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
    let policy_path = parent.join(s(&app, "verifier_policy")?).canonicalize()?;
    if !policy_path.starts_with(&parent) {
        return Err("Policy must be local".into());
    }
    let policy = read(&policy_path, MAX_METADATA)?;
    let p: confido::VerifierPolicy = serde_json::from_slice(&policy)?;
    p.validate()?;
    let bootstrap = client(app["allow_untrusted_bootstrap"].as_bool().unwrap_or(false))?;
    let public = client(false)?;
    let info: Value = serde_json::from_slice(
        &body(
            bootstrap.get(origin.join("/service-info")?).send().await?,
            MAX_METADATA,
        )
        .await?,
    )?;
    validate_info(&info, &app)?;
    let nonce: [u8; 32] = rand::random();
    let response = bootstrap
        .post(origin.join("/tee-report")?)
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
    let report = body(response, MAX_BODY).await?;
    let req = confido::inspect_requirements(&report)?;
    let product = req.product.as_deref().unwrap_or(&p.platform.product);
    if product != p.platform.product {
        return Err("Signed SNP processor differs from enrolled product".into());
    }
    let base = format!("https://kdsintf.amd.com/vcek/v1/{product}");
    let chain = kds(&public, &format!("{base}/cert_chain")).await?;
    let vcek = kds(
        &public,
        &format!(
            "{base}/{}?blSPL={:02}&teeSPL={:02}&snpSPL={:02}&ucodeSPL={:02}",
            req.chip_id, req.tcb[0], req.tcb[1], req.tcb[2], req.tcb[3]
        ),
    )
    .await?;
    let mut request = public
        .get(format!(
            "https://api.github.com/repos/{}/contents/{}?ref={}",
            p.reference.repository, p.reference.path, p.reference.commit
        ))
        .header("Accept", "application/vnd.github.raw+json")
        .header("User-Agent", concat!("confido-caller/", env!("CARGO_PKG_VERSION")));
    if let Ok(token) = std::env::var("CONFIDO_TRS_TOKEN") {
        request = request.bearer_auth(token)
    }
    let reference = body(request.send().await?, MAX_BODY).await?;
    if started.elapsed() > Duration::from_secs(120) {
        return Err("Challenge deadline expired".into());
    }
    Ok((
        json!({"schema_version":2,"mode":"live_collection","origin":origin.as_str(),"service_info":info,"inputs":{"report":base64::encode(report),"amd_chain":base64::encode(chain),"vcek":base64::encode(vcek),"reference":base64::encode(reference)},"context":{"expected_nonce_base64":base64::encode(nonce),"evaluation_unix_seconds":now()?}}),
        policy,
    ))
}
fn evaluate(
    archive: &Value,
    policy: &[u8],
    nonce: [u8; 32],
    at: i64,
) -> Result<confido::VerificationResult> {
    let (report, chain, vcek, reference) = if archive["schema_version"] == 1 {
        (
            serde_json::to_vec(&archive["report"])?,
            s(archive, "amd_chain_pem")?.as_bytes().to_vec(),
            serde_json::from_value::<Vec<u8>>(archive["vcek_der"].clone())?,
            s(archive, "reference_json")?.as_bytes().to_vec(),
        )
    } else if archive["schema_version"] == 2 {
        let i = &archive["inputs"];
        (
            base64::decode(s(i, "report")?)?,
            base64::decode(s(i, "amd_chain")?)?,
            base64::decode(s(i, "vcek")?)?,
            base64::decode(s(i, "reference")?)?,
        )
    } else {
        return Err("Unsupported archive schema".into());
    };
    Ok(confido::verify(
        VerificationInput {
            report_json: &report,
            amd_chain_pem: &chain,
            vcek_der: &vcek,
            reference_json: &reference,
        },
        policy,
        &VerificationContext {
            expected_nonce: nonce,
            evaluation_unix_seconds: at,
        },
    )?)
}
#[tokio::main]
async fn main() -> Result<()> {
    let a: Vec<_> = std::env::args().collect();
    if a.get(1).map(String::as_str) == Some("--build-info") {
        println!(
            "{}",
            serde_json::json!({"core":confido::build_info(),"wrapper":{
            "version":env!("CARGO_PKG_VERSION"),"source_sha256":env!("CONFIDO_SOURCE_SHA256"),
            "target":env!("CONFIDO_TARGET"),"rustc":env!("CONFIDO_RUSTC"),"flags":env!("CONFIDO_BUILD_FLAGS"),"features":env!("CONFIDO_BUILD_FEATURES"),"build_profile":env!("CONFIDO_BUILD_PROFILE")}})
        );
        return Ok(());
    }

    if a.get(1).map(String::as_str) == Some("--version") {
        println!("confido_client {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    if a.get(1).map(String::as_str) == Some("migrate-archive") {
        if a.len() != 5 {
            return Err("Usage: migrate-archive LEGACY_ARCHIVE NEW_ARCHIVE TIME".into());
        }
        let old: Value = serde_json::from_slice(&read(Path::new(&a[2]), MAX_BUNDLE)?)?;
        if old["schema_version"] != 1 {
            return Err("Expected legacy archive v1".into());
        }
        let nonce = s(&old, "nonce")?;
        if base64::decode(nonce)?.len() != 32 {
            return Err("Expected 32-byte historical nonce".into());
        }
        let at: i64 = a[4].parse()?;
        let migrated = json!({"schema_version":2,"mode":"historical_replay","inputs":{
   "report":base64::encode(serde_json::to_vec(&old["report"])?),"amd_chain":base64::encode(s(&old,"amd_chain_pem")?),
   "vcek":base64::encode(serde_json::from_value::<Vec<u8>>(old["vcek_der"].clone())?),"reference":base64::encode(s(&old,"reference_json")?)},
   "context":{"expected_nonce_base64":nonce,"evaluation_unix_seconds":at}});
        save(&a[3], &migrated)?;
        return Ok(());
    }
    if a.len() < 4 {
        return Err("Usage: collect|appraise APP_POLICY NEW_ARCHIVE | replay VERIFIER_POLICY ARCHIVE TIME | verify VERIFIER_POLICY ARCHIVE EXPECTED_NONCE TIME".into());
    }
    let result = match a[1].as_str() {
        "collect" | "appraise" => {
            let (mut archive, policy) = collect(Path::new(&a[2])).await?;
            if a[1] == "collect" {
                save(&a[3], &archive)?;
                return Ok(());
            }
            let nonce = base64::decode(s(&archive["context"], "expected_nonce_base64")?)?
                .try_into()
                .map_err(|_| "Expected 32 bytes")?;
            let r = evaluate(
                &archive,
                &policy,
                nonce,
                archive["context"]["evaluation_unix_seconds"]
                    .as_i64()
                    .ok_or("Missing time")?,
            )?;
            archive["verification"] = serde_json::to_value(&r)?;
            save(&a[3], &archive)?;
            r
        }
        "replay" | "verify" => {
            let archive: Value = serde_json::from_slice(&read(Path::new(&a[3]), MAX_BUNDLE)?)?;
            let policy = read(Path::new(&a[2]), MAX_METADATA)?;
            let (nonce, at) = if a[1] == "replay" {
                (
                    if archive["schema_version"] == 1 {
                        s(&archive, "nonce")?
                    } else {
                        s(&archive["context"], "expected_nonce_base64")?
                    },
                    a.get(4).ok_or("Explicit replay evaluation time required")?,
                )
            } else {
                (
                    a.get(4).ok_or("Independent nonce required")?.as_str(),
                    a.get(5).ok_or("Evaluation time required")?,
                )
            };
            evaluate(
                &archive,
                &policy,
                base64::decode(nonce)?
                    .try_into()
                    .map_err(|_| "Expected 32-byte nonce")?,
                at.parse()?,
            )?
        }
        _ => return Err("Unknown command".into()),
    };
    println!("{}", serde_json::to_string_pretty(&result)?);
    if result.status != Status::Verified {
        std::process::exit(2)
    }
    Ok(())
}
