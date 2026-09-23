//! Verifier-controlled collection, deterministic local appraisal and scoped HTTPS.
//! Offline results never construct a client or authorize a new operation.
use crate::{
    atls::{AttestationRequest, AttestationResponse},
    evidence::Evidence,
    nonce::{Base64, Nonce},
    profile,
    trs::TRS,
};
use az_snp_vtpm::{
    certs::{AmdChain, Vcek},
    report::Validateable,
};
use log::{debug, error, info};
use openssl::x509::X509;
use reqwest::{Client, Url};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    error::Error,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

pub use crate::profile::PlatformPolicy;
pub const PROFILE: &str = "azure-snp-vtpm-ima/1";
pub const WIRE_VERSION: u32 = 1;
pub const MAX_BODY: usize = 4 * 1024 * 1024;
pub const MAX_METADATA: usize = 64 * 1024;
pub const MAX_BUNDLE: usize = 16 * 1024 * 1024;

pub fn sha256(bytes: &[u8]) -> String {
    hex::encode(openssl::sha::sha256(bytes))
}
pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Reference {
    pub repository: String,
    pub commit: String,
    pub path: String,
    pub sha256: String,
}
impl Reference {
    pub fn locator(&self) -> String {
        format!(
            "https://github.com/{}/blob/{}/{}",
            self.repository, self.commit, self.path
        )
    }
    fn api_url(&self) -> String {
        format!(
            "https://api.github.com/repos/{}/contents/{}?ref={}",
            self.repository, self.path, self.commit
        )
    }
    fn validate(&self) -> Result<(), String> {
        fn safe(s: &str) -> bool {
            !s.is_empty()
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
                && s != "."
                && s != ".."
        }
        if self.repository.split('/').count() != 2
            || !self.repository.split('/').all(safe)
            || !self.path.split('/').all(safe)
            || self.commit.len() != 40
            || !is_hex(&self.commit, 40)
            || !is_hex(&self.sha256, 64)
        {
            return Err(
                "Reference requires repository, immutable 40-hex commit, safe path and SHA-256"
                    .into(),
            );
        }
        Ok(())
    }
}
fn is_hex(s: &str, len: usize) -> bool {
    s.len() == len
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppraisalConfig {
    pub origin: String,
    pub service_id: String,
    pub profile: String,
    pub reference: Reference,
    pub platform: PlatformPolicy,
}
impl AppraisalConfig {
    pub fn validate(&self) -> Result<Url, String> {
        let origin = origin_url(&self.origin)?;
        if self.profile != PROFILE || self.platform.product != "Milan" {
            return Err("Unsupported evidence profile or product".into());
        }
        if self.service_id.is_empty()
            || !is_hex(&self.platform.ark_sha256, 64)
            || !is_hex(&self.platform.launch_measurement, 96)
        {
            return Err("Missing service identity or invalid platform enrollment".into());
        }
        self.reference.validate()?;
        Ok(origin)
    }
}
pub fn origin_url(s: &str) -> Result<Url, String> {
    let u = Url::parse(s).map_err(|e| e.to_string())?;
    if u.scheme() != "https"
        || u.host_str().is_none()
        || !u.username().is_empty()
        || u.password().is_some()
        || u.path() != "/"
        || u.query().is_some()
        || u.fragment().is_some()
    {
        return Err(
            "Expected a bare HTTPS origin without credentials, path, query or fragment".into(),
        );
    }
    Ok(u)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Passed,
    InvalidEvidence,
    PolicyMismatch,
    UnsupportedProfile,
    DependencyUnavailable,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Check {
    pub stage: String,
    pub status: String,
    pub reason: String,
    pub detail: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppraisalResult {
    pub schema_version: u32,
    pub status: Status,
    pub reason: String,
    pub profile: String,
    pub wire_version: u32,
    pub mode: String,
    pub evaluated_at: i64,
    pub origin: String,
    pub service_id: String,
    pub checks: Vec<Check>,
    pub evidence_sha256: Option<String>,
    pub nonce: Option<String>,
    pub certificate_sha256: Option<String>,
    pub vtpm_key_sha256: Option<String>,
    pub reference: Reference,
    pub coverage: Value,
    pub bindings: Value,
    pub timings_ms: Value,
    pub limitations: Vec<String>,
    pub application_admitted: bool,
}
impl AppraisalResult {
    pub fn new(config: &AppraisalConfig, at: i64) -> Self {
        Self {schema_version:1,status:Status::InvalidEvidence,reason:"not_evaluated".into(),profile:PROFILE.into(),wire_version:WIRE_VERSION,
            mode:"historical_replay".into(),evaluated_at:at,origin:config.origin.clone(),service_id:config.service_id.clone(),checks:vec![],
            evidence_sha256:None,nonce:None,certificate_sha256:None,vtpm_key_sha256:None,reference:config.reference.clone(),
            coverage:json!({"ima_entries":0,"description":"Exact enrolled boot aggregate and IMA entries; no implied application/model/GPU coverage"}),
            bindings:json!({"fresh_quote":false,"snp_report_regenerated":false,"certificate_in_quote":false,"ima_log_in_quote":false,"tls_session":false}),
            timings_ms:json!({}),application_admitted:false,
            limitations:vec!["No TLS session binding or relay resistance claim".into(),"Point-in-time client admission; no server-side capability enforcement".into(),"Guest collector and TLS private-key custody are trusted".into(),"TCB floor and launch measurement are operator-enrolled baselines, not vulnerability-free certification".into(),"AMD revocation/security-advisory updates are not automatically checked".into(),"GPU and external inference are not appraised".into()]}
    }
    fn pass(&mut self, stage: &str, detail: impl Into<String>) {
        let detail = detail.into();
        info!("{stage}: {detail}");
        self.checks.push(Check {
            stage: stage.into(),
            status: "passed".into(),
            reason: "ok".into(),
            detail,
        });
    }
    pub fn fail(&mut self, stage: &str, status: Status, reason: &str, detail: impl ToString) {
        let detail = detail.to_string();
        error!("{stage}: {reason}: {detail}");
        self.status = status;
        self.reason = reason.into();
        self.application_admitted = false;
        self.checks.push(Check {
            stage: stage.into(),
            status: "failed".into(),
            reason: reason.into(),
            detail,
        });
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceBundle {
    pub schema_version: u32,
    pub origin: String,
    pub nonce: String,
    pub collected_at: i64,
    pub service_info: Value,
    pub report: Value,
    pub reference: Reference,
    /// Exact fetched reference bytes; digest is over these UTF-8 bytes, not reserialization.
    pub reference_json: String,
    pub amd_chain_pem: String,
    pub vcek_der: Vec<u8>,
}

pub fn validate_discovery(info: &Value, config: &AppraisalConfig) -> Result<(), String> {
    if info.get("id").and_then(Value::as_str) != Some(config.service_id.as_str()) {
        return Err("Service ID does not match verifier policy".into());
    }
    let ad = &info["teeReport"];
    let expected = json!({"endpoint":"/tee-report","method":"POST","profile":PROFILE,"wireVersion":WIRE_VERSION,
        "nonce":{"name":"nonce","in":"body","encoding":"base64","sizeBytes":32},
        "response":{"evidenceField":"evidence","certificateField":"certificate"},"sessionBinding":{"supported":false}});
    // Reject unsupported binding/version claims as well as cross-origin paths.
    if ad != &expected {
        return Err("Unsupported TEE advertisement; this client requires azure-snp-vtpm-ima/1, wireVersion 1 and sessionBinding false".into());
    }
    if info["type"]["group"] != "network.genxt.demo"
        || info["type"]["artifact"] != "confidential-chat"
    {
        return Err("Unsupported service type".into());
    }
    Ok(())
}
pub fn metadata_consistent(a: &Value, b: &Value) -> bool {
    ["id", "type", "version", "teeReport"]
        .iter()
        .all(|key| a.get(key) == b.get(key))
}

/// Pure local appraisal. `at` is independently supplied by the evaluator, never
/// trusted from a recorded bundle. Success here is not a chat authorization.
pub fn appraise(bundle: &EvidenceBundle, config: &AppraisalConfig, at: i64) -> AppraisalResult {
    let started = Instant::now();
    let mut result = AppraisalResult::new(config, at);
    let outcome = appraise_inner(bundle, config, at, &mut result);
    if outcome {
        result.status = Status::Passed;
        result.reason = "reference_match".into();
    }
    result.timings_ms["local_appraisal"] = json!(started.elapsed().as_secs_f64() * 1000.0);
    result
}
fn appraise_inner(
    b: &EvidenceBundle,
    c: &AppraisalConfig,
    at: i64,
    r: &mut AppraisalResult,
) -> bool {
    macro_rules! check {
        ($stage:expr,$status:expr,$reason:expr,$expr:expr) => {
            match $expr {
                Ok(value) => value,
                Err(e) => {
                    r.fail($stage, $status, $reason, e);
                    return false;
                }
            }
        };
    }
    check!(
        "profile",
        Status::UnsupportedProfile,
        "unsupported_profile",
        c.validate()
    );
    if b.schema_version != 1
        || b.report["wireVersion"] != WIRE_VERSION
        || b.report["profile"] != PROFILE
    {
        r.fail(
            "profile",
            Status::UnsupportedProfile,
            "unsupported_wire_version",
            "Bundle/report profile or version unsupported",
        );
        return false;
    }
    if b.origin != c.origin || b.reference != c.reference {
        r.fail(
            "reference",
            Status::PolicyMismatch,
            "reference_identity_mismatch",
            "Bundle origin or reference identity differs from verifier policy",
        );
        return false;
    }
    if b.reference_json.len() > MAX_BODY
        || b.amd_chain_pem.len() > MAX_METADATA
        || b.vcek_der.len() > MAX_METADATA
    {
        r.fail(
            "input",
            Status::InvalidEvidence,
            "input_too_large",
            "Bundle component exceeds profile size limit",
        );
        return false;
    }
    check!(
        "discovery",
        Status::UnsupportedProfile,
        "unsupported_discovery",
        validate_discovery(&b.service_info, c)
    );
    r.pass(
        "discovery",
        "Service identity and report contract match verifier policy",
    );
    let bytes = check!(
        "evidence",
        Status::InvalidEvidence,
        "malformed_evidence",
        serde_json::to_vec(&b.report)
    );
    if bytes.len() > MAX_BODY {
        r.fail(
            "evidence",
            Status::InvalidEvidence,
            "input_too_large",
            "Report exceeds 4 MiB",
        );
        return false;
    }
    r.evidence_sha256 = Some(sha256(&bytes));
    r.nonce = Some(b.nonce.clone());
    let mut nonce = check!(
        "challenge",
        Status::InvalidEvidence,
        "invalid_nonce",
        Nonce::read(&Base64::from_base64(b.nonce.clone()))
    );
    let response: AttestationResponse = check!(
        "evidence",
        Status::InvalidEvidence,
        "malformed_evidence",
        serde_json::from_value(b.report.clone())
    );
    let cert = check!(
        "certificate",
        Status::InvalidEvidence,
        "invalid_certificate",
        X509::from_pem(&response.certificate)
    );
    let der = check!(
        "certificate",
        Status::InvalidEvidence,
        "invalid_certificate",
        cert.to_der()
    );
    r.certificate_sha256 = Some(sha256(&der));
    let (_, parsed_cert) = check!(
        "certificate",
        Status::InvalidEvidence,
        "invalid_certificate",
        x509_parser::parse_x509_certificate(&der)
    );
    if parsed_cert.is_ca() {
        r.fail(
            "certificate",
            Status::UnsupportedProfile,
            "ca_certificate_unsupported",
            "Profile requires a leaf TLS certificate",
        );
        return false;
    }
    let (report, var_hash, ak) = check!(
        "snp_report",
        Status::InvalidEvidence,
        "malformed_hcl",
        response.evidence.parse_report()
    );
    if ![2, 3].contains(&report.version) || report.sig_algo != 1 {
        r.fail(
            "snp_report",
            Status::UnsupportedProfile,
            "unsupported_snp_report",
            "Only Milan SNP versions 2/3 with ECDSA P-384/SHA-384 are supported",
        );
        return false;
    }
    let certs = check!(
        "endorsements",
        Status::InvalidEvidence,
        "invalid_endorsements",
        X509::stack_from_pem(b.amd_chain_pem.as_bytes())
    );
    if certs.len() != 2 {
        r.fail(
            "endorsements",
            Status::InvalidEvidence,
            "invalid_endorsements",
            "Expected ASK and ARK",
        );
        return false;
    }
    let chain = AmdChain {
        ask: certs[0].clone(),
        ark: certs[1].clone(),
    };
    let vcek = Vcek(check!(
        "endorsements",
        Status::InvalidEvidence,
        "invalid_endorsements",
        X509::from_der(&b.vcek_der)
    ));
    check!(
        "endorsements",
        Status::InvalidEvidence,
        "endorsement_chain_invalid",
        profile::endorsements(&chain, &vcek, &c.platform, at)
    );
    check!(
        "endorsements",
        Status::InvalidEvidence,
        "endorsement_report_mismatch",
        profile::correspondence(&report, &vcek, &c.platform)
    );
    r.pass(
        "endorsements",
        "Pinned AMD root, valid certificate chain, VCEK product/chip/TCB correspondence",
    );
    check!(
        "snp_signature",
        Status::InvalidEvidence,
        "snp_signature_invalid",
        report.validate(&vcek)
    );
    r.pass(
        "snp_signature",
        "SNP signature and reported/committed TCB equality verified",
    );
    check!(
        "platform_policy",
        Status::PolicyMismatch,
        "platform_policy_mismatch",
        profile::guest_policy(&report, &c.platform)
    );
    r.pass(
        "platform_policy",
        "VMPL 0, debug/migration disabled, enrolled launch measurement and minimum TCB satisfied",
    );
    if var_hash != report.report_data[..32] {
        r.fail(
            "hcl_key",
            Status::InvalidEvidence,
            "hcl_binding_invalid",
            "HCL variable-data hash differs from SNP report_data",
        );
        return false;
    }
    r.vtpm_key_sha256 = Some(sha256(&check!(
        "hcl_key",
        Status::InvalidEvidence,
        "invalid_ak",
        ak.public_key_to_der()
    )));
    r.pass(
        "hcl_key",
        "vTPM attestation public key extracted from SNP-authenticated HCL metadata",
    );
    let binding = check!(
        "quote",
        Status::InvalidEvidence,
        "invalid_ima_encoding",
        Evidence::ima_binding(&response.evidence.ima_measurements)
    );
    nonce.extend_binding(&cert, &binding);
    check!(
        "quote",
        Status::InvalidEvidence,
        "quote_binding_invalid",
        crate::quote::verify(&response.evidence.quote, &ak, nonce.as_bytes())
    );
    r.bindings["challenge_bound_quote"] = json!(true);
    r.bindings["certificate_in_quote"] = json!(true);
    r.bindings["ima_log_in_quote"] = json!(true);
    r.pass(
        "quote",
        "AK signature, challenge/certificate/log transcript and signed PCR selection verified",
    );
    debug!("Evidence: {:?}", response.evidence);
    if sha256(b.reference_json.as_bytes()) != c.reference.sha256 {
        r.fail(
            "reference",
            Status::PolicyMismatch,
            "reference_digest_mismatch",
            "Fetched reference bytes differ from pinned SHA-256",
        );
        return false;
    }
    let trs: TRS = check!(
        "reference",
        Status::PolicyMismatch,
        "reference_invalid",
        serde_json::from_str(&b.reference_json)
    );
    r.pass(
        "reference",
        format!("{} (SHA-256 {})", c.reference.locator(), c.reference.sha256),
    );
    r.coverage["ima_entries"] = json!(response.evidence.ima_measurements.len());
    r.coverage["pcr10_method"] = json!(if trs.pcr10_sha256.is_some() {
        "enrolled_sha256"
    } else {
        "template_digest_replay"
    });
    check!(
        "measurements",
        Status::PolicyMismatch,
        "measurement_mismatch",
        response.evidence.verify_measurements(&trs)
    );
    r.pass(
        "measurements",
        "Measured boot aggregate, exact IMA log and PCR 10 match the configured reference",
    );
    true
}

#[derive(Debug)]
struct CollectionFailure {
    status: Status,
    reason: &'static str,
    detail: String,
}
impl std::fmt::Display for CollectionFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.reason, self.detail)
    }
}
impl Error for CollectionFailure {}
fn collection_failure(
    status: Status,
    reason: &'static str,
    detail: impl ToString,
) -> Box<dyn Error> {
    Box::new(CollectionFailure {
        status,
        reason,
        detail: detail.to_string(),
    })
}

pub async fn limited_body(
    mut response: reqwest::Response,
    limit: usize,
) -> Result<Vec<u8>, Box<dyn Error>> {
    if response.status().is_redirection() {
        return Err(collection_failure(
            Status::UnsupportedProfile,
            "redirect_rejected",
            "HTTP redirects are disabled",
        ));
    }
    if !response.status().is_success() {
        return Err(format!("HTTP {} (redirects are disabled)", response.status()).into());
    }
    if response
        .content_length()
        .is_some_and(|len| len > limit as u64)
    {
        return Err(collection_failure(
            Status::InvalidEvidence,
            "input_too_large",
            "HTTP body exceeds size limit",
        ));
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if bytes.len() + chunk.len() > limit {
            return Err(collection_failure(
                Status::InvalidEvidence,
                "input_too_large",
                "HTTP body exceeds size limit",
            ));
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}
fn public_client(bootstrap: bool) -> Result<Client, reqwest::Error> {
    Client::builder()
        .danger_accept_invalid_certs(bootstrap)
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(30))
        .connect_timeout(Duration::from_secs(10))
        .build()
}
pub async fn discover(config: &AppraisalConfig) -> Result<Value, Box<dyn Error>> {
    let origin = config.validate()?;
    let bytes = limited_body(
        public_client(true)?
            .get(origin.join("/service-info")?)
            .send()
            .await?,
        MAX_METADATA,
    )
    .await?;
    Ok(serde_json::from_slice(&bytes)?)
}

async fn collect(
    config: &AppraisalConfig,
    preview: Value,
    nonce: &Nonce,
) -> Result<(EvidenceBundle, Value), Box<dyn Error>> {
    let origin = config.validate()?;
    validate_discovery(&preview, config)?;
    let started = Instant::now();
    let response = public_client(true)?
        .post(origin.join("/tee-report")?)
        .json(&AttestationRequest {
            nonce: nonce.clone().into(),
        })
        .send()
        .await?;
    if response.status().is_success()
        && response
            .headers()
            .get("cache-control")
            .and_then(|h| h.to_str().ok())
            .is_none_or(|s| {
                !s.split(',')
                    .any(|v| v.trim().eq_ignore_ascii_case("no-store"))
            })
    {
        return Err(collection_failure(
            Status::UnsupportedProfile,
            "unsupported_report_contract",
            "Report response must declare Cache-Control: no-store",
        ));
    }
    let report_bytes = limited_body(response, MAX_BODY).await?;
    let report: Value = serde_json::from_slice(&report_bytes)
        .map_err(|e| collection_failure(Status::InvalidEvidence, "malformed_report", e))?;
    if report["profile"] != PROFILE || report["wireVersion"] != WIRE_VERSION {
        return Err(collection_failure(
            Status::UnsupportedProfile,
            "unsupported_wire_version",
            "Report profile/version differs from supported contract",
        ));
    }
    let parsed: AttestationResponse = serde_json::from_slice(&report_bytes)
        .map_err(|e| collection_failure(Status::InvalidEvidence, "malformed_report", e))?;
    let (snp, _, _) = parsed
        .evidence
        .parse_report()
        .map_err(|e| collection_failure(Status::InvalidEvidence, "malformed_hcl", e))?;
    if ![2, 3].contains(&snp.version) || snp.sig_algo != 1 {
        return Err(collection_failure(
            Status::UnsupportedProfile,
            "unsupported_snp_report",
            "SNP report version/signature unsupported",
        ));
    }
    let collection_ms = started.elapsed().as_secs_f64() * 1000.0;
    let deps = Instant::now();
    let chain = crate::kds::get_cert_chain().await?;
    let vcek = crate::kds::get_vcek(&snp).await?;
    let kds_ms = deps.elapsed().as_secs_f64() * 1000.0;
    let reference_started = Instant::now();
    let mut request = public_client(false)?
        .get(config.reference.api_url())
        .header("Accept", "application/vnd.github.raw+json")
        .header("User-Agent", "confido/0.3.0");
    // Optional registry-only token: never sent to a discovered host or saved.
    if let Ok(token) = std::env::var("CONFIDO_TRS_TOKEN") {
        request = request.bearer_auth(token);
    }
    let reference = limited_body(request.send().await?, MAX_BODY).await?;
    let chain_bytes = [chain.ask.to_pem()?, chain.ark.to_pem()?].concat();
    let bundle = EvidenceBundle {
        schema_version: 1,
        origin: config.origin.clone(),
        nonce: nonce.as_string(),
        collected_at: now(),
        service_info: preview,
        report,
        reference: config.reference.clone(),
        reference_json: String::from_utf8(reference)?,
        amd_chain_pem: String::from_utf8(chain_bytes)?,
        vcek_der: vcek.0.to_der()?,
    };
    Ok((
        bundle,
        json!({"collection_network":collection_ms,"kds_network":kds_ms,"reference_network":reference_started.elapsed().as_secs_f64()*1000.0}),
    ))
}

/// Only live `connect` can create this capability. The reqwest client is private.
pub struct AppraisedClient {
    client: Client,
    origin: Url,
}
impl AppraisedClient {
    pub async fn request(
        &self,
        method: &str,
        url: &str,
        headers: &[(String, String)],
        body: Vec<u8>,
    ) -> Result<(u16, Vec<(String, String)>, Vec<u8>), Box<dyn Error>> {
        let target = Url::parse(url)?;
        if target.origin() != self.origin.origin()
            || target.scheme() != "https"
            || !target.username().is_empty()
            || target.password().is_some()
            || target.fragment().is_some()
        {
            return Err("Application request is outside the appraised HTTPS origin".into());
        }
        let mut request = self.client.request(method.parse()?, target).body(body);
        for (k, v) in headers {
            if [
                "host",
                "connection",
                "transfer-encoding",
                "content-length",
                "proxy-authorization",
            ]
            .contains(&k.to_ascii_lowercase().as_str())
            {
                // reqwest computes authority/framing; caller cannot redirect it.
                continue;
            }
            request = request.header(k, v);
        }
        let mut response = request.send().await?;
        if response.status().is_redirection() {
            return Err("Application redirects are disabled".into());
        }
        let status = response.status().as_u16();
        let headers = response
            .headers()
            .iter()
            .filter_map(|(k, v)| v.to_str().ok().map(|v| (k.to_string(), v.to_string())))
            .collect();
        let mut bytes = vec![];
        while let Some(chunk) = response.chunk().await? {
            if bytes.len() + chunk.len() > MAX_BODY {
                return Err("Application response exceeds size limit".into());
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok((status, headers, bytes))
    }
}
pub struct ConnectionOutcome {
    pub result: AppraisalResult,
    pub bundle: Option<EvidenceBundle>,
    pub client: Option<AppraisedClient>,
}

pub async fn connect(config: &AppraisalConfig, preview: Value) -> ConnectionOutcome {
    let mut result = AppraisalResult::new(config, now());
    result.mode = "live".into();
    let origin = match config.validate() {
        Ok(u) => u,
        Err(e) => {
            result.fail(
                "profile",
                Status::UnsupportedProfile,
                "unsupported_profile",
                e,
            );
            return ConnectionOutcome {
                result,
                bundle: None,
                client: None,
            };
        }
    };
    if let Err(e) = validate_discovery(&preview, config) {
        result.fail(
            "discovery",
            Status::UnsupportedProfile,
            "unsupported_discovery",
            e,
        );
        return ConnectionOutcome {
            result,
            bundle: None,
            client: None,
        };
    }
    let nonce = Nonce::generate();
    result.nonce = Some(nonce.as_string());
    let (bundle, timings) = match collect(config, preview, &nonce).await {
        Ok(v) => v,
        Err(e) => {
            if let Some(failure) = e.downcast_ref::<CollectionFailure>() {
                result.fail(
                    "collection",
                    failure.status.clone(),
                    failure.reason,
                    &failure.detail,
                );
            } else {
                result.fail(
                    "collection",
                    Status::DependencyUnavailable,
                    "collection_unavailable",
                    e,
                );
            }
            return ConnectionOutcome {
                result,
                bundle: None,
                client: None,
            };
        }
    };
    result = appraise(&bundle, config, now());
    result.mode = "live".into();
    if result.bindings["challenge_bound_quote"] == true {
        result.bindings["fresh_quote"] = json!(true);
    }
    for (k, v) in timings.as_object().unwrap() {
        result.timings_ms[k] = v.clone();
    }
    if result.status != Status::Passed {
        return ConnectionOutcome {
            result,
            bundle: Some(bundle),
            client: None,
        };
    }
    let started = Instant::now();
    let authenticate = async {
        let response: AttestationResponse = serde_json::from_value(bundle.report.clone())?;
        let certificate = reqwest::Certificate::from_pem(&response.certificate)?;
        let client = Client::builder()
            .use_native_tls()
            .tls_built_in_root_certs(false)
            .add_root_certificate(certificate)
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(30))
            .connect_timeout(Duration::from_secs(10))
            .build()?;
        let info: Value = serde_json::from_slice(
            &limited_body(
                client.get(origin.join("/service-info")?).send().await?,
                MAX_METADATA,
            )
            .await?,
        )?;
        validate_discovery(&info, config)?;
        if !metadata_consistent(&bundle.service_info, &info) {
            return Err("Critical ServiceInfo changed after HTTPS peer authentication".into());
        }
        Ok::<_, Box<dyn Error>>(AppraisedClient { client, origin })
    }
    .await;
    result.timings_ms["https_authentication"] = json!(started.elapsed().as_secs_f64() * 1000.0);
    match authenticate {
        Ok(client) => {
            result.pass("https_peer","Intended HTTPS hostname authenticated using only the appraised certificate; critical metadata unchanged");
            result.application_admitted = true;
            ConnectionOutcome {
                result,
                bundle: Some(bundle),
                client: Some(client),
            }
        }
        Err(e) => {
            result.fail(
                "https_peer",
                Status::InvalidEvidence,
                "https_authentication_failed",
                e,
            );
            ConnectionOutcome {
                result,
                bundle: Some(bundle),
                client: None,
            }
        }
    }
}

/// New files only, owner-readable; never overwrite another run's evidence.
pub fn save_private_json(
    path: &std::path::Path,
    value: &impl Serialize,
) -> Result<(), Box<dyn Error>> {
    use std::{io::Write, os::unix::fs::OpenOptionsExt};
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(&serde_json::to_vec_pretty(value)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn config() -> AppraisalConfig {
        serde_json::from_str(include_str!("../../profiles/match.json")).unwrap()
    }
    #[test]
    fn policy_rejects_mutable_refs_and_unsafe_origins() {
        let mut c = config();
        c.validate().unwrap();
        c.reference.commit = "main".into();
        assert!(c.validate().is_err());
        for origin in [
            "http://example.org",
            "https://user:pass@example.org",
            "https://example.org/path",
            "https://example.org?x=1",
            "https://example.org#frag",
        ] {
            assert!(origin_url(origin).is_err());
        }
        c = config();
        c.reference.path = "../secret".into();
        assert!(c.validate().is_err());
    }
    #[test]
    fn discovery_and_metadata_fail_closed() {
        let c = config();
        let mut a = json!({"id":c.service_id,"type":{"group":"network.genxt.demo","artifact":"confidential-chat","version":"0.2.0"},"version":"0.3.0","teeReport":{"endpoint":"/tee-report","method":"POST","profile":PROFILE,"wireVersion":1,"nonce":{"name":"nonce","in":"body","encoding":"base64","sizeBytes":32},"response":{"evidenceField":"evidence","certificateField":"certificate"},"sessionBinding":{"supported":false}}});
        validate_discovery(&a, &c).unwrap();
        let b = a.clone();
        a["description"] = json!("display update");
        assert!(metadata_consistent(&a, &b));
        a["id"] = json!("other");
        assert!(!metadata_consistent(&a, &b));
        assert!(validate_discovery(&a, &c).is_err());
        for endpoint in [
            "https://other.example/tee-report",
            "//other.example/tee-report",
            "/aTLS",
        ] {
            a = b.clone();
            a["teeReport"]["endpoint"] = json!(endpoint);
            assert!(validate_discovery(&a, &c).is_err());
        }
        a = b.clone();
        a["teeReport"]["wireVersion"] = json!(2);
        assert!(validate_discovery(&a, &c).is_err());
        a = b;
        a["teeReport"].as_object_mut().unwrap().remove("profile");
        assert!(validate_discovery(&a, &c).is_err());
    }
    #[tokio::test]
    async fn scoped_client_rejects_other_origin_before_network() {
        let client = AppraisedClient {
            client: Client::new(),
            origin: origin_url("https://localhost:19443").unwrap(),
        };
        for target in [
            "https://localhost:19444/v1",
            "https://127.0.0.1:19443/v1",
            "http://localhost:19443/v1",
            "https://u:p@localhost:19443/v1",
        ] {
            assert!(client
                .request(
                    "POST",
                    target,
                    &[("authorization".into(), "must-not-leave".into())],
                    vec![]
                )
                .await
                .unwrap_err()
                .to_string()
                .contains("outside"));
        }
    }
}
