use az_snp_vtpm::certs::{AmdChain, Vcek};
use az_snp_vtpm::report::AttestationReport;
use log::warn;
use openssl::x509::X509;
use reqwest::header::{HeaderMap, RETRY_AFTER};
use reqwest::{Client, StatusCode};
use std::collections::HashMap;
use std::error::Error;
use std::sync::OnceLock;
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::Mutex;

const KDS_BASE: &str = "https://kdsintf.amd.com/vcek/v1/Milan";
const CACHE_TTL: Duration = Duration::from_secs(60 * 60);
const MAX_CACHE_ENTRIES: usize = 128;
const MAX_ATTEMPTS: usize = 3;
const MAX_RETRY_WAIT: Duration = Duration::from_secs(60);

struct CachedBytes {
    bytes: Vec<u8>,
    fetched_at: Instant,
}

static CACHE: OnceLock<Mutex<HashMap<String, CachedBytes>>> = OnceLock::new();

type KdsResult<T> = Result<T, Box<dyn Error>>;

pub async fn get_cert_chain() -> KdsResult<AmdChain> {
    let url = format!("{KDS_BASE}/cert_chain");
    get_cached(&url, "certificate chain", |bytes| {
        let certs = X509::stack_from_pem(bytes)?;
        if certs.len() != 2 {
            return Err(format!(
                "AMD KDS returned {} chain certificates, expected 2",
                certs.len()
            )
            .into());
        }
        Ok(AmdChain {
            ask: certs[0].clone(),
            ark: certs[1].clone(),
        })
    })
    .await
}

pub async fn get_vcek(report: &AttestationReport) -> KdsResult<Vcek> {
    let url = format!(
        "{KDS_BASE}/{}?blSPL={:02}&teeSPL={:02}&snpSPL={:02}&ucodeSPL={:02}",
        hex::encode(report.chip_id),
        report.reported_tcb.bootloader,
        report.reported_tcb.tee,
        report.reported_tcb.snp,
        report.reported_tcb.microcode
    );
    get_cached(&url, "VCEK", |bytes| Ok(Vcek(X509::from_der(bytes)?))).await
}

async fn get_cached<T>(
    url: &str,
    description: &str,
    parse: impl Fn(&[u8]) -> KdsResult<T>,
) -> KdsResult<T> {
    // Includes lock wait, response transfer and backoff, not only each request.
    tokio::time::timeout(MAX_RETRY_WAIT, get_cached_inner(url, description, parse))
        .await
        .map_err(|_| "AMD KDS lookup exceeded 60-second total deadline")?
}

async fn get_cached_inner<T>(
    url: &str,
    description: &str,
    parse: impl Fn(&[u8]) -> KdsResult<T>,
) -> KdsResult<T> {
    // Keep the lock during a miss so concurrent attestations for the same VM
    // cannot all make the identical KDS request and trigger another 429.
    let mut cache = CACHE
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .await;
    if let Some(entry) = cache.get(url) {
        if entry.fetched_at.elapsed() < CACHE_TTL {
            return parse(&entry.bytes);
        }
    }

    let client = Client::builder()
        .timeout(Duration::from_secs(15))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let bytes = request_with_retry(&client, url, description).await?;
    let certificate = parse(&bytes)?;
    cache.retain(|_, entry| entry.fetched_at.elapsed() < CACHE_TTL);
    if cache.len() >= MAX_CACHE_ENTRIES {
        if let Some(oldest) = cache
            .iter()
            .min_by_key(|(_, entry)| entry.fetched_at)
            .map(|(key, _)| key.clone())
        {
            cache.remove(&oldest);
        }
    }
    cache.insert(
        url.to_owned(),
        CachedBytes {
            bytes,
            fetched_at: Instant::now(),
        },
    );
    Ok(certificate)
}

async fn request_with_retry(client: &Client, url: &str, description: &str) -> KdsResult<Vec<u8>> {
    let started = Instant::now();
    for attempt in 1..=MAX_ATTEMPTS {
        match client.get(url).send().await {
            Ok(response) if response.status().is_success() => {
                return crate::appraisal::limited_body(response, 64 * 1024).await
            }
            Ok(response) => {
                let status = response.status();
                if attempt == MAX_ATTEMPTS
                    || !(status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error())
                {
                    return Err(format!("AMD KDS {description} request returned HTTP {status} (attempt {attempt}/{MAX_ATTEMPTS})").into());
                }
                let delay = if status == StatusCode::TOO_MANY_REQUESTS {
                    retry_after(response.headers())
                        .unwrap_or(Duration::from_secs(10 * attempt as u64))
                } else {
                    Duration::from_secs(attempt as u64)
                };
                if started.elapsed() + delay > MAX_RETRY_WAIT {
                    return Err(format!("AMD KDS {description} request returned HTTP {status}; retry delay exceeds the 60-second limit").into());
                }
                warn!("AMD KDS {description} request returned HTTP {status}; retrying in {} seconds (attempt {attempt}/{MAX_ATTEMPTS})", delay.as_secs());
                tokio::time::sleep(delay).await;
            }
            Err(error) => {
                if attempt == MAX_ATTEMPTS || !(error.is_connect() || error.is_timeout()) {
                    return Err(error.into());
                }
                let delay = Duration::from_secs(attempt as u64);
                warn!("AMD KDS {description} request failed: {error}; retrying in {} seconds (attempt {attempt}/{MAX_ATTEMPTS})", delay.as_secs());
                tokio::time::sleep(delay).await;
            }
        }
    }
    unreachable!("the final attempt returns")
}

fn retry_after(headers: &HeaderMap) -> Option<Duration> {
    let value = headers.get(RETRY_AFTER)?.to_str().ok()?;
    if let Ok(seconds) = value.parse::<u64>() {
        return Some(Duration::from_secs(seconds));
    }
    let date = httpdate::parse_http_date(value).ok()?;
    Some(date.duration_since(SystemTime::now()).unwrap_or_default())
}

#[cfg(test)]
#[path = "kds_tests.rs"]
mod tests;
