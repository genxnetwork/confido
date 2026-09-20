use crate::atls::{IMALogEntry, ModuleLoadOrder};
use crate::pcr::Pcr;
use az_snp_vtpm::vtpm;
use log::{debug, error, info};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use std::env;
use std::net::IpAddr;
use tokio::net::lookup_host;

#[derive(Serialize, Deserialize)]
pub struct TRS {
    pub ima_measurements: Vec<IMALogEntry>,
    #[serde(default)]
    pub pcr10_sha256: Option<String>,
}

#[cfg(test)]
mod tests;

impl TRS {
    pub fn compare_measurements(&self, actual: &[IMALogEntry]) -> Vec<String> {
        let mut mismatches = Vec::new();
        if self.ima_measurements.len() != actual.len() {
            mismatches.push(format!(
                "count trusted={} actual={}",
                self.ima_measurements.len(),
                actual.len()
            ));
        }
        for (index, (trusted, observed)) in
            self.ima_measurements.iter().zip(actual.iter()).enumerate()
        {
            if trusted != observed {
                if trusted.name != observed.name {
                    mismatches.push(format!(
                        "index {} name trusted={} actual={}",
                        index, trusted.name, observed.name
                    ));
                } else {
                    mismatches.push(format!(
                        "index {} module {} digest differs",
                        index, trusted.name
                    ));
                }
            }
        }
        mismatches
    }

    pub async fn get(url: &str, trs_registry: &str) -> Result<TRS, Box<dyn std::error::Error>> {
        let url = Url::parse(url)?;
        let host = url.host_str().ok_or("TRS URL has no host")?;
        let trs_host = if host == "127.0.0.1" || host == "localhost" {
            let public_ip = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()?
                .get("https://api.ipify.org")
                .send()
                .await?
                .error_for_status()?
                .text()
                .await?;
            info!("Resolved {} through ipify to {}", host, public_ip);
            public_ip.trim().parse::<IpAddr>()?.to_string()
        } else if host.parse::<IpAddr>().is_ok() {
            host.to_string()
        } else {
            let port = url.port_or_known_default().ok_or("TRS URL has no port")?;
            let address = lookup_host((host, port))
                .await?
                .next()
                .ok_or("TRS host did not resolve")?;
            info!("Resolved {} to {}", host, address.ip());
            address.ip().to_string()
        };
        info!("Fetching TRS for {}", trs_host);

        // Try to use GitHub token if available, otherwise skip authentication
        let url = format!(
            "https://api.github.com/repos/{}/contents/bb-attest-{}.json",
            trs_registry, trs_host
        )
        .to_string();
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()?;

        let request = client
            .get(&url)
            .header("Accept", "application/vnd.github.raw+json")
            .header("User-Agent", "confido");

        // Only add auth if token file exists
        let request = if let Ok(pat) = std::fs::read_to_string(format!(
            "{}/.confido/trs.token",
            env::var("HOME").unwrap_or_else(|_| ".".to_string())
        )) {
            request.bearer_auth(pat.trim())
        } else {
            request
        };

        let data = request.send().await?.error_for_status()?.text().await?;
        let trs: TRS = serde_json::from_str(&data)?;
        Ok(trs)
    }

    pub fn get_boot_aggregate_hash(&self) -> Result<String, &'static str> {
        let entry = self
            .ima_measurements
            .iter()
            .find(|&measurement| measurement.filename_hint == "boot_aggregate");
        match entry {
            Some(measurement) => {
                info!("TRS ima-template: {}", measurement.ima_template);
                debug!(
                    "TRS boot_aggregate template_hash: {}",
                    measurement.template_hash
                );
                debug!(
                    "TRS boot_aggregate filedata_hash: {}",
                    measurement.filedata_hash
                );
                Ok(measurement.filedata_hash.clone())
            }
            None => Err("No entry found with filename_hint = 'boot_aggregate'"),
        }
    }

    pub fn boot_aggregate_algorithm(&self) -> Result<vtpm::Algorithm, &'static str> {
        let entry = self
            .ima_measurements
            .iter()
            .find(|measurement| measurement.filename_hint == "boot_aggregate")
            .ok_or("No boot aggregate in trusted measurements")?;
        let algo = match entry.filedata_alg.as_str() {
            "sha1" => vtpm::Algorithm::Sha1,
            "sha256" => vtpm::Algorithm::Sha256,
            _ => return Err("Unsupported boot aggregate algorithm"),
        };
        let digest =
            hex::decode(&entry.filedata_hash).map_err(|_| "Invalid boot aggregate hash")?;
        if digest.len() != algo.length() {
            return Err("Invalid boot aggregate hash length");
        }
        Ok(algo)
    }

    fn validate_order(&self, module_load_order: &ModuleLoadOrder) -> Result<(), &'static str> {
        if self.ima_measurements.is_empty() {
            return Err("No IMA records found");
        }
        if self.ima_measurements.len() != module_load_order.order.len() {
            return Err("TRS measurement count does not match the server IMA order");
        }
        for (name, measurement) in module_load_order.order.iter().zip(&self.ima_measurements) {
            if name != &measurement.name {
                return Err("TRS measurement order does not match the server IMA order");
            }
            if measurement.pcr != 10 {
                return Err("TRS measurement does not target PCR 10");
            }
        }
        Ok(())
    }

    pub fn ima_calculate(
        &self,
        module_load_order: &ModuleLoadOrder,
        algo: vtpm::Algorithm,
    ) -> Result<(vtpm::Algorithm, Vec<u8>), &'static str> {
        self.validate_order(module_load_order)?;
        let template = &self.ima_measurements[0].ima_template;
        if template != "ima-ng" && template != "ima-sig" {
            return Err("No known IMA template found in records");
        }
        if self
            .ima_measurements
            .iter()
            .any(|measurement| measurement.ima_template != *template)
        {
            return Err("Mixed templates found in records");
        }

        // Replay the trusted template digests in the selected PCR bank. In
        // particular, ima-sig cannot be reconstructed from a file digest and
        // path alone: its signature field is part of the template digest.
        let mut pcr = Pcr::new(algo.digest());
        for measurement in &self.ima_measurements {
            let digest =
                hex::decode(&measurement.template_hash).map_err(|_| "Invalid IMA template hash")?;
            pcr.extend_digest(&digest)?;
        }
        Ok((algo, pcr.value))
    }

    pub fn verify_pcr10(
        &self,
        module_load_order: &ModuleLoadOrder,
        algo: vtpm::Algorithm,
        actual: &[u8],
    ) -> Result<(), &'static str> {
        self.validate_order(module_load_order)?;
        if actual.len() != algo.length() {
            return Err("Quoted PCR 10 has an invalid length");
        }
        let expected = if let Some(expected) = &self.pcr10_sha256 {
            if algo != vtpm::Algorithm::Sha256 {
                return Err("TRS contains SHA-256 PCR 10 but quote uses another PCR bank");
            }
            let digest =
                hex::decode(expected).map_err(|_| "TRS SHA-256 PCR 10 has an invalid format")?;
            if digest.len() != algo.length() {
                return Err("TRS SHA-256 PCR 10 has an invalid length");
            }
            digest
        } else {
            self.ima_calculate(module_load_order, algo)?.1
        };
        if expected != actual {
            error!(
                "PCR 10 mismatch: expected={}, actual={}",
                hex::encode(expected),
                hex::encode(actual)
            );
            return Err("PCR 10 mismatch");
        }
        info!("PCR 10 matches");
        Ok(())
    }
}
