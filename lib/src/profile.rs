//! Deliberately narrow Milan/VCEK policy. Enrollment is an operator decision.
use az_snp_vtpm::{
    certs::{AmdChain, Vcek},
    report::AttestationReport,
};
use openssl::{
    asn1::Asn1Time,
    stack::Stack,
    x509::{store::X509StoreBuilder, verify::X509VerifyParam, X509StoreContext},
};
use serde::{Deserialize, Serialize};
use std::error::Error;
use x509_parser::prelude::*;

type Result<T> = std::result::Result<T, Box<dyn Error>>;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlatformPolicy {
    pub product: String,
    pub ark_sha256: String,
    /// bootloader, TEE, SNP firmware, microcode; component-wise floor.
    pub minimum_tcb: [u8; 4],
    pub launch_measurement: String,
}

pub fn endorsements(chain: &AmdChain, vcek: &Vcek, policy: &PlatformPolicy, at: i64) -> Result<()> {
    if crate::appraisal::sha256(&chain.ark.to_der()?) != policy.ark_sha256 {
        return Err("AMD root certificate does not match the enrolled trust anchor".into());
    }
    let now = Asn1Time::from_unix(at)?;
    for cert in [&chain.ark, &chain.ask, &vcek.0] {
        if cert.not_before() > now || cert.not_after() < now {
            return Err("AMD endorsement is outside its validity interval".into());
        }
    }
    chain.validate()?;
    vcek.validate(chain)?;
    let mut store = X509StoreBuilder::new()?;
    store.add_cert(chain.ark.clone())?;
    let mut params = X509VerifyParam::new()?;
    params.set_time(at as _);
    store.set_param(&params)?;
    let mut intermediate = Stack::new()?;
    intermediate.push(chain.ask.clone())?;
    let mut context = X509StoreContext::new()?;
    if !context.init(&store.build(), &vcek.0, &intermediate, |ctx| {
        ctx.verify_cert()
    })? {
        return Err(format!("AMD certificate chain validation: {}", context.error()).into());
    }
    Ok(())
}

// AMD SPLs are unsigned octets in canonical DER INTEGERs, including the sign
// padding for values >= 128. Accept no trailing or non-minimal encoding.
fn spl(bytes: &[u8]) -> Result<u8> {
    match bytes {
        [2, 1, n @ 0..=127] => Ok(*n),
        [2, 2, 0, n @ 128..=255] => Ok(*n),
        _ => Err("Invalid VCEK SPL encoding".into()),
    }
}

pub fn correspondence(
    report: &AttestationReport,
    vcek: &Vcek,
    policy: &PlatformPolicy,
) -> Result<()> {
    let der = vcek.0.to_der()?;
    let (rest, cert) = parse_x509_certificate(&der).map_err(|_| "Invalid VCEK DER")?;
    if !rest.is_empty() {
        return Err("Trailing VCEK bytes".into());
    }
    let value = |suffix: &str| -> Result<&[u8]> {
        let oid = format!("1.3.6.1.4.1.3704.1.{suffix}");
        let matches: Vec<_> = cert
            .extensions()
            .iter()
            .filter(|e| e.oid.to_id_string() == oid)
            .collect();
        if matches.len() != 1 {
            return Err(format!("Missing or duplicated AMD extension {oid}").into());
        }
        Ok(matches[0].value)
    };
    if spl(value("1")?)? != 0 {
        return Err("Unsupported VCEK structure version".into());
    }
    let product = value("2")?;
    if product.len() < 2
        || product[0] != 0x16
        || product[1] as usize != product.len() - 2
        || !std::str::from_utf8(&product[2..])?.starts_with(&format!("{}-", policy.product))
    {
        return Err("VCEK product does not match the enrolled family".into());
    }
    if value("4")? != report.chip_id {
        return Err("VCEK chip identifier differs from SNP report".into());
    }
    for (oid, expected) in [
        ("3.1", report.reported_tcb.bootloader),
        ("3.2", report.reported_tcb.tee),
        ("3.3", report.reported_tcb.snp),
        ("3.8", report.reported_tcb.microcode),
        ("3.4", 0),
        ("3.5", 0),
        ("3.6", 0),
        ("3.7", 0),
    ] {
        if spl(value(oid)?)? != expected {
            return Err(format!("VCEK TCB extension {oid} differs from SNP report").into());
        }
    }
    Ok(())
}

pub fn guest_policy(report: &AttestationReport, policy: &PlatformPolicy) -> Result<()> {
    if report.vmpl != 0 {
        return Err("Profile requires VMPL 0".into());
    }
    if report.policy.debug_allowed() != 0 {
        return Err("Guest debug policy is enabled".into());
    }
    if report.policy.migrate_ma_allowed() != 0 {
        return Err("Guest migration-agent policy is enabled".into());
    }
    let actual = [
        report.reported_tcb.bootloader,
        report.reported_tcb.tee,
        report.reported_tcb.snp,
        report.reported_tcb.microcode,
    ];
    if actual.iter().zip(policy.minimum_tcb).any(|(a, b)| *a < b) {
        return Err("Reported TCB is below the enrolled minimum".into());
    }
    if hex::encode(report.measurement) != policy.launch_measurement {
        return Err("SNP launch measurement differs from enrolled policy".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn canonical_spl_encodings_only() {
        assert_eq!(spl(&[2, 1, 24]).unwrap(), 24);
        assert_eq!(spl(&[2, 2, 0, 219]).unwrap(), 219);
        for b in [&[2, 1, 219][..], &[2, 2, 0, 24], &[2, 1, 1, 0], &[2, 0]] {
            assert!(spl(b).is_err());
        }
    }
    #[test]
    fn rejects_debug_migration_vmpl_measurement_and_tcb() {
        let mut r = AttestationReport::default();
        let p = PlatformPolicy {
            product: "Milan".into(),
            ark_sha256: "00".repeat(32),
            minimum_tcb: [0; 4],
            launch_measurement: "00".repeat(48),
        };
        guest_policy(&r, &p).unwrap();
        r.policy.set_debug_allowed(1);
        assert!(guest_policy(&r, &p).is_err());
        r.policy.set_debug_allowed(0);
        r.policy.set_migrate_ma_allowed(1);
        assert!(guest_policy(&r, &p).is_err());
        r.policy.set_migrate_ma_allowed(0);
        r.vmpl = 1;
        assert!(guest_policy(&r, &p).is_err());
        r.vmpl = 0;
        r.measurement[0] = 1;
        assert!(guest_policy(&r, &p).is_err());
        r.measurement[0] = 0;
        let mut p = p;
        p.minimum_tcb[2] = 1;
        assert!(guest_policy(&r, &p).is_err());
    }
}
