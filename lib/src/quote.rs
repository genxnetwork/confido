use az_snp_vtpm::vtpm::{Algorithm, Quote};
use openssl::pkey::{PKey, Public};
use ring::digest::{Context, SHA256};
use std::error::Error;
use tss_esapi::interface_types::algorithm::HashingAlgorithm;
use tss_esapi::structures::{Attest, AttestInfo};
use tss_esapi::traits::UnMarshall;

/// Verify both the quote and the mapping of its bundled PCR values to the
/// signed selection. The dependency checks the concatenated PCR bytes, but
/// does not authenticate the bundled bank labels, lengths, or PCR positions.
pub(crate) fn verify(
    quote: &Quote,
    key: &PKey<Public>,
    nonce: &[u8],
) -> Result<(), Box<dyn Error>> {
    quote.verify(key, nonce)?;
    let attest = Attest::unmarshall(&quote.message())?;
    let AttestInfo::Quote { info } = attest.attested() else {
        return Err("Attestation is not a TPM quote".into());
    };
    let selections = info.pcr_selection().get_selections();
    if selections.is_empty() {
        return Err("Quote has no PCR selection".into());
    }
    let mut seen = Vec::new();
    let mut digest = Context::new(&SHA256);
    for selection in selections {
        let algo = match selection.hashing_algorithm() {
            HashingAlgorithm::Sha1 => Algorithm::Sha1,
            HashingAlgorithm::Sha256 => Algorithm::Sha256,
            _ => return Err("Unsupported quoted PCR algorithm".into()),
        };
        if seen.contains(&algo) {
            return Err("Duplicate quoted PCR bank".into());
        }
        seen.push(algo.clone());
        let bank = quote
            .get_pcr_bank(algo.clone())
            .ok_or("Signed PCR bank is missing")?;
        let slots = selection.selected();
        // Confido addresses bank entries by their PCR number. Require the
        // contiguous selection starting at PCR 0, including at least PCR 10.
        if slots.len() < 11 || slots.len() != bank.pcr_values.len() {
            return Err("Quoted PCR count does not match the signed selection".into());
        }
        for (index, (slot, value)) in slots.iter().zip(&bank.pcr_values).enumerate() {
            if u32::from(*slot) != 1u32 << index || value.len() != algo.length() {
                return Err(
                    "Quoted PCR position or length does not match the signed selection".into(),
                );
            }
            digest.update(value);
        }
    }
    if digest.finish().as_ref() != info.pcr_digest().value() {
        return Err("PCR bank mapping does not match the signed digest".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests;
