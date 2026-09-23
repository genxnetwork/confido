// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
// Multi-bank quote support lives here so the remaining vTPM and SNP APIs can
// come from the original kinvolk/azure-cvm-tooling repository.

use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Public};
use openssl::sign::Verifier;
use ring::digest::{Context as DigestContext, SHA256};
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt;
use tss_esapi::abstraction::pcr;
use tss_esapi::handles::TpmHandle;
use tss_esapi::interface_types::algorithm::HashingAlgorithm;
use tss_esapi::interface_types::session_handles::AuthSession;
use tss_esapi::structures::pcr_selection_list::PcrSelectionListBuilder;
use tss_esapi::structures::pcr_slot::PcrSlot;
use tss_esapi::structures::{Attest, AttestInfo, Data, Signature, SignatureScheme};
use tss_esapi::tcti_ldr::{DeviceConfig, TctiNameConf};
use tss_esapi::traits::{Marshall, UnMarshall};
use tss_esapi::Context;

pub use az_snp_vtpm::vtpm::get_report;

const VTPM_AK_HANDLE: u32 = 0x81000003;
const VTPM_QUOTE_PCR_SLOTS: [PcrSlot; 24] = [
    PcrSlot::Slot0,
    PcrSlot::Slot1,
    PcrSlot::Slot2,
    PcrSlot::Slot3,
    PcrSlot::Slot4,
    PcrSlot::Slot5,
    PcrSlot::Slot6,
    PcrSlot::Slot7,
    PcrSlot::Slot8,
    PcrSlot::Slot9,
    PcrSlot::Slot10,
    PcrSlot::Slot11,
    PcrSlot::Slot12,
    PcrSlot::Slot13,
    PcrSlot::Slot14,
    PcrSlot::Slot15,
    PcrSlot::Slot16,
    PcrSlot::Slot17,
    PcrSlot::Slot18,
    PcrSlot::Slot19,
    PcrSlot::Slot20,
    PcrSlot::Slot21,
    PcrSlot::Slot22,
    PcrSlot::Slot23,
];

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    Sha1 = 0,
    Sha256 = 1,
}

impl Algorithm {
    pub fn length(&self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha256 => 32,
        }
    }

    pub fn to_str(&self) -> &'static str {
        match self {
            Self::Sha1 => "sha1",
            Self::Sha256 => "sha256",
        }
    }

    fn tss_esapi(&self) -> HashingAlgorithm {
        match self {
            Self::Sha1 => HashingAlgorithm::Sha1,
            Self::Sha256 => HashingAlgorithm::Sha256,
        }
    }

    pub fn digest(&self) -> &'static ring::digest::Algorithm {
        match self {
            Self::Sha1 => &ring::digest::SHA1_FOR_LEGACY_USE_ONLY,
            Self::Sha256 => &ring::digest::SHA256,
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct PcrBank {
    pub algo: Algorithm,
    pub pcr_values: Vec<Vec<u8>>,
}

impl PcrBank {
    pub fn get(&self, index: usize) -> Option<&Vec<u8>> {
        self.pcr_values.get(index)
    }
}

impl fmt::Debug for PcrBank {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PcrBank")
            .field("algo", &self.algo)
            .field(
                "pcr_values",
                &self.pcr_values.iter().map(hex::encode).collect::<Vec<_>>(),
            )
            .finish()
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Quote {
    signature: Vec<u8>,
    message: Vec<u8>,
    pcr_banks: Vec<PcrBank>,
}

impl fmt::Debug for Quote {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Quote")
            .field("signature", &hex::encode(&self.signature))
            .field("message", &hex::encode(&self.message))
            .field("pcr_banks", &self.pcr_banks)
            .finish()
    }
}

impl Quote {
    pub(crate) fn bank_count(&self) -> usize {
        self.pcr_banks.len()
    }

    pub fn get_pcr_bank(&self, algo: Algorithm) -> Option<&PcrBank> {
        self.pcr_banks.iter().find(|bank| bank.algo == algo)
    }

    pub fn message(&self) -> Vec<u8> {
        self.message.clone()
    }

    pub fn nonce(&self) -> Result<Vec<u8>, Box<dyn Error>> {
        Ok(Attest::unmarshall(&self.message)?.extra_data().to_vec())
    }

    /// Verify the AK signature, nonce, and digest over the bundled PCR values.
    /// The caller also checks the bank labels and positions against the signed selection.
    pub fn verify(&self, key: &PKey<Public>, nonce: &[u8]) -> Result<(), Box<dyn Error>> {
        let mut verifier = Verifier::new(MessageDigest::sha256(), key)?;
        verifier.update(&self.message)?;
        if !verifier.verify(&self.signature)? {
            return Err("Quote signature mismatch".into());
        }
        if self.nonce()? != nonce {
            return Err("Quote nonce mismatch".into());
        }
        let attest = Attest::unmarshall(&self.message)?;
        let AttestInfo::Quote { info } = attest.attested() else {
            return Err("Attestation is not a TPM quote".into());
        };
        let mut digest = DigestContext::new(&SHA256);
        for bank in &self.pcr_banks {
            for value in &bank.pcr_values {
                digest.update(value);
            }
        }
        if digest.finish().as_ref() != info.pcr_digest().value() {
            return Err("Quote PCR digest mismatch".into());
        }
        Ok(())
    }
}

/// Get a TPM quote over the requested PCR banks, preserving the existing wire format.
pub fn get_quote(data: &[u8], mut algorithms: Vec<Algorithm>) -> Result<Quote, Box<dyn Error>> {
    if data.len() > Data::MAX_SIZE {
        return Err("Quote nonce is too large".into());
    }
    if algorithms.is_empty() || algorithms.len() > 2 {
        return Err("Expected one or two PCR banks".into());
    }
    algorithms.sort_by_key(|algo| match algo {
        Algorithm::Sha1 => 0,
        Algorithm::Sha256 => 1,
    });
    if algorithms.len() == 2 && algorithms[0] == algorithms[1] {
        return Err("Duplicate PCR bank".into());
    }

    let conf = TctiNameConf::Device(DeviceConfig::default());
    let mut context = Context::new(conf)?;
    let handle: TpmHandle = VTPM_AK_HANDLE.try_into()?;
    let key_handle = context.tr_from_tpm_public(handle)?;
    let quote_data: Data = data.try_into()?;
    let mut builder = PcrSelectionListBuilder::new();
    for algorithm in &algorithms {
        builder = builder.with_selection(algorithm.tss_esapi(), &VTPM_QUOTE_PCR_SLOTS);
    }
    let selections = builder.build()?;
    context.set_sessions((Some(AuthSession::Password), None, None));
    let (attest, signature) = context.quote(
        key_handle.into(),
        quote_data,
        SignatureScheme::Null,
        selections.clone(),
    )?;
    let AttestInfo::Quote { .. } = attest.attested() else {
        return Err("TPM returned a non-quote attestation".into());
    };
    let Signature::RsaSsa(rsa_signature) = signature else {
        return Err("TPM returned an unsupported signature".into());
    };
    let signature = rsa_signature.signature().to_vec();
    let message = attest.marshall()?;

    context.clear_sessions();
    let pcr_data = pcr::read_all(&mut context, selections)?;
    let mut pcr_banks = Vec::new();
    for algo in algorithms {
        let bank = pcr_data
            .pcr_bank(algo.tss_esapi())
            .ok_or("Requested PCR bank is missing")?;
        let pcr_values = bank
            .into_iter()
            .map(|(_, value)| value.value().to_vec())
            .collect();
        pcr_banks.push(PcrBank { algo, pcr_values });
    }
    Ok(Quote {
        signature,
        message,
        pcr_banks,
    })
}
