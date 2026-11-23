// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
// Multi-bank quote support lives here so the remaining vTPM and SNP APIs can
// come from the original kinvolk/azure-cvm-tooling repository.

use std::error::Error;

use tss_esapi::abstraction::pcr;
use tss_esapi::handles::TpmHandle;
use tss_esapi::interface_types::algorithm::HashingAlgorithm;
use tss_esapi::interface_types::session_handles::AuthSession;
use tss_esapi::structures::pcr_selection_list::PcrSelectionListBuilder;
use tss_esapi::structures::pcr_slot::PcrSlot;
use tss_esapi::structures::{AttestInfo, Data, Signature, SignatureScheme};
use tss_esapi::tcti_ldr::{DeviceConfig, TctiNameConf};
use tss_esapi::traits::Marshall;
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

pub use evidence_protocol::{Algorithm, PcrBank, Quote};
fn tss_algo(a: Algorithm) -> HashingAlgorithm {
    match a {
        Algorithm::Sha1 => HashingAlgorithm::Sha1,
        Algorithm::Sha256 => HashingAlgorithm::Sha256,
    }
}
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
        builder = builder.with_selection(tss_algo(*algorithm), &VTPM_QUOTE_PCR_SLOTS);
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
            .pcr_bank(tss_algo(algo))
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
