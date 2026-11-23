#!/usr/bin/env python3
"""Hardware-evidence replay mutations; no live authorization or network traffic.
Run against a privately retained real bundle, not a synthetic SNP signature.
"""
import argparse
import copy
import json
import hashlib
import math
from pathlib import Path
import time
import confido_verifier
from archive_inputs import migrate, arguments, decode, encode


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("bundle", type=Path)
    parser.add_argument("policy", type=Path)
    parser.add_argument("--at", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--samples", type=int, default=30)
    args = parser.parse_args()
    bundle = migrate(json.loads(args.bundle.read_text()), args.at)
    config = json.loads(args.policy.read_text())
    records = []

    def input_bytes(archive, name):
        return decode(archive['inputs'][name])

    def set_input(archive, name, value):
        archive['inputs'][name] = encode(value)

    def change_json_input(archive, name, edit):
        value = json.loads(input_bytes(archive, name))
        edit(value)
        set_input(archive, name, json.dumps(value, separators=(',', ':')).encode())

    def change_report(archive, edit):
        change_json_input(archive, 'report', edit)

    pipeline = ['endorsements', 'snp_signature', 'vcek_correspondence', 'platform_policy', 'hcl_key',
                'quote_signature', 'quote_binding', 'quoted_pcrs', 'reference', 'ima_reference', 'boot_aggregate', 'pcr10']
    stages = {'challenge_replay': 'quote_binding', 'reference_content': 'reference',
              'changed_snp_signature': 'snp_signature', 'changed_vcek_chip': 'snp_signature',
              'ca_certificate_after_signed_report': 'certificate', 'snp_signature_before_ca_certificate': 'snp_signature',
              'quote_signature_before_ca_certificate': 'quote_signature', 'changed_quote_signature': 'quote_signature',
              'changed_pcr': 'quoted_pcrs', 'changed_ima': 'quote_binding',
              'reference_ima_content': 'ima_reference', 'reference_ima_order': 'ima_reference',
              'reference_pcr10': 'pcr10', 'unsigned_module_order': 'pcr10'}

    def run(name, mutate, expected):
        b, c = copy.deepcopy(bundle), copy.deepcopy(config)
        mutate(b, c)
        try:
            r = confido_verifier.verify(*arguments(b, json.dumps(c).encode()))
        except ValueError:
            if expected not in ("invalid_nonce", "input_too_large"): raise
            records.append({"id": name, "expected": expected, "observed": "api_input_error"})
            return
        assert r["reason"] == expected, (name, r["reason"], r["checks"][-1])
        assert "application_admitted" not in r and r["scope"] == "evidence_only"
        passed = [x['stage'] for x in r['checks'] if x['status'] == 'passed']
        assert passed == pipeline[:len(passed)], (name, passed)
        if name in stages:
            assert r['checks'][-1]['stage'] == stages[name], (name, r['checks'][-1])
        if r['status'] == 'verified':
            assert passed == pipeline and r['coverage']['ima_entries'] > 0
        else:
            assert r['coverage']['ima_entries'] == 0
        bound = 'quote_binding' in passed
        assert all(value is bound for value in r['bindings'].values())
        assert ('certificate_sha256' in r['verified_artifacts']) is bound
        assert ('vtpm_key_sha256' in r['verified_artifacts']) is ('hcl_key' in passed)
        records.append({"id": name, "expected": expected, "observed": r["reason"],
                        "last_stage": r['checks'][-1]['stage'],
                        "completed_stages": [x["stage"] for x in r["checks"] if x["status"] == "passed"]})

    run("original_hardware_evidence", lambda b,c: None, "reference_match")
    run("challenge_replay", lambda b,c: b['context'].update(expected_nonce_base64=encode(bytes(32))), "quote_binding_invalid")
    run("invalid_nonce", lambda b,c: b['context'].update(expected_nonce_base64="bad!"), "invalid_nonce")
    run("reference_content", lambda b,c: set_input(b, 'reference', input_bytes(b, 'reference')+b' '), "reference_digest_mismatch")
    # A saved result is untrusted replay metadata, including for migrated v1 inputs.
    run("stored_result_substitution", lambda b,c: b.update(verification={'reference': {'commit': "0"*40}, 'status': 'verified'}), "reference_match")
    run("origin_substitution", lambda b,c: b.update(origin="https://other.invalid"), "reference_match")
    run("unsupported_wire", lambda b,c: change_report(b, lambda r: r.update(wireVersion=2)), "unsupported_wire_version")
    run("untrusted_root", lambda b,c: c["platform"].update(ark_sha256="0"*64), "endorsement_chain_invalid")
    run("launch_policy", lambda b,c: c["platform"].update(launch_measurement="0"*96), "platform_policy_mismatch")
    run("minimum_tcb", lambda b,c: c["platform"].update(minimum_tcb=[255]*4), "platform_policy_mismatch")
    run("malformed_hcl", lambda b,c: change_report(b, lambda r: r['evidence'].update(report=[0])), "malformed_hcl")
    def flip_snp_byte(archive, offset):
        def edit(report):
            raw = report['evidence']['report']
            raw[offset] ^= 1
        change_report(archive, edit)
    run("changed_snp_signature", lambda b,c: flip_snp_byte(b, 32+672), "snp_signature_invalid")
    run("changed_vcek_chip", lambda b,c: flip_snp_byte(b, 32+416), "snp_signature_invalid")
    def substitute_ca_certificate(b,c):
        first = input_bytes(b, 'amd_chain').split(b"-----END CERTIFICATE-----", 1)[0] + b"-----END CERTIFICATE-----\n"
        change_report(b, lambda r: r.update(certificate=list(first)))
    run("ca_certificate_after_signed_report", substitute_ca_certificate, "ca_certificate_unsupported")
    def invalid_signature_and_ca_certificate(b,c):
        substitute_ca_certificate(b,c)
        flip_snp_byte(b, 32+672)
    run("snp_signature_before_ca_certificate", invalid_signature_and_ca_certificate, "snp_signature_invalid")
    def bad_quote_and_ca(b,c):
        substitute_ca_certificate(b,c)
        change_report(b, lambda r: r['evidence']['quote']['signature'].__setitem__(0, r['evidence']['quote']['signature'][0]^1))
    run('quote_signature_before_ca_certificate', bad_quote_and_ca, 'quote_binding_invalid')
    def reference_change(b,c,edit):
        reference = json.loads(input_bytes(b, 'reference')); edit(reference)
        raw = json.dumps(reference, separators=(',', ':')).encode()
        set_input(b, 'reference', raw)
        c['reference']['sha256'] = hashlib.sha256(raw).hexdigest()
    run('reference_ima_content', lambda b,c: reference_change(b,c,lambda r: r['ima_measurements'][1].update(filedata_hash='0'*64)), 'measurement_mismatch')
    run('reference_ima_order', lambda b,c: reference_change(b,c,lambda r: r['ima_measurements'].reverse()), 'measurement_mismatch')
    run('reference_pcr10', lambda b,c: reference_change(b,c,lambda r: r.update(pcr10_sha256='0'*64)), 'measurement_mismatch')
    run('unsigned_module_order', lambda b,c: change_report(b, lambda r: r['evidence']['module_load_order']['order'].reverse()), 'measurement_mismatch')
    def substitute_hcl_key(b,c):
        report=json.loads(input_bytes(b, 'report'))
        raw=bytearray(report["evidence"]["report"])
        size=int.from_bytes(raw[1232:1236],"little")
        metadata=json.loads(raw[1236:1236+size])
        key=next(k for k in metadata["keys"] if k.get("kid")=="HCLAkPub")
        offset=raw.find(key["n"].encode(),1236)+10
        raw[offset]=ord("A") if raw[offset]!=ord("A") else ord("B")
        report["evidence"]["report"]=list(raw)
        set_input(b, 'report', json.dumps(report, separators=(',', ':')).encode())
    run("substituted_hcl_attestation_key", substitute_hcl_key,"hcl_binding_invalid")
    run("changed_quote_signature", lambda b,c: change_report(b, lambda r: r['evidence']['quote']['signature'].__setitem__(0, r['evidence']['quote']['signature'][0]^1)), "quote_binding_invalid")
    run("changed_pcr", lambda b,c: change_report(b, lambda r: r['evidence']['quote']['pcr_banks'][0]['pcr_values'][10].__setitem__(0, r['evidence']['quote']['pcr_banks'][0]['pcr_values'][10][0]^1)), "quote_binding_invalid")
    run("changed_ima", lambda b,c: change_report(b, lambda r: r['evidence']['ima_measurements'][0].update(filedata_hash="0"*64)), "quote_binding_invalid")
    run("oversized_reference", lambda b,c: set_input(b, 'reference', b' '*(4*1024*1024+1)), "input_too_large")
    for label, at in [("endorsement_not_yet_valid",0),("endorsement_expired",7258118400)]:
        r=confido_verifier.verify(*arguments(bundle, json.dumps(config).encode(), at=at))
        assert r["reason"]=="endorsement_chain_invalid",(label,r)
        assert "application_admitted" not in r
        records.append({"id":label,"expected":"endorsement_chain_invalid","observed":r["reason"]})
    times=[]
    for _ in range(args.samples):
        started=time.perf_counter()
        r=confido_verifier.verify(*arguments(bundle, json.dumps(config).encode()))
        assert r["status"]=="verified"
        times.append((time.perf_counter()-started)*1000)
    p95=sorted(times)[math.ceil(len(times)*.95)-1]
    output={"mode":"hardware_evidence_replay","runtime":confido_verifier.build_info(),"evaluation_time":args.at,"tests":records,"samples":len(times),
            "local_appraisal_ms":times,"p95_ms":p95,"target_ms":3000,"target_met":p95<=3000,
            "timing_scope":"All inputs already local; includes caller serialization and Rust checks; excludes collection and network"}
    args.output.write_text(json.dumps(output,indent=2)+"\n")
    print(f'{len(records)} replay cases passed; {len(times)} local appraisals, p95={p95:.2f} ms')


if __name__ == "__main__":
    main()
