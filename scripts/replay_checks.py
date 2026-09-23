#!/usr/bin/env python3
"""Hardware-evidence replay mutations; no live authorization or network traffic.
Run against a privately retained real bundle, not a synthetic SNP signature.
"""
import argparse
import copy
import json
import math
from pathlib import Path
import time
import confido


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("bundle", type=Path)
    parser.add_argument("policy", type=Path)
    parser.add_argument("--at", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--samples", type=int, default=30)
    args = parser.parse_args()
    bundle = json.loads(args.bundle.read_text())
    config = json.loads(args.policy.read_text())
    records = []

    def run(name, mutate, expected):
        b, c = copy.deepcopy(bundle), copy.deepcopy(config)
        mutate(b, c)
        r = json.loads(confido.appraise_offline_py(json.dumps(b), json.dumps(c), args.at))
        assert r["reason"] == expected, (name, r["reason"], r["checks"][-1])
        assert not r["application_admitted"], "Replay must never authorize live requests"
        records.append({"id": name, "expected": expected, "observed": r["reason"],
                        "completed_stages": [x["stage"] for x in r["checks"] if x["status"] == "passed"]})

    run("original_hardware_evidence", lambda b,c: None, "reference_match")
    run("challenge_replay", lambda b,c: b.update(nonce="AA"*21+"A="), "quote_binding_invalid")
    run("invalid_nonce", lambda b,c: b.update(nonce="bad!"), "invalid_nonce")
    run("reference_content", lambda b,c: b.update(reference_json=b["reference_json"]+" "), "reference_digest_mismatch")
    run("reference_identity", lambda b,c: b["reference"].update(commit="0"*40), "reference_identity_mismatch")
    run("origin_substitution", lambda b,c: b.update(origin="https://other.invalid"), "reference_identity_mismatch")
    run("service_identity", lambda b,c: b["service_info"].update(id="other"), "unsupported_discovery")
    run("unsupported_wire", lambda b,c: b["report"].update(wireVersion=2), "unsupported_wire_version")
    run("untrusted_root", lambda b,c: c["platform"].update(ark_sha256="0"*64), "endorsement_chain_invalid")
    run("launch_policy", lambda b,c: c["platform"].update(launch_measurement="0"*96), "platform_policy_mismatch")
    run("minimum_tcb", lambda b,c: c["platform"].update(minimum_tcb=[255]*4), "platform_policy_mismatch")
    run("malformed_hcl", lambda b,c: b["report"]["evidence"].update(report=[0]), "malformed_hcl")
    run("changed_snp_signature", lambda b,c: b["report"]["evidence"]["report"].__setitem__(32+672, b["report"]["evidence"]["report"][32+672]^1), "snp_signature_invalid")
    run("changed_vcek_chip", lambda b,c: b["report"]["evidence"]["report"].__setitem__(32+416, b["report"]["evidence"]["report"][32+416]^1), "endorsement_report_mismatch")
    def substitute_hcl_key(b,c):
        raw=bytearray(b["report"]["evidence"]["report"])
        size=int.from_bytes(raw[1232:1236],"little")
        metadata=json.loads(raw[1236:1236+size])
        key=next(k for k in metadata["keys"] if k.get("kid")=="HCLAkPub")
        offset=raw.find(key["n"].encode(),1236)+10
        raw[offset]=ord("A") if raw[offset]!=ord("A") else ord("B")
        b["report"]["evidence"]["report"]=list(raw)
    run("substituted_hcl_attestation_key", substitute_hcl_key,"hcl_binding_invalid")
    run("changed_quote_signature", lambda b,c: b["report"]["evidence"]["quote"]["signature"].__setitem__(0, b["report"]["evidence"]["quote"]["signature"][0]^1), "quote_binding_invalid")
    run("changed_pcr", lambda b,c: b["report"]["evidence"]["quote"]["pcr_banks"][0]["pcr_values"][10].__setitem__(0, b["report"]["evidence"]["quote"]["pcr_banks"][0]["pcr_values"][10][0]^1), "quote_binding_invalid")
    run("changed_ima", lambda b,c: b["report"]["evidence"]["ima_measurements"][0].update(filedata_hash="0"*64), "quote_binding_invalid")
    run("oversized_reference", lambda b,c: b.update(reference_json=" "*(4*1024*1024+1)), "input_too_large")
    times=[]
    for _ in range(args.samples):
        r=json.loads(confido.appraise_offline_py(json.dumps(bundle),json.dumps(config),args.at))
        assert r["status"]=="passed"
        times.append(r["timings_ms"]["local_appraisal"])
    p95=sorted(times)[math.ceil(len(times)*.95)-1]
    output={"mode":"hardware_evidence_replay","evaluation_time":args.at,"tests":records,"samples":len(times),
            "local_appraisal_ms":times,"p95_ms":p95,"target_ms":3000,"target_met":p95<=3000,
            "timing_scope":"All inputs already local; excludes Python JSON parse, collection and network; Rust input parsing and checks included"}
    args.output.write_text(json.dumps(output,indent=2)+"\n")
    print(f'{len(records)} replay cases passed; {len(times)} local appraisals, p95={p95:.2f} ms')


if __name__ == "__main__":
    main()
