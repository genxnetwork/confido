"""Legacy archive compatibility belongs to callers, not the verifier."""
import base64
import json

def encode(data): return base64.b64encode(data).decode('ascii')
def decode(data): return base64.b64decode(data, validate=True)
def migrate(archive, at):
    if archive['schema_version'] == 2:
        return dict(archive, mode='historical_replay', context=dict(archive['context'], evaluation_unix_seconds=at))
    if archive['schema_version'] != 1: raise ValueError('Unsupported archive')
    return {'schema_version': 2, 'mode': 'historical_replay', 'inputs': {
        'report': encode(json.dumps(archive['report'], separators=(',', ':')).encode()),
        'amd_chain': encode(archive['amd_chain_pem'].encode()), 'vcek': encode(bytes(archive['vcek_der'])),
        'reference': encode(archive['reference_json'].encode())},
        'context': {'expected_nonce_base64': archive['nonce'], 'evaluation_unix_seconds': at}}
def arguments(archive, policy, nonce=None, at=None):
    i=archive['inputs']; c=archive['context']
    return [*(decode(i[k]) for k in ('report','amd_chain','vcek','reference')), policy,
            decode(c['expected_nonce_base64']) if nonce is None else nonce,
            c['evaluation_unix_seconds'] if at is None else at]
