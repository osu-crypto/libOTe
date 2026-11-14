"""Replay the q256 ledger and reject any characteristic-dependent leaf.

Usage: python verify_field_transfer.py /path/to/gen-BAA
The original verifier imports scipy/numpy for discovery helpers even on replay.
The ledger is vendored here; the mathematical field-transfer argument is in
../ChosenBaaDirections.md. Replaying numbers alone does not prove that transfer.
"""
import hashlib
import gzip
import json
import pathlib
import sys

root = pathlib.Path(__file__).resolve().parent
research = pathlib.Path(sys.argv[1]) / 'field-universality/expander-lift'
sys.path.insert(0, str(research))
import small_q_fresh_pair_certificate as certificate

ledger = gzip.decompress((root / 'q256-direct.json.gz').read_bytes())
data = json.loads(ledger)
assert data['kind'] == 'small-q-fresh-pairs-direct-sparse-v2'
assert data['n'] == 2097152 and data['q'] == 256 and data['block_k'] == 8
assert data['source_min'] == 32 and data['steps'] == 16

def direct_only(node):
    if 'children' in node:
        for child in node['children']:
            direct_only(child)
    elif not node.get('empty'):
        assert node['method'] == 'direct', 'Characteristic-dependent leaf cannot transfer.'

direct_only(data['dense'])
result = certificate.verify(data)
assert result['dense_leaves'] == {'direct': 349, 'fresh_pairs': 0}
assert result['minimum_distance_at_least'] == 640135
assert result['failure_upper'] == '2310514520786904766507047478833/1461501637330902918203684832716283019655932542976'
print(json.dumps({
    'construction': 'MDS [16,8,9]; two uniform independent permutations; two recursive scans',
    'alphabet': '256 distinct nonzero elements of any one fixed field admitting the local MDS code',
    'n': result['n'], 'k': result['k'],
    'minimum_distance_at_least': result['minimum_distance_at_least'],
    'failure_upper': result['failure_upper'],
    'failure_log2_upper': result['failure_log2_upper'],
    'direct_leaves': 349, 'characteristic_dependent_leaves': 0,
    'ledger_sha256': hashlib.sha256(ledger).hexdigest(),
}, indent=2))
