"""Build the AVX-512 Fp comparison against an unchanged gen-BAA reference.

python build_fp_comparison.py --reference /path/to/gen-BAA --build-dir /tmp/fp-comparison
Requires an AVX-512/BMI2 x86 host, GCC/Clang, and Boost multiprecision headers.
Does not run a benchmark. Run the resulting executable sequentially.
"""
import argparse
import hashlib
import json
import pathlib
import shutil
import subprocess

p = argparse.ArgumentParser()
p.add_argument('--reference', required=True, type=pathlib.Path)
p.add_argument('--build-dir', required=True, type=pathlib.Path)
p.add_argument('--cxx', default='c++')
args = p.parse_args()
source = args.reference / 'field-universality/expander-lift/bench'
build = args.build_dir.resolve()
reference = build / 'reference'
reference.mkdir(parents=True, exist_ok=True)
manifest = {}
for pattern in ('*.h', '*.cpp'):
    for path in source.glob(pattern):
        shutil.copy2(path, reference / path.name)
        manifest[path.name] = hashlib.sha256(path.read_bytes()).hexdigest()
for stem, include in [('certified_convolution_bench', 'certified_convolution_shared'),
                      ('width_one_small_q_bench', 'width_one_small_q_shared')]:
    text = (reference / (stem + '.cpp')).read_text()
    (reference / (include + '.inc')).write_text(text[:text.index('int main(')])
driver = pathlib.Path(__file__).with_name('FpBaaDirections.cpp')
manifest[driver.name] = hashlib.sha256(driver.read_bytes()).hexdigest()
(build / 'source-sha256.json').write_text(json.dumps(manifest, indent=2) + '\n')
subprocess.run([args.cxx, '-O3', '-march=native', '-DNDEBUG', '-std=c++20',
                '-I' + str(reference), str(driver), '-o', str(build / 'fp_baa_directions')], check=True)
