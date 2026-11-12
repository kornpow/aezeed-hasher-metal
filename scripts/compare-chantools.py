#!/usr/bin/env python3
"""Check seed restoration with chantools and record comparable throughput.

Run after cargo build --release. No existing wallet or seed is accessed.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
import platform
import re
import signal
import statistics
import subprocess
import tempfile
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]


def root_key(entropy, coin):
    """Independent BIP32 master serialization using Python's standard library."""
    digest = hmac.digest(b'Bitcoin seed', entropy, 'sha512')
    version = bytes.fromhex('0488ade4' if coin == 0 else '04358394')
    payload = version + bytes(9) + digest[32:] + b'\0' + digest[:32]
    check = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    value = int.from_bytes(payload + check, 'big')
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    encoded = ''
    while value:
        value, digit = divmod(value, 58)
        encoded = alphabet[digit] + encoded
    return encoded


def fixed_vectors(binary, reference, directory, version):
    seeds = [bytes(16), bytes([255])*16, bytes(range(16))]
    seeds += [hashlib.sha256(f'chantools-vector-{i}'.encode()).digest()[:16] for i in range(5)]
    rows = []
    for coin, network, flag in [(0, 'mainnet', []), (1, 'testnet', ['--testnet'])]:
        for entropy in seeds:
            output = subprocess.check_output(
                [reference, '--nologfile', '--resultsdir', directory, *flag,
                 'derivekey', '--rootkey', root_key(entropy, coin), '--identity', '--neuter'],
                text=True, stderr=subprocess.PIPE, timeout=30)
            match = re.search(r'Public key:\s*([0-9a-f]{66})', output)
            if not match:
                raise RuntimeError('chantools did not report a node identity public key')
            expected = match.group(1)
            actual = subprocess.check_output(
                [binary, 'derive', '--entropy', entropy.hex(), '--network', network],
                text=True, timeout=30).strip()
            if actual != expected:
                raise RuntimeError(f'Fixed entropy mismatch: {entropy.hex()}, {network}')
            rows.append(f'{entropy.hex()}\t{coin}\t{expected}')
    path = ROOT / 'data/identity-vectors.tsv'
    path.write_text(f'# Verified against {version}\n# entropy\tcoin_type\tnode_pubkey\n' + '\n'.join(rows) + '\n')
    return len(rows)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--chantools',required=True)
    parser.add_argument('--seconds',type=int,default=5)
    parser.add_argument('--repeats',type=int,default=3)
    parser.add_argument('--metal',action='store_true')
    parser.add_argument('--tune',action='store_true')
    parser.add_argument('--batches',type=int,nargs='+',default=[1024,4096,8192],help='batch sizes for --tune')
    parser.add_argument('--windows',type=int,nargs='+',choices=[2,4,8],default=[2,4,8],help='curve windows for --tune')
    parser.add_argument('--threadgroups',type=int,nargs='+',default=[32,64,128],help='threadgroup sizes for --tune')
    parser.add_argument('--output',type=Path,default=ROOT/'validation/benchmarks.json')
    args=parser.parse_args()
    if args.seconds<1 or args.repeats<1:
        parser.error('--seconds and --repeats must be positive')
    if any(b<1 or b>1048576 for b in args.batches) or any(t<1 for t in args.threadgroups):
        parser.error('batch sizes must be 1..1048576 and threadgroup sizes must be positive')
    binary=str(ROOT/'target/release/aezeed-hasher-metal')
    reference=str(Path(args.chantools).resolve())
    results={'reference':subprocess.check_output([reference,'--version'],text=True).strip(),
             'timestamp_utc':datetime.now(timezone.utc).isoformat(),
             'platform':platform.platform(),
             'rust_binary_sha256':hashlib.sha256(Path(binary).read_bytes()).hexdigest(),
             'reference_binary_sha256':hashlib.sha256(Path(reference).read_bytes()).hexdigest(),
             'workload':'Random entropy generation, full BIP32 identity derivation, and public key prefix comparison',
             'seconds_per_sample':args.seconds,'repeats':args.repeats,
             'restore_checks':[],'benchmarks':[]}
    with tempfile.TemporaryDirectory() as tmp:
        results['fixed_entropy_vectors_checked']=fixed_vectors(binary,reference,tmp,results['reference'])
        # Only freshly generated disposable seeds are passed to the reference.
        backends=['cpu','metal'] if args.metal or args.tune else ['cpu']
        for backend,network,flag in [(b,n,f) for b in backends for n,f in [('mainnet',[]),('testnet',['--testnet'])]]:
            generated=subprocess.check_output([binary,'vanitygen','--prefix','02ab','--backend',backend,'--network',network,'--batch-size','256'],text=True,stderr=subprocess.PIPE,timeout=120)
            pubkey=re.search(r'Public key: (\w+)',generated).group(1)
            seed=re.search(r'Aezeed: (.*)',generated).group(1)
            env=os.environ.copy();env.update(AEZEED_MNEMONIC=seed,AEZEED_PASSPHRASE='-')
            restored=subprocess.check_output([reference,'--nologfile','--resultsdir',tmp,*flag,'derivekey','--identity','--neuter'],env=env,text=True,stderr=subprocess.PIPE,timeout=30)
            assert pubkey in restored,'chantools restored a different identity'
            results['restore_checks'].append({'backend':backend,'network':network,'passed':True})
        configurations=[['--backend','cpu','--threads','4']]
        if args.metal or args.tune:
            # Native execution must succeed; GPU failures are never silently skipped.
            subprocess.run([binary,'verify-gpu','--samples','256'],check=True,timeout=180)
            if args.tune:
                configurations += [['--backend','metal','--batch-size',str(b),'--threadgroup-size',str(t),'--window-bits',str(w)] for w in args.windows for b in args.batches for t in args.threadgroups]
            else: configurations.append(['--backend','metal'])
        for config in configurations:
            if 'metal' in config:
                checked=subprocess.run([binary,'verify-gpu','--samples','1025',*config],text=True,capture_output=True,timeout=180)
                if checked.returncode:
                    if 'threadgroup size exceeds' in checked.stderr:
                        results['benchmarks'].append({'program':'rust','arguments':config,'unsupported':checked.stderr.strip()})
                        continue
                    raise RuntimeError(f'GPU verification failed: {checked.stderr}')
            samples=[]
            for _ in range(args.repeats):
                output=subprocess.check_output([binary,'benchmark','--seconds',str(args.seconds),*config],text=True,timeout=args.seconds+180)
                samples.append(int(re.search(r'Seeds/s: (\d+)',output).group(1)))
            results['benchmarks'].append({'program':'rust','arguments':config,'median_seeds_per_second':statistics.median(samples),'samples_seeds_per_second':samples,'gpu_verified':'metal' in config})
        samples=[]
        for _ in range(args.repeats):
            process=subprocess.Popen([reference,'--nologfile','--resultsdir',tmp,'vanitygen','--prefix','02ffffffffffffff','--threads','4'],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
            try: output,_=process.communicate(timeout=args.seconds+0.25)
            except subprocess.TimeoutExpired:
                process.send_signal(signal.SIGINT)
                output,_=process.communicate(timeout=10)
            measurements=re.findall(r'Tested ([\d,]+)k seeds.*?elapsed=(\d+)s',output)
            assert measurements,output
            count,elapsed=measurements[-1]
            samples.append(int(count.replace(',',''))*1000/int(elapsed))
        results['benchmarks'].append({'program':'chantools','threads':4,'median_seeds_per_second':statistics.median(samples),'samples_seeds_per_second':samples,'note':'Reference reports tested count rounded down to thousands.'})
    gpu=[b for b in results['benchmarks'] if b.get('gpu_verified') and 'median_seeds_per_second' in b]
    if gpu:
        results['recommended_gpu_arguments']=max(gpu,key=lambda b:b['median_seeds_per_second'])['arguments']
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(results,indent=2)+'\n')
    print(json.dumps(results,indent=2))


if __name__=='__main__':main()
