#!/usr/bin/env python3
"""Execute the same MSL arithmetic as C++ and compare with an independent oracle.

This supplements, and does not replace, the native Metal tests.
Uses only Python's standard library and Apple's C++ compiler.
"""
import ctypes as C
import hashlib
import hmac
import re
import subprocess
import tempfile
import random
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def add(a, b):
    if a is None: return b
    if b is None: return a
    x, y = a
    u, v = b
    if x == u and (y != v or y == 0): return None
    slope = ((3*x*x) * pow(2*y, -1, P) if a == b else (v-y)*pow(u-x, -1, P)) % P
    z = (slope*slope-x-u) % P
    return z, (slope*(x-z)-y) % P


def multiply(k):
    q, base = None, G
    while k:
        if k & 1: q = add(q, base)
        base = add(base, base)
        k >>= 1
    return q


def pub(k):
    x, y = multiply(k)
    return bytes([2+(y & 1)]) + x.to_bytes(32, 'big')


def derive(entropy, coin):
    digest = hmac.digest(b'Bitcoin seed', entropy, 'sha512')
    key = int.from_bytes(digest[:32], 'big')
    chain = digest[32:]
    stages = digest
    for child in [0x800003f9, 0x80000000 | coin, 0x80000006, 0, 0]:
        data = b'\0'+key.to_bytes(32, 'big') if child >> 31 else pub(key)
        digest = hmac.digest(chain, data+child.to_bytes(4, 'big'), 'sha512')
        tweak = int.from_bytes(digest[:32], 'big')
        assert tweak < N
        key = (key+tweak) % N
        assert key
        chain = digest[32:]
        stages += key.to_bytes(32, 'big')+chain
    return b'\1'+stages+pub(key)


def main():
    source = (ROOT/'shaders/search.metal').read_text()
    source = source.replace('#include <metal_stdlib>', '').replace('using namespace metal;', '')
    source = source.replace('#include "sha512-constants.metal"', (ROOT/'shaders/sha512-constants.metal').read_text())
    source = re.sub(r'\[\[.*?\]\]', '', source)
    source = re.sub(r'\b(thread|device|kernel)\b', '', source)
    source = re.sub(r'\bconstant\b', 'const', source)
    header = '''#include <cstdint>
#include <atomic>
using uint=uint32_t; using uchar=uint8_t; using ulong=uint64_t;
using std::atomic_uint; using std::memory_order_relaxed;
using std::atomic_compare_exchange_weak_explicit;
struct uint4 {uint x,y,z,w;};
'''
    wrapper = '''extern "C" void run(const uchar* entropy, uchar* output, uint count, uint coin, const uint* table,uint bits) {
    uint4 params={count,coin,0,1};atomic_uint winner(0xffffffff);uchar prefix[8]={0};
    for(uint i=0;i<count;i++)search(entropy,output,params,prefix,table,&winner,bits,i);
}
extern "C" uint match(const uchar* entropy,uchar* output,uint count,uint coin,const uint* table,uint bits,const uchar* prefix,uint length) {
    uint4 params={count,coin,length,0};atomic_uint winner(0xffffffff);
    for(uint i=0;i<count;i++)search(entropy,output,params,prefix,table,&winner,bits,i);
    return winner.load();
}
extern "C" void arithmetic(const uint* a,const uint* b,uint* out,uint op) {
    U x,y;for(uint i=0;i<8;i++){x.v[i]=a[i];y.v[i]=b[i];}
    U r=op==0?add(x,y):op==1?sub(x,y):op==2?mul(x,y):op==3?scalaradd(x,y):inverse(x);
    for(uint i=0;i<8;i++)out[i]=r.v[i];
}
'''
    with tempfile.TemporaryDirectory() as tmp:
        cpp, lib = Path(tmp)/'shader.cpp', Path(tmp)/'shader.dylib'
        cpp.write_text(header+source+wrapper)
        subprocess.run(['clang++','-O2','-std=c++17','-shared',str(cpp),'-o',str(lib)],check=True)
        loaded = C.CDLL(str(lib))
        loaded.run.argtypes = [C.c_void_p,C.c_void_p,C.c_uint,C.c_uint,C.c_void_p,C.c_uint]
        loaded.match.argtypes = [C.c_void_p,C.c_void_p,C.c_uint,C.c_uint,C.c_void_p,C.c_uint,C.c_void_p,C.c_uint]
        loaded.match.restype = C.c_uint
        loaded.arithmetic.argtypes=[C.c_void_p,C.c_void_p,C.c_void_p,C.c_uint]
        rng=random.Random(1017)
        limbs=lambda n:(C.c_uint32*8)(*((n>>(32*i))&0xffffffff for i in range(8)))
        edge=[0,1,2,2**32-1,2**128-1,N-1,P-2,P-1]
        pairs=[(a,b) for a in edge for b in edge]+[(rng.randrange(P),rng.randrange(P)) for _ in range(1024)]
        for a,b in pairs:
            for op,modulus,expected in [(0,P,a+b),(1,P,a-b),(2,P,a*b),(3,N,(a%N)+(b%N))]:
                out=(C.c_uint32*8)()
                loaded.arithmetic(limbs(a%modulus),limbs(b%modulus),out,op)
                actual=sum(int(v)<<(32*i) for i,v in enumerate(out))
                assert actual==expected%modulus,(op,a,b,actual,expected%modulus)
        for a in edge[1:]+[rng.randrange(1,P) for _ in range(64)]:
            out=(C.c_uint32*8)();loaded.arithmetic(limbs(a),limbs(0),out,4)
            assert sum(int(v)<<(32*i) for i,v in enumerate(out))==pow(a,-1,P)
        seeds = [bytes(16),bytes([255])*16]+[hashlib.sha256(f'vector-{i}'.encode()).digest()[:16] for i in range(64)]
        inputs = C.create_string_buffer(b''.join(seeds))
        references={coin:[derive(entropy,coin) for entropy in seeds] for coin in [0,1]}
        for bits in [2,4,8]:
            table = []
            base = G
            for window in range(256//bits):
                q = None
                for digit in range(1,2**bits):
                    q = add(q,base)
                    for coordinate in q:
                        table.extend((coordinate >> (32*i)) & 0xffffffff for i in range(8))
                for _ in range(bits): base = add(base,base)
            data = (C.c_uint32*len(table))(*table)
            for coin in [0,1]:
                output = C.create_string_buffer(len(seeds)*418)
                loaded.run(inputs,output,len(seeds),coin,data,bits)
                for i,expected in enumerate(references[coin]):
                    actual = output.raw[i*418:(i+1)*418]
                    assert actual == expected, (bits,coin,i,next(j for j,(a,b) in enumerate(zip(actual,expected)) if a!=b))
                expected=references[coin][17][-33:]
                winner=loaded.match(inputs,output,len(seeds),coin,data,bits,expected[:4],4)
                assert winner==17 and output.raw[:33]==expected
                assert loaded.match(inputs,output,len(seeds),coin,data,bits,b'\xff\xff',2)==2**32-1
        print(f'PASS: {len(pairs)*4} field/scalar operations, 71 inverses; {len(seeds)*6} derivations across 2/4/8-bit tables, all six stages, public keys and prefix matches')


if __name__ == '__main__': main()
