"""
@author: Vitaly <vitaly@optinsoft.net> | github.com/optinsoft
"""
import pathutils
import pycuda.driver as cuda
from pycuda.compiler import SourceModule
import pycuda.gpuarray as gpuarray
import pycuda.autoinit
import numpy as np
from functools import reduce
import ecdsa
from Crypto.Hash import keccak
import base58
import random

def randomUInt32() -> int:
    return int.from_bytes(np.random.bytes(4), byteorder='little', signed=False)

'''
test private key:          0x68e23530deb6d5011ab56d8ad9f7b4a3b424f1112f08606357497495929f72dc
test public key:           0x5d99d81d9e731e0d7eebd1c858b1155da7981b1f0a16d322a361f8b589ad2e3bde53dc614e3a84164dab3f5899abde3b09553dca10c9716fa623a5942b9ea420
test keccak256:            0x4c84817f57c18372837905af33f4b63eb1c5a9966a31cebc302f563685695506
test sha256-0:             0x00645d7ba1bbd8ab7a0de9e6e5527ef2ad50486bcba78074ba3bfcd33f75f468
test sha256-1:             0x6fd9ed936f1cce537040e5fc1b59bfd1ed11c1f50c4fe0a85f69799ea366bb62
test checksum:             0x6fd9ed93
test trx address (hex):    0x4133f4b63eb1c5a9966a31cebc302f5636856955066fd9ed93
test trx address (base58): TEhvcissgbsN96cYCcjpGrhBuT9cedk6cS
'''

def testUInt32(idx: int) -> int:
    r = [0x68e23530, 0xdeb6d501, 0x1ab56d8a, 0xd9f7b4a3, 0xb424f111, 0x2f086063, 0x57497495, 0x929f72dc][idx]
    return r

def randomUInt32Array(count: int) -> list[int]:
    return [randomUInt32() for i in range(count)]

def randomWithTestUInt32Array(count: int, idx: int) -> list[int]:
    return [testUInt32(idx) if i == 0 else randomUInt32() for i in range(count)]

def constUInt32Array(count: int, v: int) -> list[int]:
    return [v for i in range(count)]

def public_key_to_trx_address(public_key, i, print_keccak):
    keccak_hash = keccak.new(digest_bits=256)
    keccak_hash.update(public_key)
    keccak_digest = keccak_hash.digest()
    if print_keccak:
        print(f'keccak[{i}] (verification):      0x{keccak_digest.hex()}')
    primitive_address = b'\x41' + keccak_digest[-20:]
    address = base58.b58encode_check(primitive_address)
    return address.decode()

def key_to_str(k: list[int]) -> str:
    return reduce(lambda s, t: str(s) + t.to_bytes(4, byteorder='big').decode('ascii'), k[1:], k[0].to_bytes(4, byteorder='big').decode('ascii')).rstrip('\x00')

def key_to_hex(k: list[int]) -> str:
    return reduce(lambda s, t: str(s) + t.to_bytes(4, byteorder='big').hex(), k[1:], k[0].to_bytes(4, byteorder='big').hex())

def main_getTrxAddress(keyCount: int, verify: bool):
    kernel_code = f'''
#define RANDOM_VALUE {random.randint(1, 1000000)}
    '''
    def load_code(path: str) -> str:
        with open(path, 'r') as text_file:
            code_text = text_file.read()
        lines = code_text.splitlines()
        result = reduce(lambda t, l: 
                        t + "\n" + l if len(l) > 0 and not l.startswith('#include ') else t, 
                        lines, '')
        return result
    dirCommon = './common/'    
    
    kernel_code += load_code(dirCommon + 'inc_vendor.h')
    kernel_code += load_code(dirCommon + 'inc_types.h')
    kernel_code += load_code(dirCommon + 'inc_platform_1.h')
    kernel_code += load_code(dirCommon + 'inc_common.h')
    kernel_code += load_code(dirCommon + 'inc_platform_1.cl')
    kernel_code += load_code(dirCommon + 'inc_common_1.cl')
    dirSecp256k1 = './secp256k1/'    
    kernel_code += load_code(dirSecp256k1 + 'inc_ecc_secp256k1.h')
    kernel_code += load_code(dirSecp256k1 + 'inc_ecc_secp256k1.cl')
    dirKeccak = './keccak/'
    kernel_code += load_code(dirKeccak + 'keccak256.h')
    kernel_code += load_code(dirKeccak + 'keccak256.cl')
    dirSha256 = './sha256/'
    kernel_code += load_code(dirSha256 + 'inc_hash_sha256.h')
    kernel_code += load_code(dirSha256 + 'inc_hash_sha256.cl')    
    dirBase58 = './base58/'
    kernel_code += load_code(dirBase58 + 'inc_hash_base58.h')
    kernel_code += load_code(dirBase58 + 'inc_hash_base58.cl')    
    dirKernels = './kernels/'
    kernel_code += load_code(dirKernels + 'gen_trx_addr.cl')
    
    k = [np.array(randomWithTestUInt32Array(keyCount, i), dtype=np.uint32) for i in range(8)]
    a = [np.array(constUInt32Array(keyCount, 0), dtype=np.uint32) for i in range(9)]

    k_gpu = [gpuarray.to_gpu(k[i]) for i in range(8)]
    a_gpu = [gpuarray.to_gpu(a[i]) for i in range(9)]

    mod = SourceModule(kernel_code)
    genTrxAddress = mod.get_function('genTrxAddress')

    print("")

    genTrxAddress(
        a_gpu[0], a_gpu[1], a_gpu[2], a_gpu[3], a_gpu[4], a_gpu[5], a_gpu[6], a_gpu[7], a_gpu[8], 
        k_gpu[0], k_gpu[1], k_gpu[2], k_gpu[3], k_gpu[4], k_gpu[5], k_gpu[6], k_gpu[7],
        block=(keyCount, 1, 1))

    for i in range(keyCount):
        _k = [k_gpu[j][i].get().item() for j in range(8)]
        priv = key_to_hex(_k)
        if verify:
            print(f"priv[{i}]:                       0x{priv}")   
        _a = [a_gpu[j][i].get().item() for j in range(9)]
        trx_address = key_to_str(_a)            
        if verify:
            print(f"trx address[{i}]:                {trx_address}")
            pk_bytes = bytes.fromhex(priv)
            public_key = ecdsa.SigningKey.from_string(pk_bytes, curve=ecdsa.SECP256k1).verifying_key.to_string()
            print(f"public key[{i}] (verification):  0x{public_key.hex()}")    
            address = public_key_to_trx_address(public_key, i, True)
            print(f"trx address[{i}] (verification): {address}")
        else:
            print(f"0x{priv},{trx_address}")

if __name__ == "__main__":
    main_getTrxAddress(keyCount=32, verify=True)