"""
@author: Vitaly <vitaly@optinsoft.net> | github.com/optinsoft
"""
import pycuda.driver as cuda
from pycuda.compiler import SourceModule
import pycuda.gpuarray as gpuarray
import pycuda.autoinit
import numpy as np
from decouple import config
import os
from functools import reduce
import ecdsa
from Crypto.Hash import keccak
import base58
import argparse
import time

def randomUInt32() -> int:
    return int.from_bytes(np.random.bytes(4), byteorder='little', signed=False)

def randomUInt32Array(count: int) -> list[int]:
    return [randomUInt32() for i in range(count)]

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

def check_num_suffix(trx_address: str, suffixLength: int) -> bool:
    if len(trx_address) < suffixLength: return False
    s = trx_address[-suffixLength:]
    return s.isdigit() and (s == suffixLength * s[0])

def main_vanityTrxAddress(suffixLength: int, keyBlockCount: int, maxBlocks: int, blockIterations: int, verify: bool, verbose: bool, outputFile: str) -> int:
    CL_PATH = config('CL_PATH', default='')
    if len(CL_PATH) > 0:
        os.environ['PATH'] += ';'+CL_PATH
    
    kernel_code = '''

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

    if verbose:
        print("Building kernel...")

    mod = SourceModule(kernel_code)
    genTrxAddressWithNumSuffix = mod.get_function('genTrxAddressWithNumSuffix')

    print("")

    if verbose:
        print(f'Searching vanity trx address with suffix of {suffixLength} identical digits...')

    start_time = time.time()

    a = [np.array(constUInt32Array(keyBlockCount, 0), dtype=np.uint32) for i in range(9)]
    a_gpu = [gpuarray.to_gpu(a[i]) for i in range(9)]
    as_gpu = gpuarray.to_gpu(np.array(constUInt32Array(keyBlockCount, 0), dtype=np.uint32))
    
    s_len = np.int32(suffixLength)
    n_iterations = np.int32(blockIterations)

    for n in range(maxBlocks):
        k = [np.array(randomUInt32Array(keyBlockCount), dtype=np.uint32) for i in range(8)]
        k_gpu = [gpuarray.to_gpu(k[i]) for i in range(8)]

        genTrxAddressWithNumSuffix(
            a_gpu[0], a_gpu[1], a_gpu[2], a_gpu[3], a_gpu[4], 
            a_gpu[5], a_gpu[6], a_gpu[7], a_gpu[8], as_gpu,
            k_gpu[0], k_gpu[1], k_gpu[2], k_gpu[3], k_gpu[4], k_gpu[5], k_gpu[6], k_gpu[7],
            s_len, n_iterations,
            block=(keyBlockCount, 1, 1))
        
        for i in range(keyBlockCount):
            _as = as_gpu[i].get().item()
            if _as != 0:
                _a = [a_gpu[j][i].get().item() for j in range(9)]
                trx_address = key_to_str(_a)
                if check_num_suffix(trx_address, suffixLength):
                    if verbose:
                        end_time = time.time()  # end time
                        elapsed_time = end_time - start_time
                        print(f"Vanity trx address found in block # {n+1} iteration # {_as}, {elapsed_time:.2f} seconds")
                        count = (n + 1) * keyBlockCount * (blockIterations if blockIterations > 0 else 1)
                        print(f"Generated {count} trx addresses, {count/elapsed_time:.2f} addresses/second")
                    _k = [k_gpu[j][i].get().item() for j in range(8)]
                    priv = key_to_hex(_k)
                    if verify and verbose:
                        print(f"private key[{i}]:                0x{priv}")
                        print(f"trx address[{i}]:                {trx_address}")
                    if verify:
                        pk_bytes = bytes.fromhex(priv)
                        public_key = ecdsa.SigningKey.from_string(pk_bytes, curve=ecdsa.SECP256k1).verifying_key.to_string()
                        # print(f"public key[{i}] (verification):  0x{public_key.hex()}")    
                        address = public_key_to_trx_address(public_key, i, False)
                        if verbose:
                            print(f"trx address[{i}] (verification): {address}")
                        if address != trx_address:
                            print(f"Verification failed: _as[{i}]={_as}, trx_address[{i}]={trx_address}, verification={address}")
                        else:
                            print(f"0x{priv},{trx_address}")
                            if outputFile:
                                with open(outputFile, "a") as of:
                                    of.write(f"0x{priv},{trx_address}\n")
                    else:
                        print(f"0x{priv},{trx_address}")
                        if outputFile:
                            with open(outputFile, "a") as of:
                                of.write(f"0x{priv},{trx_address}\n")
                    return 1
                else:
                    print(f"Unexpected result: _as[{i}]={_as}, trx_address[{i}]={trx_address}")
    if verbose:
        end_time = time.time()  # end time
        elapsed_time = end_time - start_time
        print(f"Not found, {elapsed_time:.2f} seconds")
        count = maxBlocks * keyBlockCount * (blockIterations if blockIterations > 0 else 1)
        print(f"Generated {count} trx addresses, {count/elapsed_time:.2f} addresses/second")
    return 0

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="pyvanityeth.py")
    parser.add_argument('-v', '--verbose', action='store_true', help='verbose')
    parser.add_argument('--verify', action='store_true', help='verify found trx address')
    parser.add_argument("--suffixLength", required=True, type=int, help="vanity trx address suffix length")
    parser.add_argument("--blocks", required=False, type=int, default=1000, help="try find vanity trx address within BLOCKS blocks (default: 1000)")
    parser.add_argument("--blockSize", required=False, type=int, default=128, help="generate block of BLOCKSIZE trx addresses by using GPU (default: 128)")
    parser.add_argument("--blockIterations", required=False, type=int, default=1, help="attempts to find vanity trx address within each block")
    parser.add_argument("--output", required=False, type=str, default="", help="output found trx address to file")
    args = parser.parse_args()
    main_vanityTrxAddress(args.suffixLength, args.blockSize, args.blocks, args.blockIterations, args.verify, args.verbose, args.output)
