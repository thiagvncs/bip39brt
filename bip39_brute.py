import itertools
import hashlib
import hmac
import ecdsa
import binascii
import sys
from io import StringIO
from mnemonic import Mnemonic
import pyopencl as cl
import numpy as np
import time

# Base58 alphabet
BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def base58_encode(data):
    n = int.from_bytes(data, 'big')
    result = ''
    while n > 0:
        n, r = divmod(n, 58)
        result = BASE58_ALPHABET[r] + result
    # Add leading '1's for leading zeros
    leading_zeros = 0
    for byte in data:
        if byte == 0:
            leading_zeros += 1
        else:
            break
    return '1' * leading_zeros + result

def parse_hmac_from_output(output):
    lines = output.split('\n')
    for line in lines:
        if 'HMAC' in line:
            # Extract the hex values
            parts = line.split('"')
            if len(parts) > 1:
                hex_str = parts[1]
                # Remove spaces if any
                hex_str = hex_str.replace(' ', '')
                # It's 16 hex values of 016lx, so 128 chars
                if len(hex_str) == 128:
                    return [int(hex_str[i:i+16], 16) for i in range(0, 128, 16)]
    return None

def master_key_to_address(master_key_bytes):
    # master_key_bytes is 64 bytes
    master_private = master_key_bytes[:32]
    master_chain = master_key_bytes[32:]

    # Derive m/44'/0'/0'/0/0
    # 44' = 0x8000002C
    i = 0x8000002C
    data = master_private + i.to_bytes(4, 'big')
    I = hmac.new(master_chain, data, hashlib.sha512).digest()
    k_int = (int.from_bytes(I[:32], 'big') + int.from_bytes(master_private, 'big')) % 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    c = I[32:]
    private_key = k_int.to_bytes(32, 'big')

    # 0' = 0x80000000
    i = 0x80000000
    data = private_key + i.to_bytes(4, 'big')
    I = hmac.new(c, data, hashlib.sha512).digest()
    k_int = (int.from_bytes(I[:32], 'big') + int.from_bytes(private_key, 'big')) % 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    c = I[32:]
    private_key = k_int.to_bytes(32, 'big')

    # 0' = 0x80000000
    i = 0x80000000
    data = private_key + i.to_bytes(4, 'big')
    I = hmac.new(c, data, hashlib.sha512).digest()
    k_int = (int.from_bytes(I[:32], 'big') + int.from_bytes(private_key, 'big')) % 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    c = I[32:]
    private_key = k_int.to_bytes(32, 'big')

    # 0 (non-hardened)
    i = 0
    data = b'\x00' + private_key + i.to_bytes(4, 'big')
    I = hmac.new(c, data, hashlib.sha512).digest()
    k_int = (int.from_bytes(I[:32], 'big') + int.from_bytes(private_key, 'big')) % 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    c = I[32:]
    private_key = k_int.to_bytes(32, 'big')

    # 0
    i = 0
    data = b'\x00' + private_key + i.to_bytes(4, 'big')
    I = hmac.new(c, data, hashlib.sha512).digest()
    k_int = (int.from_bytes(I[:32], 'big') + int.from_bytes(private_key, 'big')) % 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    private_key = k_int.to_bytes(32, 'big')

    # Public key
    sk = ecdsa.SigningKey.from_secret_exponent(k_int, curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    pub_key_bytes = b'\x04' + vk.pubkey.point.x().to_bytes(32, 'big') + vk.pubkey.point.y().to_bytes(32, 'big')

    # Hash160
    sha = hashlib.sha256(pub_key_bytes).digest()
    rip = hashlib.new('ripemd160', sha).digest()

    # Address
    version_rip = b'\x00' + rip
    checksum = hashlib.sha256(hashlib.sha256(version_rip).digest()).digest()[:4]
    address = base58_encode(version_rip + checksum)
    return address

def run_kernel_captured(context, queue, program, high, low):
    kernel = program.verify
    elements = 1 * 12000
    bytes_size = elements * 8
    high_buf = cl.Buffer(context, cl.mem_flags.READ_ONLY | cl.mem_flags.COPY_HOST_PTR, hostbuf=np.array([high], dtype=np.uint64))
    low_buf = cl.Buffer(context, cl.mem_flags.READ_ONLY | cl.mem_flags.COPY_HOST_PTR, hostbuf=np.array([low], dtype=np.uint64))
    p = cl.Buffer(context, cl.mem_flags.READ_ONLY | cl.mem_flags.COPY_HOST_PTR, hostbuf=np.array([1], dtype=np.uint32))
    output_buf = cl.Buffer(context, cl.mem_flags.WRITE_ONLY, bytes_size)

    kernel.set_args(p, high_buf, low_buf, output_buf)

    # Capture stdout
    old_stdout = sys.stdout
    sys.stdout = captured_output = StringIO()

    event = cl.enqueue_nd_range_kernel(queue, kernel, (1,), (1,))
    event.wait()

    sys.stdout = old_stdout
    output = captured_output.getvalue()

    return parse_hmac_from_output(output)

def words_to_indices(words):
    indices = []
    for word in words:
        if word in mnemo.wordlist:
            indices.append(mnemo.wordlist.index(word))
    return np.array(indices, dtype=np.int32)

def mnemonic_to_uint64_pair(indices): 
    binary_string = ''.join(f"{index:011b}" for index in indices)[:-4]
    binary_string = binary_string.ljust(128, '0')
    high = int(binary_string[:64], 2)
    low = int(binary_string[64:], 2)
    return high, low

# Blocks
block1 = ['bexiga', 'curativo', 'neblina', 'nevoeiro', 'bonde', 'reter']
block2 = ['abutre', 'corvo', 'urubu', 'megafone', 'falar', 'haste', 'global', 'englobar', 'pilastra', 'sentado', 'pouso', 'reter']
block3 = ['livro', 'leitura', 'mulher', 'jogador', 'amarelo', 'colher', 'futebol', 'cozinha', 'espanto', 'rosto', 'camisa', 'branco', 'senador', 'gaveta', 'reter']

TARGET_ADDRESS = "1CfntEjWHwCc7moXnMHUX8QuBJaakAnv8U"

mnemo = Mnemonic("portuguese")

# Setup OpenCL
platforms = cl.get_platforms()
devices = platforms[0].get_devices()
device = devices[0]
print(f"Using device: {device.name}")
context = cl.Context([device])
queue = cl.CommandQueue(context, properties=cl.command_queue_properties.PROFILING_ENABLE)

def load_program_source(filename):
    with open(filename, 'r') as f:
        content = f.read()
    return content

def build_program(context, *filenames):
    source_code = ""
    for filename in filenames:
        source_code += load_program_source(filename) + "\n\n\n"
    return cl.Program(context, source_code).build()

program = build_program(context, "./kernel/brute_kernel.cl")

kernel = program.verify_batch

# Generate combinations
combos1 = list(itertools.combinations(block1, 4))
combos2 = list(itertools.combinations(block2, 4))
combos3 = list(itertools.combinations(block3, 4))

total_combos = len(combos1) * len(combos2) * len(combos3)
print(f"Number of combinations: {len(combos1)} * {len(combos2)} * {len(combos3)} = {total_combos}")

batch_size = 512
local_workers = 256  # Match main.py
global_workers = batch_size

start_time = time.perf_counter()
count = 0

highs = []
lows = []
words_list = []

def process_batch(highs, lows, words_list):
    global count
    if not highs:
        return
    num = len(highs)
    high_buf = cl.Buffer(context, cl.mem_flags.READ_ONLY | cl.mem_flags.COPY_HOST_PTR, hostbuf=np.array(highs, dtype=np.uint64))
    low_buf = cl.Buffer(context, cl.mem_flags.READ_ONLY | cl.mem_flags.COPY_HOST_PTR, hostbuf=np.array(lows, dtype=np.uint64))
    output_buf = cl.Buffer(context, cl.mem_flags.WRITE_ONLY, num * 8 * 8)  # num * 8 ulongs

    kernel.set_args(high_buf, low_buf, output_buf)

    event = cl.enqueue_nd_range_kernel(queue, kernel, (num,), (local_workers,))
    event.wait()

    result = np.empty(num * 8, dtype=np.uint64)
    cl.enqueue_copy(queue, result, output_buf).wait()

    for i in range(num):
        master_key_bytes = b''.join(int(result[i*8 + j]).to_bytes(8, 'big') for j in range(8))
        address = master_key_to_address(master_key_bytes)
        if address == TARGET_ADDRESS:
            print(f"Found: {' '.join(words_list[i])}")
            print(f"Address: {address}")
            exit(0)

for combo1 in combos1:
    for combo2 in combos2:
        for combo3 in combos3:
            words = list(combo1) + list(combo2) + list(combo3)
            indices = [mnemo.wordlist.index(word) for word in words]
            high, low = mnemonic_to_uint64_pair(indices)
            highs.append(high)
            lows.append(low)
            words_list.append(words)
            if len(highs) == batch_size:
                process_batch(highs, lows, words_list)
                count += batch_size
                if count % (batch_size * 10) == 0:  # every 10 batches
                    elapsed = time.perf_counter() - start_time
                    rate = count / elapsed
                    print(f"Processed {count} combinations, {rate:.2f} per second")
                highs = []
                lows = []
                words_list = []

# Process remaining
if highs:
    process_batch(highs, lows, words_list)
    count += len(highs)

print("No match found.")
