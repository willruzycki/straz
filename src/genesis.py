#!/usr/bin/env python3

import hashlib
import time
import struct
import binascii

def sha256(data):
    return hashlib.sha256(data).digest()

def sha256d(data):
    return sha256(sha256(data))

def uint32(x):
    return x & 0xffffffff

def bytereverse(x):
    # Handle both int and bytes types
    if isinstance(x, int):
        return uint32((x >> 24) | ((x >> 8) & 0xff00) | ((x << 8) & 0xff0000) | (x << 24))
    else:
        return uint32(int.from_bytes(x, byteorder='little'))

def bufreverse(in_buf):
    out_words = []
    for i in range(0, len(in_buf), 4):
        word = struct.unpack("@I", in_buf[i:i+4])[0]
        out_words.append(struct.pack("@I", bytereverse(word)))
    return b''.join(out_words)

def wordreverse(in_buf):
    out_words = []
    for i in range(0, len(in_buf), 4):
        out_words.append(in_buf[i:i+4])
    out_words.reverse()
    return b''.join(out_words)

def calc_hash_str(merkle_root):
    version = 1
    prev_block = "0" * 64
    timestamp = 1748736000  # May 5, 2025 00:00:00 UTC
    bits = 0x1d00ffff
    nonce = 0

    header = struct.pack("<I", version)
    header += binascii.unhexlify(prev_block)[::-1]
    header += struct.pack("<I", timestamp)
    header += struct.pack("<I", bits)
    header += struct.pack("<I", nonce)
    header += merkle_root

    hash = sha256d(header)
    hash = bufreverse(hash)
    hash = wordreverse(hash)
    hash_str = binascii.hexlify(hash).decode('utf-8')

    return hash_str

def main():
    # Genesis block parameters
    timestamp = "Straz Genesis Block – Privacy & Payments, 2025-05-05"
    pubkey = "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f"
    value = 50 * 100000000  # 50 STRZ in satoshis
    script = "4104" + pubkey + "ac"  # P2PKH script

    # Create coinbase transaction
    tx_in = struct.pack("<I", 0xffffffff)  # Previous output index
    tx_in += struct.pack("<B", len(timestamp)) + timestamp.encode()  # Coinbase script
    tx_in += struct.pack("<I", 0xffffffff)  # Sequence

    tx_out = struct.pack("<Q", value)  # Value
    tx_out += struct.pack("<B", len(script)//2) + binascii.unhexlify(script)  # Script

    tx = struct.pack("<I", 1)  # Version
    tx += struct.pack("<B", 1)  # Input count
    tx += tx_in
    tx += struct.pack("<B", 1)  # Output count
    tx += tx_out
    tx += struct.pack("<I", 0)  # Lock time

    # Calculate merkle root
    merkle_root = sha256d(tx)
    merkle_root = bufreverse(merkle_root)
    merkle_root = wordreverse(merkle_root)

    # Find nonce that gives hash below target
    target = 0x1d00ffff
    nonce = 0
    while True:
        header = struct.pack("<I", 1)  # Version
        header += b'\x00' * 32  # Previous block hash
        header += struct.pack("<I", 1748736000)  # Timestamp
        header += struct.pack("<I", target)  # Bits
        header += struct.pack("<I", nonce)  # Nonce
        header += merkle_root

        hash = sha256d(header)
        hash = bufreverse(hash)
        hash = wordreverse(hash)
        hash_int = int.from_bytes(hash, byteorder='big')

        if hash_int < target:
            break

        nonce += 1
        if nonce % 1000000 == 0:
            print(f"Tried {nonce} nonces...")

    # Print results
    print("\nGenesis Block Parameters:")
    print(f"Timestamp: {timestamp}")
    print(f"Pubkey: {pubkey}")
    print(f"Nonce: {nonce}")
    print(f"Merkle Root: {binascii.hexlify(merkle_root).decode('utf-8')}")
    print(f"Hash: {binascii.hexlify(hash).decode('utf-8')}")

if __name__ == "__main__":
    main() 