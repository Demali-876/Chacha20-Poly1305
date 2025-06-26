# Motoko ChaCha20-Poly1305 Implementation

A pure Motoko implementation of the ChaCha20-Poly1305 Authenticated Encryption with Associated Data (AEAD) algorithm.

## Overview

This library provides a complete implementation of:

- **ChaCha20** stream cipher (RFC 8439)
- **Poly1305** message authentication code
- **ChaCha20-Poly1305 AEAD** construction

The implementation follows RFC 8439 specifications and includes comprehensive test coverage with RFC test vectors.

## Features

- RFC 8439 compliant ChaCha20-Poly1305 AEAD
- Support for single-block and multi-block encryption
- Authenticated encryption with associated data (AEAD)
- Comprehensive test suite with RFC test vectors
- Performance benchmarking suite

## Installation

```bash
mops add Chacha
```

## Usage

### Basic ChaCha20 Encryption

```motoko
import Chacha20 "mo:Chacha/Chacha";

// Generate key and nonce
let keyBytes = [/* 32 bytes */];
let nonceBytes = [/* 12 bytes */];
let key = Chacha20.keyFromBytes(keyBytes);
let nonce = Chacha20.nonceFromBytes(nonceBytes);

// Encrypt data
let plaintext = [/* your data */];
let ciphertext = Chacha20.encryptMultiBlock(key, 0, nonce, plaintext);

// Decrypt (ChaCha20 is symmetric)
let decrypted = Chacha20.encryptMultiBlock(key, 0, nonce, ciphertext);
```

### Poly1305 Message Authentication

```motoko
import Poly1305 "mo:Chacha/Poly1305";

let key = [/* 32 bytes */];
let message = [/* your message */];

// Compute MAC
let tag = Poly1305.mac(key, message);

// Verify MAC
let isValid = Poly1305.verify(tag, expectedTag);
```

### AEAD (Authenticated Encryption)

```motoko
import Chacha20_poly1305 "mo:Chcha";

let plaintext = [/* your data */];
let aad = [/* associated data */];
let key = [/* 32 bytes */];
let iv = [/* 8 bytes */];
let constant = [/* 4 bytes */];

// Encrypt with authentication
let (ciphertext, tag) = Chacha20_poly1305.aeadEncrypt(plaintext, aad, key, iv, constant);

// Decrypt and verify
switch (Chacha20_poly1305.aeadDecrypt(ciphertext, tag, aad, key, iv, constant)) {
  case (?decrypted) { /* Success */ };
  case (null) { /* Authentication failed */ };
};
```

## API Reference

### ChaCha20 Module

| Function | Description |
|----------|-------------|
| `keyFromBytes([Nat8])` | Convert 32-byte array to ChaCha20 key |
| `nonceFromBytes([Nat8])` | Convert 12-byte array to ChaCha20 nonce |
| `chachaBlock(key, counter, nonce)` | Generate 64-byte keystream block |
| `encrypt(key, counter, nonce, plaintext)` | Encrypt single block (≤64 bytes) |
| `encryptMultiBlock(key, counter, nonce, plaintext)` | Encrypt any size data |
| `quarterRound(state, a, b, c, d)` | Core ChaCha20 quarter round operation |

### Poly1305 Module

| Function | Description |
|----------|-------------|
| `mac(key, message)` | Compute Poly1305 MAC tag |
| `verify(tag1, tag2)` | Constant-time MAC verification |

### AEAD Module

| Function | Description |
|----------|-------------|
| `aeadEncrypt(plaintext, aad, key, iv, constant)` | Authenticated encryption |
| `aeadDecrypt(ciphertext, tag, aad, key, iv, constant)` | Authenticated decryption |

## Performance

Performance measurements using `IC.countInstructions()` on Internet Computer replica:

### Core Operations

| Operation | Instructions |
|-----------|-------------|
| Quarter Round | 1,905 |
| ChaCha Block (64B) | 180,119 |
| Key From Bytes | 9,031 |
| Nonce From Bytes | 2,938 |

### Instructions per Byte by Message Size

| Size | ChaCha20 | Poly1305 | AEAD |
|------|----------|----------|------|
| 16B | 11,870 | 52,716 | 114,399 |
| 64B | 3,328 | 23,146 | 39,322 |
| 1024B | 3,313 | 13,348 | 17,815 |
| 1400B | 3,329 | 13,352 | 17,410 |
| 4096B | 3,312 | 12,847 | 16,807 |

### Memory Usage (Garbage Collection)

|               |        16 |        64 |        256 |       1024 |       1400 |       4096 |    16384 |
| :------------ | --------: | --------: | ---------: | ---------: | ---------: | ---------: | -------: |
| ChaCha20 |  5.36 KiB |  5.92 KiB |  22.86 KiB |  89.68 KiB | 123.04 KiB | 356.15 KiB | 1.39 MiB |
| Poly1305 |    22 KiB | 38.75 KiB | 102.24 KiB | 358.14 KiB | 489.71 KiB |   1.35 MiB | 5.34 MiB |
| AEAD     | 48.21 KiB | 65.73 KiB | 147.59 KiB | 471.91 KiB | 630.48 KiB |   1.74 MiB | 6.83 MiB |

### Performance Characteristics

- **ChaCha20**: Consistent ~3,300 instructions/byte for messages ≥64 bytes
- **Poly1305**: Performance improves with message size (52K to 13K instructions/byte)
- **AEAD Overhead**: 4-7% coordination cost for medium/large messages
- **Optimal Range**: 1KB-4KB messages for best efficiency

## Security Notes

- Implementation follows RFC 8439 specifications
- Uses constant-time operations where applicable
- **Nonce reuse with the same key is cryptographically dangerous!**
- **Each encryption operation should use a unique nonce**
- The presence of the private keys in a canister is not secure as a single malicious node provider could inspect the state of the canister. VetKeys is a more  secure alternative but more expensive.

## Algorithm Details

### ChaCha20

- 20-round ARX (Add-Rotate-XOR) cipher
- 256-bit key, 96-bit nonce, 32-bit counter
- Generates 64-byte keystream blocks
- XOR keystream with plaintext for encryption

### Poly1305

- Universal hash function for message authentication
- 256-bit key input
- Operates over prime field 2^130 - 5
- Produces 128-bit authentication tag

### AEAD Construction

1. Use ChaCha20 to encrypt plaintext
2. Use Poly1305 to authenticate ciphertext + associated data
3. Combine for authenticated encryption

## Implementation Notes

- Prioritises for correctness over performance
- Poly1305 field arithmetic is the primary performance bottleneck
- ChaCha20 implementation is well-optimized for Motoko
- Memory usage is predictable and constant per operation

## Limitations

- Performance is **significantly** slower than other implementations (eg. C or  Rust Implementations) :( But still pretty good for motoko
- Small messages (<256 bytes) have high per-byte overhead

## References

- [RFC 8439: ChaCha20 and Poly1305 for IETF Protocols](https://tools.ietf.org/html/rfc8439)
- [C++ Implementation](https://github.com/mrdcvlsc/ChaCha20-Poly1305)
- [ChaCha20-Poly1305 Wikipedia](https://en.wikipedia.org/wiki/ChaCha20-Poly1305)
- [Daniel J. Bernstein's ChaCha specification](https://cr.yp.to/chacha.html)
- [Daniel J. Bernstein's Poly1305 specification](https://cr.yp.to/mac.html)
