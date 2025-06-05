import Nat32 "mo:base/Nat32";
import Nat8 "mo:base/Nat8";
import Nat "mo:base/Nat";
import Iter "mo:base/Iter";
import Array "mo:base/Array";

module Chacha20 {
  // Function to perform bitwise left rotation on a 32-bit value
  public func bitLeftRoll(num : Nat32, n : Nat32) : Nat32 {
    let msb = num << n;
    let lsb = num >> (32 - n);
    msb | lsb
  };

  // Perform a ChaCha20 quarter round on specified indices of the state
  public func quarterRound(state : [var Nat32], x : Nat, y : Nat, z : Nat, w : Nat) {
    state[x] := state[x] +% state[y];
    state[w] := state[w] ^ state[x];
    state[w] := bitLeftRoll(state[w], 16);

    state[z] := state[z] +% state[w];
    state[y] := state[y] ^ state[z];
    state[y] := bitLeftRoll(state[y], 12);

    state[x] := state[x] +% state[y];
    state[w] := state[w] ^ state[x];
    state[w] := bitLeftRoll(state[w], 8);

    state[z] := state[z] +% state[w];
    state[y] := state[y] ^ state[z];
    state[y] := bitLeftRoll(state[y], 7)
  };

  // Initialize ChaCha20 state with key, counter, and nonce
  func state(key : [Nat32], counter : Nat32, nonce : [Nat32]) : [var Nat32] {
    assert (key.size() == 8 and nonce.size() == 3); // Ensure correct key and nonce sizes

    // Create initial state matrix
    let state : [var Nat32] = [
      var 0x61707865,
      0x3320646e,
      0x79622d32,
      0x6b206574, // Constants ("expand 32-byte k")
      key[0],
      key[1],
      key[2],
      key[3], // Key (first half)
      key[4],
      key[5],
      key[6],
      key[7], // Key (second half)
      counter, // Block counter
      nonce[0],
      nonce[1],
      nonce[2] // Nonce
    ];

    state
  };

  // Apply 20 rounds of ChaCha20 to the state
  func apply20Rounds(state : [var Nat32]) {
    // Copy original state to add back later
    let original_state = Array.tabulateVar<Nat32>(16, func(i) {state[i]});

    var i = 0;
    while (i < 10) {
      // Column Rounds
      quarterRound(state, 0, 4, 8, 12);
      quarterRound(state, 1, 5, 9, 13);
      quarterRound(state, 2, 6, 10, 14);
      quarterRound(state, 3, 7, 11, 15);

      // Diagonal Rounds
      quarterRound(state, 0, 5, 10, 15);
      quarterRound(state, 1, 6, 11, 12);
      quarterRound(state, 2, 7, 8, 13);
      quarterRound(state, 3, 4, 9, 14);

      i += 1
    };

    // Final Addition: state[i] += original_state[i]
    for (i in Iter.range(0, 15)) {
      state[i] := state[i] +% original_state[i]
    }
  };

  // Convert a 32-bit word to bytes in little-endian order
  func nat32ToBytes(num : Nat32) : [Nat8] {
    return [
      Nat8.fromNat(Nat32.toNat(num & 0xFF)), // Byte 0 (LSB)
      Nat8.fromNat(Nat32.toNat((num >> 8) & 0xFF)), // Byte 1
      Nat8.fromNat(Nat32.toNat((num >> 16) & 0xFF)), // Byte 2
      Nat8.fromNat(Nat32.toNat((num >> 24) & 0xFF)) // Byte 3 (MSB)
    ]
  };

  // Utility to convert bytes to a Nat32 word in little-endian order
  public func bytesToNat32(bytes : [Nat8], offset : Nat) : Nat32 {
    assert (offset + 4 <= bytes.size());
    var result : Nat32 = 0;
    result := result | Nat32.fromNat(Nat8.toNat(bytes[offset]));
    result := result | (Nat32.fromNat(Nat8.toNat(bytes[offset + 1])) << 8);
    result := result | (Nat32.fromNat(Nat8.toNat(bytes[offset + 2])) << 16);
    result := result | (Nat32.fromNat(Nat8.toNat(bytes[offset + 3])) << 24);
    result
  };

  // Generate a ChaCha20 keystream block
  public func chachaBlock(key : [Nat32], counter : Nat32, nonce : [Nat32]) : [Nat8] {
    let state_matrix = state(key, counter, nonce);
    apply20Rounds(state_matrix); // Apply 20 rounds of transformation

    // Convert Nat32 state to byte array (64-byte keystream)
    Array.flatten(Array.tabulate<[Nat8]>(16, func(i) = nat32ToBytes(state_matrix[i])))
  };

  // XOR a plaintext with a keystream
  public func xorBytes(plaintext : [Nat8], keystream : [Nat8]) : [Nat8] {
    let length = plaintext.size();
    assert (keystream.size() >= length); // Ensure keystream is long enough

    return Array.tabulate<Nat8>(
      length,
      func(i) {
        plaintext[i] ^ keystream[i]
      }
    )
  };

  // Encrypt a single block of data
  public func encrypt(key : [Nat32], counter : Nat32, nonce : [Nat32], plaintext : [Nat8]) : [Nat8] {
    let keystream = chachaBlock(key, counter, nonce); // Generate 64-byte keystream
    xorBytes(plaintext, keystream)
  };

  // Encrypt multiple blocks of data
  public func encryptMultiBlock(key : [Nat32], counter : Nat32, nonce : [Nat32], plaintext : [Nat8]) : [Nat8] {
    // Handle empty plaintext case
    if (plaintext.size() == 0) {
      return []
    };

    let blockSize = 64; // ChaCha20 block size in bytes
    let numBlocks = (plaintext.size() + blockSize - 1) / blockSize; // Calculate number of blocks needed
    var ciphertext = Array.init<Nat8>(plaintext.size(), 0); // Initialize output array

    var i = 0;
    while (i < numBlocks) {
      let blockCounter = counter +% Nat32.fromNat(i); // Increment block counter
      let keystream = chachaBlock(key, blockCounter, nonce); // Generate keystream for this block

      // Calculate the start and end indices for this block
      let start = i * blockSize;
      let end = Nat.min(start + blockSize, plaintext.size());
      let blockLength = end - start;

      // XOR the block with the keystream
      for (j in Iter.range(0, blockLength - 1)) {
        ciphertext[start + j] := plaintext[start + j] ^ keystream[j]
      };

      i += 1
    };

    return Array.freeze(ciphertext)
  };

  // Utility function to create a key array from byte array
  public func keyFromBytes(keyBytes : [Nat8]) : [Nat32] {
    assert (keyBytes.size() == 32);

    var key = Array.init<Nat32>(8, 0);
    for (i in Iter.range(0, 7)) {
      key[i] := bytesToNat32(keyBytes, i * 4)
    };

    return Array.freeze(key)
  };

  // Utility function to create a nonce array from byte array
  public func nonceFromBytes(nonceBytes : [Nat8]) : [Nat32] {
    assert (nonceBytes.size() == 12);

    var nonce = Array.init<Nat32>(3, 0);
    nonce[0] := bytesToNat32(nonceBytes, 0); // First 4 bytes
    nonce[1] := bytesToNat32(nonceBytes, 4); // Next 4 bytes
    nonce[2] := bytesToNat32(nonceBytes, 8); // Last 4 bytes

    Array.freeze(nonce)
  }
}