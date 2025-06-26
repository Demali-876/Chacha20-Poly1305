////////////////////////////////////////////////////////////////////////////////
// File:    Poly1305.mo
// Author:  Demali Gregg
// Created: 2025-06
//
// Poly1305 MAC per RFC 8439.
////////////////////////////////////////////////////////////////////////////////

import Nat8 "mo:base/Nat8";
import Array "mo:base/Array";
import Iter "mo:base/Iter";
import Nat "mo:base/Nat";
import Text "mo:base/Text";
import Chacha20 "Chacha20";

module {

  public let KEY_SIZE : Nat = 32;
  public let TAG_SIZE : Nat = 16;
  public let BLOCK_SIZE : Nat = 16;

  public func clamp(r : [var Nat8]) {
    assert (r.size() == 16);
    r[3] := r[3] & 0x0F;
    r[7] := r[7] & 0x0F;
    r[11] := r[11] & 0x0F;
    r[15] := r[15] & 0x0F;
    r[4] := r[4] & 0xFC;
    r[8] := r[8] & 0xFC;
    r[12] := r[12] & 0xFC;
  };

  /// Convert little-endian bytes to Nat
  public func leBytes2Nat(bytes : [Nat8]) : Nat {
    var result : Nat = 0;
    for (i in Iter.range(0, bytes.size() - 1)) {
      result += Nat.pow(256, i) * Nat8.toNat(bytes[i]);
    };
    result;
  };

  /// Convert Nat to little-endian bytes
  public func nat2LeBytes(n : Nat, size : Nat) : [Nat8] {
    var remaining = n;
    Array.tabulate<Nat8>(
      size,
      func(i) {
        let byte = Nat8.fromNat(remaining % 256);
        remaining := remaining / 256;
        byte;
      },
    );
  };

  public func generateKey(key : [Nat32], nonce : [Nat32]) : ([Nat8], [Nat8]) {
    let keystream = Chacha20.chachaBlock(key, 0, nonce); // Counter = 0

    // First 16 bytes for r
    let r = Array.subArray<Nat8>(keystream, 0, 16);
    let rVar = Array.thaw<Nat8>(r);
    clamp(rVar);
    let rClamped = Array.freeze<Nat8>(rVar);

    // Next 16 bytes for s
    let s = Array.subArray<Nat8>(keystream, 16, 16);

    (rClamped, s);
  };

  public func mac(key : [Nat8], msg : [Nat8]) : [Nat8] {
    assert (key.size() == KEY_SIZE);

    // Split key into r and s
    let r = Array.subArray<Nat8>(key, 0, BLOCK_SIZE);
    let s = Array.subArray<Nat8>(key, 16, BLOCK_SIZE);

    // Apply clamping to r
    let rVar = Array.thaw<Nat8>(r);
    clamp(rVar);
    let rClamped = Array.freeze<Nat8>(rVar);

    // Convert r and s to Nat
    let rInt = leBytes2Nat(rClamped);
    let sInt = leBytes2Nat(s);

    // Prime: 2^130 - 5
    let p : Nat = 0x3fffffffffffffffffffffffffffffffb;

    var accumulator : Nat = 0;

    // Process message in blocks
    var i = 0;
    while (i < msg.size()) {
      // Determine block size (full or partial)
      let blockSize = Nat.min(BLOCK_SIZE, msg.size() - i);

      // Create a block buffer and copy message bytes
      var blockBuffer = Array.init<Nat8>(BLOCK_SIZE, 0x00);
      for (j in Iter.range(0, blockSize - 1)) {
        blockBuffer[j] := msg[i + j];
      };

      let blockBytes = Array.freeze<Nat8>(blockBuffer);
      var blockInt = leBytes2Nat(blockBytes);

      if (blockSize == BLOCK_SIZE) {
        // Add 2^128 to the number instead of setting a byte outside the array
        blockInt += Nat.pow(2, 128);
      } else {
        blockBuffer[blockSize] := 0x01;
        blockInt := leBytes2Nat(Array.freeze<Nat8>(blockBuffer));
      };

      // Update accumulator
      accumulator := (accumulator + blockInt) % p;
      accumulator := (accumulator * rInt) % p;

      i += blockSize;
    };

    accumulator := (accumulator + sInt) % Nat.pow(2, 128);

    nat2LeBytes(accumulator, 16);
  };

  public func verify(tag1 : [Nat8], tag2 : [Nat8]) : Bool {
    assert (tag1.size() == TAG_SIZE and tag2.size() == TAG_SIZE);

    var result : Nat8 = 0;
    for (i in Iter.range(0, TAG_SIZE - 1)) {
      result |= (tag1[i] ^ tag2[i]);
    };

    result == 0;
  };
  public func bytesToHex(bytes : [Nat8]) : Text {
    let hexDigits = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'];
    var result = "";

    for (byte in bytes.vals()) {
      let high = Nat8.toNat(byte >> 4);
      let low = Nat8.toNat(byte & 0x0F);

      result #= Text.fromChar(hexDigits[high]) # Text.fromChar(hexDigits[low]);
    };

    result;
  };
};
