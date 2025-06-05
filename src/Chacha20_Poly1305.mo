import Array "mo:base/Array";
import Nat8 "mo:base/Nat8";
import Nat32 "mo:base/Nat32";
import Poly1305 "Poly1305";
import Chacha20 "Chacha20";
import Iter "mo:base/Iter"

module Chacha20_Poly1305 {

  public func calculatePadding(length : Nat) : Nat {
    16 - (length % 16) % 16
  };

  private func constructNonce(constant : [Nat8], iv : [Nat8]) : [Nat8] {
    assert (constant.size() == 4);
    assert (iv.size() == 8);

    let nonce = Array.tabulate<Nat8>(
      12,
      func(i) {
        if (i < 4) {
          // First 4 bytes from constant
          constant[i]
        } else {
          // Next 8 bytes from iv
          iv[i - 4]
        }
      }
    );
    nonce
  };
  public func aeadEncryptWithNonce(
    plaintext : [Nat8],
    aad : [Nat8],
    key : [Nat8],
    nonce : [Nat8]
  ) : ([Nat8], [Nat8]) {
    assert (key.size() == 32);
    assert (nonce.size() == 12);

    let nonceNat32 = Array.tabulate<Nat32>(
      3,
      func(i) {
        let b0 = Nat32.fromNat(Nat8.toNat(nonce[i * 4]));
        let b1 = Nat32.fromNat(Nat8.toNat(nonce[i * 4 + 1])) << 8;
        let b2 = Nat32.fromNat(Nat8.toNat(nonce[i * 4 + 2])) << 16;
        let b3 = Nat32.fromNat(Nat8.toNat(nonce[i * 4 + 3])) << 24;
        b0 | b1 | b2 | b3
      }
    );

    let keyNat32 = Array.tabulate<Nat32>(
      8,
      func(i) {
        let b0 = Nat32.fromNat(Nat8.toNat(key[i * 4]));
        let b1 = Nat32.fromNat(Nat8.toNat(key[i * 4 + 1])) << 8;
        let b2 = Nat32.fromNat(Nat8.toNat(key[i * 4 + 2])) << 16;
        let b3 = Nat32.fromNat(Nat8.toNat(key[i * 4 + 3])) << 24;
        b0 | b1 | b2 | b3
      }
    );

    let (r, s) = Poly1305.generateKey(keyNat32, nonceNat32);
    let polyKey = Array.append<Nat8>(r, s);

    let ciphertext = Chacha20.encryptMultiBlock(keyNat32, 1, nonceNat32, plaintext);

    let aadPadding = calculatePadding(aad.size());
    let ciphertextPadding = calculatePadding(ciphertext.size());

    let authDataSize = aad.size() + aadPadding + ciphertext.size() + ciphertextPadding + 16;

    var authData = Array.init<Nat8>(authDataSize, 0x00);
    var pos = 0;

    for (i in Iter.range(0, aad.size() - 1)) {
      authData[pos] := aad[i];
      pos += 1
    };
    pos += aadPadding;

    for (i in Iter.range(0, ciphertext.size() - 1)) {
      authData[pos] := ciphertext[i];
      pos += 1
    };

    pos += ciphertextPadding;

    let aadLen = Poly1305.nat2LeBytes(aad.size(), 8);
    for (i in Iter.range(0, 7)) {
      authData[pos] := aadLen[i];
      pos += 1
    };
    let ciphertextLen = Poly1305.nat2LeBytes(ciphertext.size(), 8);
    for (i in Iter.range(0, 7)) {
      authData[pos] := ciphertextLen[i];
      pos += 1
    };

    let tag = Poly1305.mac(polyKey, Array.freeze(authData));

    (ciphertext, tag)
  };
  public func aeadEncrypt(
    plaintext : [Nat8],
    aad : [Nat8],
    key : [Nat8],
    iv : [Nat8],
    constant : [Nat8]
  ) : ([Nat8], [Nat8]) {
    // Construct nonce from constant and IV
    let nonce = constructNonce(constant, iv);

    // Call the core implementation
    aeadEncryptWithNonce(plaintext, aad, key, nonce)
  };

  public func aeadDecryptWithNonce(
    ciphertext : [Nat8],
    tag : [Nat8],
    aad : [Nat8],
    key : [Nat8],
    nonce : [Nat8]
  ) : ?[Nat8] {
    assert (key.size() == 32);
    assert (nonce.size() == 12);
    assert (tag.size() == 16);

    // Convert nonce to Nat32 array for ChaCha20
    let nonceNat32 = Array.tabulate<Nat32>(
      3,
      func(i) {
        let b0 = Nat32.fromNat(Nat8.toNat(nonce[i * 4]));
        let b1 = Nat32.fromNat(Nat8.toNat(nonce[i * 4 + 1])) << 8;
        let b2 = Nat32.fromNat(Nat8.toNat(nonce[i * 4 + 2])) << 16;
        let b3 = Nat32.fromNat(Nat8.toNat(nonce[i * 4 + 3])) << 24;
        return b0 | b1 | b2 | b3
      }
    );

    // Convert key to Nat32 array for ChaCha20
    let keyNat32 = Array.tabulate<Nat32>(
      8,
      func(i) {
        let b0 = Nat32.fromNat(Nat8.toNat(key[i * 4]));
        let b1 = Nat32.fromNat(Nat8.toNat(key[i * 4 + 1])) << 8;
        let b2 = Nat32.fromNat(Nat8.toNat(key[i * 4 + 2])) << 16;
        let b3 = Nat32.fromNat(Nat8.toNat(key[i * 4 + 3])) << 24;
        return b0 | b1 | b2 | b3
      }
    );

    let (r, s) = Poly1305.generateKey(keyNat32, nonceNat32);
    let polyKey = Array.append<Nat8>(r, s);

    let aadPadding = calculatePadding(aad.size());
    let ciphertextPadding = calculatePadding(ciphertext.size());

    // Calculate total length of authentication data
    let authDataSize = aad.size() + aadPadding + ciphertext.size() + ciphertextPadding + 16; // 8 bytes for AAD length + 8 bytes for 

    var authData = Array.init<Nat8>(authDataSize, 0x00);

    var pos = 0;

    // Copy AAD
    for (i in Iter.range(0, aad.size() - 1)) {
      authData[pos] := aad[i];
      pos += 1
    };

    pos += aadPadding;

    for (i in Iter.range(0, ciphertext.size() - 1)) {
      authData[pos] := ciphertext[i];
      pos += 1
    };

    pos += ciphertextPadding;

    let aadLen = Poly1305.nat2LeBytes(aad.size(), 8);
    for (i in Iter.range(0, 7)) {
      authData[pos] := aadLen[i];
      pos += 1
    };

    let ciphertextLen = Poly1305.nat2LeBytes(ciphertext.size(), 8);
    for (i in Iter.range(0, 7)) {
      authData[pos] := ciphertextLen[i];
      pos += 1
    };

    let expectedTag = Poly1305.mac(polyKey, Array.freeze(authData));

    let isValid = Poly1305.verify(tag, expectedTag);


    if (isValid) {
      let plaintext = Chacha20.encryptMultiBlock(keyNat32, 1, nonceNat32, ciphertext);
      ?plaintext
    } else {
      null
    }
  };
  public func aeadDecrypt(
    ciphertext : [Nat8],
    tag : [Nat8],
    aad : [Nat8],
    key : [Nat8],
    iv : [Nat8],
    constant : [Nat8]
  ) : ?[Nat8] {
    // Construct nonce from constant and IV
    let nonce = constructNonce(constant, iv);

    // Call the core implementation
    aeadDecryptWithNonce(ciphertext, tag, aad, key, nonce)
  }
}