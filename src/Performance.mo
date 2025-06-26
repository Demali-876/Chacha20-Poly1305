// src/performance.mo
import IC "mo:base/ExperimentalInternetComputer";
import Chacha20 "Chacha20";
import Poly1305 "Poly1305";
import Chacha20_poly1305 "lib";
import Nat8 "mo:base/Nat8";
import Nat "mo:base/Nat";
import Int64 "mo:base/Int64";
import Nat64 "mo:base/Nat64";
import Array "mo:base/Array";
import Float "mo:base/Float";

actor Performance {

  func generateRandomBytes(size : Nat) : [Nat8] {
    Array.tabulate<Nat8>(size, func(i) = Nat8.fromNat((i * 31 + 17) % 256));
  };

  let key32Bytes = generateRandomBytes(32);
  let nonce12Bytes = generateRandomBytes(12);
  let key = Chacha20.keyFromBytes(key32Bytes);
  let nonce = Chacha20.nonceFromBytes(nonce12Bytes);

  // Core operations
  public func quarterRoundInstructions() : async Nat64 {
    IC.countInstructions(
      func() {
        let mut : [var Nat32] = [var 0x11111111, 0x01020304, 0x9b8d6f43, 0x01234567];
        Chacha20.quarterRound(mut, 0, 1, 2, 3);
      }
    );
  };

  public func chachaBlockInstructions() : async Nat64 {
    IC.countInstructions(
      func() {
        let _ = Chacha20.chachaBlock(key, 0, nonce);
      }
    );
  };

  public func keyFromBytesInstructions() : async Nat64 {
    IC.countInstructions(
      func() {
        let _ = Chacha20.keyFromBytes(key32Bytes);
      }
    );
  };

  public func nonceFromBytesInstructions() : async Nat64 {
    IC.countInstructions(
      func() {
        let _ = Chacha20.nonceFromBytes(nonce12Bytes);
      }
    );
  };

  // ChaCha20 encryption by size
  public func chacha20Instructions(size : Nat) : async Nat64 {
    let plaintext = generateRandomBytes(size);
    IC.countInstructions(
      func() {
        let _ = Chacha20.encryptMultiBlock(key, 0, nonce, plaintext);
      }
    );
  };

  // Poly1305 MAC by size
  public func poly1305Instructions(size : Nat) : async Nat64 {
    let message = generateRandomBytes(size);
    IC.countInstructions(
      func() {
        let _ = Poly1305.mac(key32Bytes, message);
      }
    );
  };

  // AEAD by size
  public func aeadInstructions(size : Nat) : async Nat64 {
    let plaintext = generateRandomBytes(size);
    let aad = generateRandomBytes(13);
    let iv = generateRandomBytes(8);
    let constant = generateRandomBytes(4);

    IC.countInstructions(
      func() {
        let _ = Chacha20_poly1305.aeadEncrypt(plaintext, aad, key32Bytes, iv, constant);
      }
    );
  };

  // Benchmark specific sizes
  public func benchmark16Bytes() : async {
    chacha20 : Nat64;
    poly1305 : Nat64;
    aead : Nat64;
    instructionsPerByte : {
      chacha20 : Float;
      poly1305 : Float;
      aead : Float;
    };
  } {
    let chachaInstr = await chacha20Instructions(16);
    let polyInstr = await poly1305Instructions(16);
    let aeadInstr = await aeadInstructions(16);

    {
      chacha20 = chachaInstr;
      poly1305 = polyInstr;
      aead = aeadInstr;
      instructionsPerByte = {
        chacha20 = Float.fromInt64(Int64.fromNat64(chachaInstr)) / 16.0;
        poly1305 = Float.fromInt64(Int64.fromNat64(polyInstr)) / 16.0;
        aead = Float.fromInt64(Int64.fromNat64(aeadInstr)) / 16.0;
      };
    };
  };

  public func benchmark64Bytes() : async {
    chacha20 : Nat64;
    poly1305 : Nat64;
    aead : Nat64;
    instructionsPerByte : {
      chacha20 : Float;
      poly1305 : Float;
      aead : Float;
    };
  } {
    let chachaInstr = await chacha20Instructions(64);
    let polyInstr = await poly1305Instructions(64);
    let aeadInstr = await aeadInstructions(64);

    {
      chacha20 = chachaInstr;
      poly1305 = polyInstr;
      aead = aeadInstr;
      instructionsPerByte = {
        chacha20 = Float.fromInt64(Int64.fromNat64(chachaInstr)) / 64.0;
        poly1305 = Float.fromInt64(Int64.fromNat64(polyInstr)) / 64.0;
        aead = Float.fromInt64(Int64.fromNat64(aeadInstr)) / 64.0;
      };
    };
  };

  public func benchmark1024Bytes() : async {
    chacha20 : Nat64;
    poly1305 : Nat64;
    aead : Nat64;
    instructionsPerByte : {
      chacha20 : Float;
      poly1305 : Float;
      aead : Float;
    };
  } {
    let chachaInstr = await chacha20Instructions(1024);
    let polyInstr = await poly1305Instructions(1024);
    let aeadInstr = await aeadInstructions(1024);

    {
      chacha20 = chachaInstr;
      poly1305 = polyInstr;
      aead = aeadInstr;
      instructionsPerByte = {
        chacha20 = Float.fromInt64(Int64.fromNat64(chachaInstr)) / 1024.0;
        poly1305 = Float.fromInt64(Int64.fromNat64(polyInstr)) / 1024.0;
        aead = Float.fromInt64(Int64.fromNat64(aeadInstr)) / 1024.0;
      };
    };
  };

  public func benchmark4096Bytes() : async {
    chacha20 : Nat64;
    poly1305 : Nat64;
    aead : Nat64;
    instructionsPerByte : {
      chacha20 : Float;
      poly1305 : Float;
      aead : Float;
    };
  } {
    let chachaInstr = await chacha20Instructions(4096);
    let polyInstr = await poly1305Instructions(4096);
    let aeadInstr = await aeadInstructions(4096);

    {
      chacha20 = chachaInstr;
      poly1305 = polyInstr;
      aead = aeadInstr;
      instructionsPerByte = {
        chacha20 = Float.fromInt64(Int64.fromNat64(chachaInstr)) / 4096.0;
        poly1305 = Float.fromInt64(Int64.fromNat64(polyInstr)) / 4096.0;
        aead = Float.fromInt64(Int64.fromNat64(aeadInstr)) / 4096.0;
      };
    };
  };

  // TLS record size
  public func benchmarkTLSRecord() : async {
    size : Nat;
    chacha20 : Nat64;
    poly1305 : Nat64;
    aead : Nat64;
    instructionsPerByte : {
      chacha20 : Float;
      poly1305 : Float;
      aead : Float;
    };
  } {
    let size = 1400; // Typical TLS record size
    let chachaInstr = await chacha20Instructions(size);
    let polyInstr = await poly1305Instructions(size);
    let aeadInstr = await aeadInstructions(size);

    {
      size = size;
      chacha20 = chachaInstr;
      poly1305 = polyInstr;
      aead = aeadInstr;
      instructionsPerByte = {
        chacha20 = Float.fromInt64(Int64.fromNat64(chachaInstr)) / Float.fromInt(size);
        poly1305 = Float.fromInt64(Int64.fromNat64(polyInstr)) / Float.fromInt(size);
        aead = Float.fromInt64(Int64.fromNat64(aeadInstr)) / Float.fromInt(size);
      };
    };
  };

  // Core operations summary
  public func coreOperationsBenchmark() : async {
    quarterRound : Nat64;
    chachaBlock : Nat64;
    keyFromBytes : Nat64;
    nonceFromBytes : Nat64;
  } {
    {
      quarterRound = await quarterRoundInstructions();
      chachaBlock = await chachaBlockInstructions();
      keyFromBytes = await keyFromBytesInstructions();
      nonceFromBytes = await nonceFromBytesInstructions();
    };
  };

  // Performance comparison for 1KB (most common size)
  public func performanceComparison() : async {
    size : Nat;
    chacha20Instructions : Nat64;
    poly1305Instructions : Nat64;
    aeadInstructions : Nat64;
    aeadOverhead : Nat64;
    overheadPercentage : Float;
    instructionsPerByte : {
      chacha20 : Float;
      poly1305 : Float;
      aead : Float;
    };
  } {
    let size = 1024;
    let chachaInstr = await chacha20Instructions(size);
    let polyInstr = await poly1305Instructions(size);
    let aeadInstr = await aeadInstructions(size);

    let overhead = aeadInstr - chachaInstr - polyInstr;
    let overheadPct = Float.fromInt64(Int64.fromNat64(overhead)) / Float.fromInt64(Int64.fromNat64(chachaInstr + polyInstr)) * 100.0;

    {
      size = size;
      chacha20Instructions = chachaInstr;
      poly1305Instructions = polyInstr;
      aeadInstructions = aeadInstr;
      aeadOverhead = overhead;
      overheadPercentage = overheadPct;
      instructionsPerByte = {
        chacha20 = Float.fromInt64(Int64.fromNat64(chachaInstr)) / Float.fromInt(size);
        poly1305 = Float.fromInt64(Int64.fromNat64(polyInstr)) / Float.fromInt(size);
        aead = Float.fromInt64(Int64.fromNat64(aeadInstr)) / Float.fromInt(size);
      };
    };
  };

  // Quick single measurement
  public func quickBench(size : Nat) : async {
    size : Nat;
    chacha20 : { total : Nat64; perByte : Float };
    poly1305 : { total : Nat64; perByte : Float };
    aead : { total : Nat64; perByte : Float };
  } {
    let chachaInstr = await chacha20Instructions(size);
    let polyInstr = await poly1305Instructions(size);
    let aeadInstr = await aeadInstructions(size);

    {
      size = size;
      chacha20 = {
        total = chachaInstr;
        perByte = Float.fromInt64(Int64.fromNat64(chachaInstr)) / Float.fromInt(size);
      };
      poly1305 = {
        total = polyInstr;
        perByte = Float.fromInt64(Int64.fromNat64(polyInstr)) / Float.fromInt(size);
      };
      aead = {
        total = aeadInstr;
        perByte = Float.fromInt64(Int64.fromNat64(aeadInstr)) / Float.fromInt(size);
      };
    };
  };
};
