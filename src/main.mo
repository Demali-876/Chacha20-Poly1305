import Chacha20 "Chacha20";
import Debug "mo:base/Debug";
import Blob "mo:base/Blob";
import Poly1305 "Poly1305";
import Chacha20_poly1305 "Chacha20_Poly1305";
import Nat32 "mo:base/Nat32";
import Nat8 "mo:base/Nat8";
import Nat "mo:base/Nat";
import Array "mo:base/Array";
import Text "mo:base/Text";
import Iter "mo:base/Iter";

actor {
  // Test 1: QuarterRound operation
  // Based on RFC 8439 Section 2.1.1
  public func testQuarterRound() : async Text {
    let mut : [var Nat32] = [var 0x11111111, 0x01020304, 0x9b8d6f43, 0x01234567];

    // Apply quarter round
    Chacha20.quarterRound(mut, 0, 1, 2, 3);

    // Expected results
    let expected : [Nat32] = [0xea2a92f4, 0xcb1cf8ce, 0x4581472e, 0x5881c4bb];

    let result = Array.freeze<Nat32>(mut);
    // Validate results
    var success = true;
    for (i in Iter.range(0, 3)) {
      if (result[i] != expected[i]) {
        success := false;
        Debug.print("At index " # Nat.toText(i) # " expected: " # Nat32.toText(expected[i]) # ", got: " # Nat32.toText(mut[i]))
      }
    };

    if (success) {
      return "Quarter Round Test: PASSED"
    } else {
      return "Quarter Round Test: FAILED"
    }
  };

  // Test 2: ChaCha20 Block Function
  // Based on RFC 8439 Appendix A.1 Test Vector #1
  public func testChaChaBlock() : async Text {
    // Setting up the test vector
    let key : [Nat32] = Array.tabulate<Nat32>(8, func(i) = 0);
    let nonce : [Nat32] = Array.tabulate<Nat32>(3, func(i) = 0);
    let counter : Nat32 = 0;

    // Get the keystream block
    let keystream = Chacha20.chachaBlock(key, counter, nonce);

    // Expected keystream (first 64 bytes from RFC 8439 Appendix A.1 Test Vector #1)
    let expected : [Nat8] = [
      0x76,
      0xb8,
      0xe0,
      0xad,
      0xa0,
      0xf1,
      0x3d,
      0x90,
      0x40,
      0x5d,
      0x6a,
      0xe5,
      0x53,
      0x86,
      0xbd,
      0x28,
      0xbd,
      0xd2,
      0x19,
      0xb8,
      0xa0,
      0x8d,
      0xed,
      0x1a,
      0xa8,
      0x36,
      0xef,
      0xcc,
      0x8b,
      0x77,
      0x0d,
      0xc7,
      0xda,
      0x41,
      0x59,
      0x7c,
      0x51,
      0x57,
      0x48,
      0x8d,
      0x77,
      0x24,
      0xe0,
      0x3f,
      0xb8,
      0xd8,
      0x4a,
      0x37,
      0x6a,
      0x43,
      0xb8,
      0xf4,
      0x15,
      0x18,
      0xa1,
      0x1c,
      0xc3,
      0x87,
      0xb6,
      0x69,
      0xb2,
      0xee,
      0x65,
      0x86
    ];

    // Validate results
    var success = true;

    if (keystream.size() != expected.size()) {
      Debug.print("Keystream length mismatch. Expected: " # Nat.toText(expected.size()) # ", got: " # Nat.toText(keystream.size()));
      success := false
    } else {
      for (i in Iter.range(0, expected.size() - 1)) {
        if (keystream[i] != expected[i]) {
          success := false;
          Debug.print("At index " # Nat.toText(i) # " expected: " # Nat8.toText(expected[i]) # ", got: " # Nat8.toText(keystream[i]))
        }
      }
    };

    if (success) {
      return "ChaCha20 Block Test: PASSED"
    } else {
      return "ChaCha20 Block Test: FAILED"
    }
  };

  // Test 3: Simple encryption/decryption test
  public func testEncryption() : async Text {
    // Create a simple plaintext
    let plaintext : [Nat8] = [
      0x4c,
      0x61,
      0x64,
      0x69,
      0x65,
      0x73,
      0x20,
      0x61,
      0x6e,
      0x64,
      0x20,
      0x47,
      0x65,
      0x6e,
      0x74,
      0x6c,
      0x65,
      0x6d,
      0x65,
      0x6e,
      0x20,
      0x6f,
      0x66,
      0x20,
      0x74,
      0x68,
      0x65,
      0x20,
      0x63,
      0x6c,
      0x61,
      0x73,
      0x73,
      0x20,
      0x6f,
      0x66,
      0x20,
      0x27,
      0x39,
      0x39,
      0x3a,
      0x20,
      0x49,
      0x66,
      0x20,
      0x49,
      0x20,
      0x63,
      0x6f,
      0x75,
      0x6c,
      0x64,
      0x20,
      0x6f,
      0x66,
      0x66,
      0x65,
      0x72,
      0x20,
      0x79,
      0x6f,
      0x75,
      0x20,
      0x6f
    ]; // "Ladies and Gentlemen of the class of '99: If I could offer you o"

    // Set up a simple key and nonce
    let keyBytes : [Nat8] = Array.tabulate<Nat8>(32, func(i) = Nat8.fromNat(i));
    let nonceBytes : [Nat8] = Array.tabulate<Nat8>(12, func(i) = 0);

    let key = Chacha20.keyFromBytes(keyBytes);
    let nonce = Chacha20.nonceFromBytes(nonceBytes);
    let counter : Nat32 = 1;

    // Encrypt
    let ciphertext = Chacha20.encryptMultiBlock(key, counter, nonce, plaintext);

    // Decrypt (which is just encrypting again in ChaCha20)
    let decrypted = Chacha20.encryptMultiBlock(key, counter, nonce, ciphertext);

    // Validate results
    var success = true;

    if (decrypted.size() != plaintext.size()) {
      Debug.print("Decrypted length mismatch. Expected: " # Nat.toText(plaintext.size()) # ", got: " # Nat.toText(decrypted.size()));
      success := false
    } else {
      for (i in Iter.range(0, plaintext.size() - 1)) {
        if (decrypted[i] != plaintext[i]) {
          success := false;
          Debug.print("At index " # Nat.toText(i) # " expected: " # Nat8.toText(plaintext[i]) # ", got: " # Nat8.toText(decrypted[i]))
        }
      }
    };

    if (success) {
      return "Encryption/Decryption Test: PASSED"
    } else {
      return "Encryption/Decryption Test: FAILED"
    }
  };

  // Test 4: Test Vector #2 from RFC 8439 Appendix A.2
public func testRFC8439Vector2() : async Text {
  // Key: as defined in RFC 8439 section 2.4.2
  let keyBytes : [Nat8] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
  ];

  // Nonce: from RFC 8439 section 2.4.2
  let nonceBytes : [Nat8] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00];

  // Initial counter = 1 (as specified in RFC 8439)
  let counter : Nat32 = 1;

  // Plain text (from RFC 8439 section 2.4.2 - the "Sunscreen" text)
  let plaintext : [Nat8] = [
    0x4c, 0x61, 0x64, 0x69, 0x65, 0x73, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x47, 0x65, 0x6e, 0x74, 0x6c,
    0x65, 0x6d, 0x65, 0x6e, 0x20, 0x6f, 0x66, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x61, 0x73,
    0x73, 0x20, 0x6f, 0x66, 0x20, 0x27, 0x39, 0x39, 0x3a, 0x20, 0x49, 0x66, 0x20, 0x49, 0x20, 0x63,
    0x6f, 0x75, 0x6c, 0x64, 0x20, 0x6f, 0x66, 0x66, 0x65, 0x72, 0x20, 0x79, 0x6f, 0x75, 0x20, 0x6f,
    0x6e, 0x6c, 0x79, 0x20, 0x6f, 0x6e, 0x65, 0x20, 0x74, 0x69, 0x70, 0x20, 0x66, 0x6f, 0x72, 0x20,
    0x74, 0x68, 0x65, 0x20, 0x66, 0x75, 0x74, 0x75, 0x72, 0x65, 0x2c, 0x20, 0x73, 0x75, 0x6e, 0x73,
    0x63, 0x72, 0x65, 0x65, 0x6e, 0x20, 0x77, 0x6f, 0x75, 0x6c, 0x64, 0x20, 0x62, 0x65, 0x20, 0x69,
    0x74, 0x2e
  ];

  // Expected ciphertext (from RFC 8439 section 2.4.2)
  let expected : [Nat8] = [
    0x6e, 0x2e, 0x35, 0x9a, 0x25, 0x68, 0xf9, 0x80, 0x41, 0xba, 0x07, 0x28, 0xdd, 0x0d, 0x69, 0x81,
    0xe9, 0x7e, 0x7a, 0xec, 0x1d, 0x43, 0x60, 0xc2, 0x0a, 0x27, 0xaf, 0xcc, 0xfd, 0x9f, 0xae, 0x0b,
    0xf9, 0x1b, 0x65, 0xc5, 0x52, 0x47, 0x33, 0xab, 0x8f, 0x59, 0x3d, 0xab, 0xcd, 0x62, 0xb3, 0x57,
    0x16, 0x39, 0xd6, 0x24, 0xe6, 0x51, 0x52, 0xab, 0x8f, 0x53, 0x0c, 0x35, 0x9f, 0x08, 0x61, 0xd8,
    0x07, 0xca, 0x0d, 0xbf, 0x50, 0x0d, 0x6a, 0x61, 0x56, 0xa3, 0x8e, 0x08, 0x8a, 0x22, 0xb6, 0x5e,
    0x52, 0xbc, 0x51, 0x4d, 0x16, 0xcc, 0xf8, 0x06, 0x81, 0x8c, 0xe9, 0x1a, 0xb7, 0x79, 0x37, 0x36,
    0x5a, 0xf9, 0x0b, 0xbf, 0x74, 0xa3, 0x5b, 0xe6, 0xb4, 0x0b, 0x8e, 0xed, 0xf2, 0x78, 0x5e, 0x42,
    0x87, 0x4d
  ];

  let key = Chacha20.keyFromBytes(keyBytes);
  let nonce = Chacha20.nonceFromBytes(nonceBytes);

  // Encrypt
  let ciphertext = Chacha20.encryptMultiBlock(key, counter, nonce, plaintext);

  // Validate results
  var success = true;

  if (ciphertext.size() != expected.size()) {
    Debug.print("Ciphertext length mismatch. Expected: " # Nat.toText(expected.size()) # ", got: " # Nat.toText(ciphertext.size()));
    success := false
  } else {
    for (i in Iter.range(0, expected.size() - 1)) {
      if (ciphertext[i] != expected[i]) {
        success := false;
        Debug.print("At index " # Nat.toText(i) # " expected: " # Nat8.toText(expected[i]) # ", got: " # Nat8.toText(ciphertext[i]))
      }
    }
  };

  if (success) {
    return "RFC 8439 Test Vector #2: PASSED"
  } else {
    return "RFC 8439 Test Vector #2: FAILED"
  }
};
  public func testRFC8439() : async Text {
    // Test Vector from RFC 8439
    let key : [Nat8] = [
      0x85,
      0xd6,
      0xbe,
      0x78,
      0x57,
      0x55,
      0x6d,
      0x33,
      0x7f,
      0x44,
      0x52,
      0xfe,
      0x42,
      0xd5,
      0x06,
      0xa8,
      0x01,
      0x03,
      0x80,
      0x8a,
      0xfb,
      0x0d,
      0xb2,
      0xfd,
      0x4a,
      0xbf,
      0xf6,
      0xaf,
      0x41,
      0x49,
      0xf5,
      0x1b
    ];

    let message = "Cryptographic Forum Research Group";
    let messageBytes = Blob.toArray(Text.encodeUtf8(message));

    let expectedTag : [Nat8] = [
      0xa8,
      0x06,
      0x1d,
      0xc1,
      0x30,
      0x51,
      0x36,
      0xc6,
      0xc2,
      0x2b,
      0x8b,
      0xaf,
      0x0c,
      0x01,
      0x27,
      0xa9
    ];

    let computedTag = Poly1305.mac(key, messageBytes);

    Debug.print("RFC 8439 Test Vector:");
    Debug.print("Key: " # Poly1305.bytesToHex(key));
    Debug.print("Message: " # message);
    Debug.print("Expected tag: " # Poly1305.bytesToHex(expectedTag));
    Debug.print("Computed tag: " # Poly1305.bytesToHex(computedTag));

    let isValid = Poly1305.verify(computedTag, expectedTag);

    if (isValid) {
      return "PASS"
    } else {
      return "FAIL"
    }
  };

  // Run all tests
  public func runAllTests() : async Text {
    let test1 = await testQuarterRound();
    let test2 = await testChaChaBlock();
    let test3 = await testEncryption();
    let test6 = await testRFC8439();
    let test4 = await testRFC8439Vector2();
    let test5 = await testAEAD_RFC8439();

    return "\n=== ChaCha20 Test Results ===\n" #
    test1 # "\n" #
    test2 # "\n" #
    test3 # "\n" #
    test4 # "\n" #
    test5 # "\n" #
    test6
  };
  public func testAEAD_RFC8439() : async Text {
    // Inputs from RFC 8439 section 2.8.2
    
    // Plaintext (the "Ladies and Gentlemen" quote)
    let plaintext : [Nat8] = [
      0x4c, 0x61, 0x64, 0x69, 0x65, 0x73, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x47, 0x65, 0x6e, 0x74, 0x6c,
      0x65, 0x6d, 0x65, 0x6e, 0x20, 0x6f, 0x66, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x61, 0x73,
      0x73, 0x20, 0x6f, 0x66, 0x20, 0x27, 0x39, 0x39, 0x3a, 0x20, 0x49, 0x66, 0x20, 0x49, 0x20, 0x63,
      0x6f, 0x75, 0x6c, 0x64, 0x20, 0x6f, 0x66, 0x66, 0x65, 0x72, 0x20, 0x79, 0x6f, 0x75, 0x20, 0x6f,
      0x6e, 0x6c, 0x79, 0x20, 0x6f, 0x6e, 0x65, 0x20, 0x74, 0x69, 0x70, 0x20, 0x66, 0x6f, 0x72, 0x20,
      0x74, 0x68, 0x65, 0x20, 0x66, 0x75, 0x74, 0x75, 0x72, 0x65, 0x2c, 0x20, 0x73, 0x75, 0x6e, 0x73,
      0x63, 0x72, 0x65, 0x65, 0x6e, 0x20, 0x77, 0x6f, 0x75, 0x6c, 0x64, 0x20, 0x62, 0x65, 0x20, 0x69,
      0x74, 0x2e
    ];
    
    // AAD
    let aad : [Nat8] = [
      0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7
    ];
    
    // Key
    let key : [Nat8] = [
      0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
      0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f
    ];
    
    // IV
    let iv : [Nat8] = [
      0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47
    ];
    
    // 32-bit fixed-common part (constant)
    let constant : [Nat8] = [
      0x07, 0x00, 0x00, 0x00
    ];
    
    // Expected results from RFC 8439
    let expectedCiphertext : [Nat8] = [
      0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef, 0x7e, 0xc2,
      0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe, 0xa9, 0xe2, 0xb5, 0xa7, 0x36, 0xee, 0x62, 0xd6,
      0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12, 0x82, 0xfa, 0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b,
      0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29, 0x05, 0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36,
      0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77, 0x8b, 0x8c, 0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58,
      0xfa, 0xb3, 0x24, 0xe4, 0xfa, 0xd6, 0x75, 0x94, 0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc,
      0x3f, 0xf4, 0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d, 0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b,
      0x61, 0x16
    ];
    
    let expectedTag : [Nat8] = [
      0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a, 0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60, 0x06, 0x91
    ];
    
    // Encrypt using our AEAD implementation
    let (ciphertext, tag) = Chacha20_poly1305.aeadEncrypt(plaintext, aad, key, iv, constant);
    
    Debug.print("Encryption Test:");
    Debug.print("Plaintext length: " # Nat.toText(plaintext.size()));
    Debug.print("Ciphertext length: " # Nat.toText(ciphertext.size()));
    Debug.print("Expected tag: " # Poly1305.bytesToHex(expectedTag));
    Debug.print("Computed tag: " # Poly1305.bytesToHex(tag));
    
    // Validate ciphertext
    var ciphertextCorrect = true;
    if (ciphertext.size() != expectedCiphertext.size()) {
      Debug.print("Ciphertext length mismatch. Expected: " # Nat.toText(expectedCiphertext.size()) # 
                  ", got: " # Nat.toText(ciphertext.size()));
      ciphertextCorrect := false;
    } else {
      label l for (i in Iter.range(0, expectedCiphertext.size() - 1)) {
        if (ciphertext[i] != expectedCiphertext[i]) {
          ciphertextCorrect := false;
          Debug.print("Ciphertext mismatch at index " # Nat.toText(i) # 
                      ". Expected: " # Nat8.toText(expectedCiphertext[i]) # 
                      ", got: " # Nat8.toText(ciphertext[i]));
          break l;
        };
      };
    };
    
    // Validate tag
    var tagCorrect = true;
    if (tag.size() != expectedTag.size()) {
      Debug.print("Tag length mismatch. Expected: " # Nat.toText(expectedTag.size()) # 
                  ", got: " # Nat.toText(tag.size()));
      tagCorrect := false;
    } else {
      label l2 for (i in Iter.range(0, expectedTag.size() - 1)) {
        if (tag[i] != expectedTag[i]) {
          tagCorrect := false;
          Debug.print("Tag mismatch at index " # Nat.toText(i) # 
                      ". Expected: " # Nat8.toText(expectedTag[i]) # 
                      ", got: " # Nat8.toText(tag[i]));
          break l2;
        };
      };
    };
    
    // Test decryption
    let decryptResult = Chacha20_poly1305.aeadDecrypt(ciphertext, tag, aad, key, iv, constant);
    
    var decryptionCorrect = switch (decryptResult) {
      case (null) {
        Debug.print("Decryption failed - tag verification error");
        false;
      };
      case (?decrypted) {
        var correct = true;
        if (decrypted.size() != plaintext.size()) {
          Debug.print("Decrypted length mismatch. Expected: " # Nat.toText(plaintext.size()) # 
                      ", got: " # Nat.toText(decrypted.size()));
          correct := false;
        } else {
          label l3 for (i in Iter.range(0, plaintext.size() - 1)) {
            if (decrypted[i] != plaintext[i]) {
              correct := false;
              Debug.print("Decrypted mismatch at index " # Nat.toText(i) # 
                          ". Expected: " # Nat8.toText(plaintext[i]) # 
                          ", got: " # Nat8.toText(decrypted[i]));
              break l3;
            };
          };
        };
        correct;
      };
    };
    
    // Overall test result
    if (ciphertextCorrect and tagCorrect and decryptionCorrect) {
      return "AEAD Test: PASSED";
    } else {
      return "AEAD Test: FAILED (ciphertext: " # 
             (if (ciphertextCorrect) "✓" else "✗") # ", tag: " #
             (if (tagCorrect) "✓" else "✗") # ", decryption: " #
             (if (decryptionCorrect) "✓" else "✗") # ")";
    };
  };
}