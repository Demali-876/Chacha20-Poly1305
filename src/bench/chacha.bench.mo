// bench/chacha20.bench.mo
import Bench "mo:bench";
import Chacha20 "../Chacha20";
import Poly1305 "../Poly1305";
import Chacha20_poly1305 "../lib";
import Nat8 "mo:base/Nat8";
import Nat "mo:base/Nat";
import Array "mo:base/Array";

module {
  public func init() : Bench.Bench {
    let bench = Bench.Bench();

    // Generate test data
    func generateRandomBytes(size : Nat) : [Nat8] {
      Array.tabulate<Nat8>(size, func(i) = Nat8.fromNat((i * 31 + 17) % 256));
    };

    let key32Bytes = generateRandomBytes(32);
    let nonce12Bytes = generateRandomBytes(12);
    let key = Chacha20.keyFromBytes(key32Bytes);
    let nonce = Chacha20.nonceFromBytes(nonce12Bytes);

    bench.name("ChaCha20-Poly1305 Industry Benchmark");
    bench.description("Performance across message sizes following industry standards");

    // Message sizes based on real-world usage
    bench.rows(["ChaCha20-Only", "Poly1305-Only", "AEAD-Full"]);
    bench.cols(["16", "64", "256", "1024", "1400", "4096", "16384"]);

    bench.runner(func(row, col) {
      switch (Nat.fromText(col)) {
        case (?size) {
          let plaintext = generateRandomBytes(size);
          
          if (row == "ChaCha20-Only") {
            // Pure ChaCha20 encryption performance
            let _ = Chacha20.encryptMultiBlock(key, 0, nonce, plaintext);
          }
          else if (row == "Poly1305-Only") {
            // Pure Poly1305 MAC performance
            let _ = Poly1305.mac(key32Bytes, plaintext);
          }
          else if (row == "AEAD-Full") {
            // Complete AEAD operation (encryption + authentication)
            let aad = generateRandomBytes(13); // TLS record overhead
            let iv = generateRandomBytes(8);
            let constant = generateRandomBytes(4);
            let _ = Chacha20_poly1305.aeadEncrypt(plaintext, aad, key32Bytes, iv, constant);
          };
        };
        case (null) {};
      };
    });

    bench;
  };
};