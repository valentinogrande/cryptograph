# cryptograph

Educational Rust library for cryptography, bit manipulation, and number theory.

This crate is focused on understanding how algorithms work internally, with direct,
readable implementations.

## Current status

- Learning-focused, not production security-focused.
- Includes AES, DES, classical ciphers (Caesar, Affine), XOR stream cipher
  helpers, and LFSR utilities.
- `AES` supports single-block AES-128, AES-192, and AES-256 encryption and
  decryption, plus educational helpers for `SubBytes`, `ShiftRows`,
  `MixColumns`, and key expansion.
- `DES` includes both single-block encryption and decryption.
- Backward-compatible aliases are still available for older names such as
  `cryptography::cesar` and `streams_ciphers::generete_seed`.

## Installation

```bash
cargo add cryptograph
```

or in `Cargo.toml`:

```toml
[dependencies]
cryptograph = "0.1"
```

## Project structure

```text
cryptograph/
├── Cargo.toml
├── README.md
└── src/
    ├── bits.rs
    ├── lib.rs
    ├── cryptoanalysis/
    │   ├── mod.rs
    │   └── reverse_lfsr.rs
    ├── cryptography/
    │   ├── mod.rs
    │   ├── aes/
    │   │   ├── mod.rs
    │   │   ├── bite_sub.rs
    │   │   ├── decrypt.rs
    │   │   ├── encrypt.rs
    │   │   ├── key.rs
    │   │   ├── mix_column.rs
    │   │   └── shift_rows.rs
    │   ├── affine/
    │   │   ├── mod.rs
    │   │   ├── encrypt.rs
    │   │   └── decrypt.rs
    │   ├── caesar/
    │   │   ├── mod.rs
    │   │   ├── encrypt.rs
    │   │   └── decrypt.rs
    │   ├── des/
    │   │   ├── mod.rs
    │   │   ├── encrypt.rs
    │   │   ├── decrypt.rs
    │   │   ├── e_box.rs
    │   │   ├── f.rs
    │   │   ├── key.rs
    │   │   ├── permutation.rs
    │   │   └── s_box.rs
    │   └── streams_ciphers/
    │       ├── mod.rs
    │       ├── encrypt.rs
    │       ├── decrypt.rs
    │       └── generate_seed.rs
    ├── math/
    │   ├── mod.rs
    │   ├── euclides.rs
    │   ├── bezout.rs
    │   └── multiplicative_inverse.rs
    ├── pseudorandom_generator/
    │   ├── mod.rs
    │   └── lfsr.rs
    └── tools/
        ├── mod.rs
        └── flip_flop.rs
```

## Public API (full summary)

### `bits`

- `bits_to_bytes(bits: &[bool]) -> Result<Vec<u8>, Box<dyn Error>>`
- `bytes_to_bits(bytes: &[u8]) -> Vec<bool>`

### `math`

- `euclides::gcd<T>(a: T, b: T) -> T`
- `bezout::bezout<T>(a: T, b: T) -> (T, T)`
- `multiplicative_inverse::multiplicative_inverse<T>(a: T, m: T) -> Option<T>`

### `tools`

- `FlipFlop`
  - `new(flag: bool) -> Self`
  - `get(&self) -> bool`
  - `mutate(&mut self)`
  - `mutate_and_get(&mut self) -> bool`
  - `put(&mut self, f: bool)`
  - `set(&mut self, f: bool) -> &mut Self`

### `pseudorandom_generator`

- `Lfsr<F: Fn(&[FlipFlop]) -> bool>` (with public fields `ff` and `fb`)
  - `new(ff: Vec<FlipFlop>, rule: F) -> Self`
  - `rotate(&mut self) -> &mut FlipFlop`
  - `get(&self) -> &[FlipFlop]`
  - `calculate_possibilities(&self) -> usize`

### `cryptography::aes`

- Re-exported types:
  - `Aes`
    - `new(security: AesEncryptionType, x: u128) -> Self`
    - `encrypt(&self) -> u128`
    - `decrypt(y: u128, security: AesEncryptionType) -> u128`
  - `AesEncryptionType`
    - `Low(u128)` for AES-128
    - `Medium(U192)` for AES-192
    - `High(U256)` for AES-256
    - `bit_len(self) -> usize`
  - `U192`
    - `new(data: [u64; 3]) -> Self`
    - `from_be_bytes(bytes: [u8; 24]) -> Self`
    - `to_be_bytes(self) -> [u8; 24]`
  - `U256`
    - `new(data: [u64; 4]) -> Self`
    - `from_be_bytes(bytes: [u8; 32]) -> Self`
    - `to_be_bytes(self) -> [u8; 32]`
- Public helpers:
  - `bite_sub::SBOX`
  - `bite_sub::generate_inverse_table() -> [[u8; 16]; 16]`
  - `bite_sub::generate_affine_mapping_table() -> [u8; 8]`
  - `bite_sub::affine_mapping(...) -> [[u8; 16]; 16]`
  - `key::expand_key(security: AesEncryptionType) -> Vec<u128>`
  - `shift_rows::shift_rows(x: u128) -> u128`
  - `shift_rows::inverse_shift_rows(x: u128) -> u128`
  - `mix_column::mix_column(x: u128) -> u128`
  - `mix_column::inverse_mix_column(x: u128) -> u128`

### `cryptography::caesar`

- `encrypt::caesar_encrypt(msg: &str, shift: u8) -> Result<String, FromUtf8Error>`
- `decrypt::caesar_decrypt(msg: &str, shift: u8) -> Result<String, FromUtf8Error>`

### `cryptography::affine`

- `encrypt::affine_encrypt(x: &str, a: u8, b: u8) -> Result<String, FromUtf8Error>`
- `decrypt::affine_decrypt(y: &str, a: i32, b: u8) -> Result<String, FromUtf8Error>`

### `cryptography::streams_ciphers`

- `encrypt::stream_cipher_crypt(x: Vec<bool>, seed: Vec<bool>) -> Vec<bool>`
- `encrypt::fut_stream_cipher_encrypt(x: Vec<bool>, seed: Vec<bool>) -> impl StreamExt<Item = bool>`
- `decrypt::fut_stream_cipher_decrypt(y, seed) -> Vec<bool>` (async)
- `generate_seed::generate_seed(n: usize) -> Vec<bool>`

### `cryptography::des`

- `encrypt::Des`
  - `new(x: u64) -> Self`
  - `encrypt(&self, key: u64) -> u64`
  - `decrypt(y: u64, key: u64) -> u64`
- Public internal helpers:
  - `encrypt::round(...) -> (u32, u32)`
  - `e_box::e_box(bits: u32) -> u64`
  - `f::f(bits: u32, k: u64) -> u32`
  - `key::permutated_choice_1(key: u64) -> u64`
  - `key::permutated_choice_2(left: u32, right: u32) -> u64`
  - `key::key_shift(left_key: u32, right_key: u32, n: u8) -> (u32, u32)`
  - `permutation::initial_permutation(x: u64) -> u64`
  - `permutation::final_permutation(x: u64) -> u64`
  - `s_box::s_box(right_x: u64) -> u32`
  - `s_box::SBOXES`

### `cryptoanalysis`

- `reverse_lfsr::reverse_lfsr(...) -> Result<Vec<FlipFlop>, Box<dyn Error>>`

## Usage examples

### Bytes <-> bits conversion

```rust
use cryptograph::bits::{bits_to_bytes, bytes_to_bits};

let bytes = vec![0b1010_0001, 0b1111_0000];
let bits = bytes_to_bits(&bytes);
let restored = bits_to_bytes(&bits).unwrap();

assert_eq!(bytes, restored);
```

### Modular math

```rust
use cryptograph::math::{
    bezout::bezout,
    euclides::gcd,
    multiplicative_inverse::multiplicative_inverse,
};

assert_eq!(gcd(78, 30), 6);
assert_eq!(bezout(78, 30), (2, -5));
assert_eq!(multiplicative_inverse(3, 7), Some(5));
```

### AES block encryption and decryption

```rust
use cryptograph::cryptography::aes::{Aes, AesEncryptionType};

let key = AesEncryptionType::Low(0x000102030405060708090A0B0C0D0E0F);
let plaintext = 0x00112233445566778899AABBCCDDEEFF;

let ciphertext = Aes::new(key, plaintext).encrypt();
let recovered = Aes::decrypt(ciphertext, key);

assert_eq!(ciphertext, 0x69C4E0D86A7B0430D8CDB78070B4C55A);
assert_eq!(recovered, plaintext);
```

### Caesar cipher

```rust
use cryptograph::cryptography::caesar::decrypt::caesar_decrypt;
use cryptograph::cryptography::caesar::encrypt::caesar_encrypt;

let encrypted = caesar_encrypt("hello", 3).unwrap();
let decrypted = caesar_decrypt(&encrypted, 3).unwrap();

assert_eq!(decrypted, "hello");
```

### Affine cipher

```rust
use cryptograph::cryptography::affine::decrypt::affine_decrypt;
use cryptograph::cryptography::affine::encrypt::affine_encrypt;

let a: u8 = 3;
let b: u8 = 7;

let encrypted = affine_encrypt("hola", a, b).unwrap();
let decrypted = affine_decrypt(&encrypted, a as i32, b).unwrap();

assert_eq!(decrypted, "hola");
```

### Stream cipher (bitwise XOR)

```rust
use cryptograph::cryptography::streams_ciphers::encrypt::stream_cipher_crypt;

let x = vec![true, false, true, false];
let seed = vec![true, true, false, false];

let y = stream_cipher_crypt(x.clone(), seed.clone());
let restored = stream_cipher_crypt(y, seed);

assert_eq!(restored, x);
```

### Random seed for stream cipher

```rust
use cryptograph::cryptography::streams_ciphers::generate_seed::generate_seed;

let seed = generate_seed(128);
assert_eq!(seed.len(), 128);
```

### FlipFlop and LFSR

```rust
use cryptograph::pseudorandom_generator::lfsr::Lfsr;
use cryptograph::tools::flip_flop::FlipFlop;

let ff = vec![
    FlipFlop::new(true),
    FlipFlop::new(false),
    FlipFlop::new(true),
];

let mut lfsr = Lfsr::new(ff, |ff| ff[0].get() ^ ff[ff.len() - 1].get());

lfsr.rotate();
let state = lfsr.get();

assert_eq!(state.len(), 3);
assert_eq!(lfsr.calculate_possibilities(), 7);
```

### Reverse LFSR (cryptoanalysis)

```rust
use cryptograph::cryptoanalysis::reverse_lfsr::reverse_lfsr;
use cryptograph::tools::flip_flop::FlipFlop;

let y = vec![
    FlipFlop::new(true),
    FlipFlop::new(false),
    FlipFlop::new(true),
];

let x = vec![
    FlipFlop::new(false),
    FlipFlop::new(true),
    FlipFlop::new(false),
];

let result = reverse_lfsr(y, 3, x, |ff| ff[0].get() ^ ff[ff.len() - 1].get());
assert!(result.is_ok());
```

### DES encrypt (64-bit block)

```rust
use cryptograph::cryptography::des::encrypt::Des;

let plaintext = 0x0123_4567_89AB_CDEFu64;
let key = 0x1334_5779_9BBC_DFF1u64;

let des = Des::new(plaintext);
let encrypted = des.encrypt(key);

println!("{encrypted:016X}");
```

## Known errors, panics, and limitations

- `math::euclides::gcd` may panic if `b == 0` (division/modulo by zero).
- `affine_decrypt` uses `unwrap()` on the modular inverse and may panic
  if `a` is not invertible modulo 256.
- `stream_cipher_crypt` and `fut_stream_cipher_encrypt` use `assert_eq!`
  to enforce matching message/seed length.
- `reverse_lfsr` returns an error if `x.len() < n`.
- AES and DES operate on a single block only; block modes and padding are not included.

## Security

This project is educational only.

- Not audited
- Not constant-time
- Not production-safe

If you need real-world cryptography, use audited libraries
(for example RustCrypto crates or `ring`).

## Local development

```bash
cargo test
cargo clippy --all-targets --all-features
cargo doc --no-deps --open
```

## License

MIT
