# 🔐 Cryptograph

> Educational cryptography library written in Rust

---

## 📦 Overview

`cryptograph` is a Rust library that implements fundamental concepts from **cryptography**, **bit manipulation**, and **number theory**, with a focus on **clarity**, **learning**, and **low-level understanding**.

This crate is designed for:

- Learning cryptography
- Understanding cipher construction
- Practicing bitwise programming in Rust
- Exploring pseudorandom generators

---

## 🚀 Features

### 🔑 Cryptography

- Caesar Cipher
- Affine Cipher
- Stream Cipher (XOR-based)
- DES (Data Encryption Standard)

### 🔄 Pseudorandom Generators

- **FlipFlop** — 1-bit memory cell
- **LFSR** — Linear Feedback Shift Register

### ⚙️ Bit Manipulation

- `bytes ↔ bits` conversion
- Bitwise utilities

### 🧠 Mathematics

- Euclidean Algorithm (GCD)
- Extended Euclidean Algorithm (Bézout)
- Modular Multiplicative Inverse

---

## 📥 Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
cryptograph = "0.1"
```

---

## 🧪 Usage

### Caesar Cipher

```rust
use cryptograph::cryptography::cesar::encrypt;

let encrypted = encrypt("HELLO", 3);
println!("{}", encrypted); // KHOOR
```

---

### Affine Cipher

```rust
use cryptograph::cryptography::affine::encrypt;

let encrypted = encrypt("HELLO", 5, 8);
println!("{}", encrypted);
```

---

### Stream Cipher (XOR)

```rust
use cryptograph::cryptography::streams_ciphers::encrypt;

let msg = b"hello";
let key = b"key";

let encrypted = encrypt(msg, key);
let decrypted = encrypt(&encrypted, key); // XOR is symmetric

assert_eq!(msg, decrypted);
```

---

### Bit Manipulation

```rust
use cryptograph::utils::bits::{bytes_to_bits, bits_to_bytes};

let bytes = vec![0b10100001];

let bits = bytes_to_bits(&bytes);
let reconstructed = bits_to_bytes(&bits).unwrap();

assert_eq!(bytes, reconstructed);
```

---

### Modular Inverse

```rust
use cryptograph::math::multiplicative_inverse;

let inv = multiplicative_inverse(5, 7).unwrap();

assert_eq!((5 * inv) % 7, 1);
```

### LFSR

```rust
// Create a 4-bit LFSR
let ff = vec![
    FlipFlop::new(true),
    FlipFlop::new(false),
    FlipFlop::new(true),
    FlipFlop::new(false),
];

// Initialize the LFSR
let mut lfsr = Lsfr::new(ff);

// Rotate the LFSR (advance one step)
lfsr.rotate();

// Get the current state of the flip-flops
let state = lfsr.get();

// Calculate the total number of possible LFSR states
let possibilities = lfsr.calculate_possibilities();
println!("Possible states: {}", possibilities);
```

### DES (Data Encryption Standard)

```rust
let plaintext = 0x0123456789ABCDEF;
let key = 0x133457799BBCDFF1;

let des = Des::new(plaintext);
let encrypted = des.encrypt(key);

println!("{:016X}", encrypted);
```

---

## ⚠️ Security Notice

This library is intended for **educational purposes only**.

* ❌ Not audited
* ❌ Not constant-time
* ❌ Not safe for production cryptography

For real-world use, consider libraries like:

* RustCrypto
* ring

---

## 🧠 Design Goals

* Simplicity over performance
* Explicit bit-level control
* Clear mathematical foundations
* Modular architecture

---

## 📁 Project Structure
```
cryptograph/
├── cryptography/
│   ├── cesar/
│   ├── affine/
│   ├── des/
│   └── streams_ciphers/
│
├── math/
│   ├── euclides/
│   ├── bezout/
│   └── multiplicative_inverse/
│
├── tools/
│   └── flip_flop.rs
│
└── pseudorandom_generator/
    └── lfsr.rs
```
---

## 🤝 Contributing

Contributions are welcome!

You can help by:

* Improving documentation
* Adding tests
* Optimizing implementations
* Extending cryptographic primitives

---

## 📄 License

MIT
---

## 💡 Author Notes

This project is built to deeply understand:

* Bitwise operations
* Modular arithmetic
* Cipher design
* pseudorandom number generator

If you're learning cryptography or low-level Rust, this crate is for you.

---

