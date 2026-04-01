# 🔐 Cryptograph

> Educational cryptography library in Rust

---

## 📦 Overview

`cryptograph` is a Rust library that implements fundamental concepts from **cryptography** and **number theory**, with a focus on clarity, learning, and low-level understanding.

It includes:

* Classical ciphers (Caesar, Affine)
* Stream cipher primitives
* Pseudorandom bit generators (FlipFlop & LFSR)
* Bit-level utilities
* Number theory algorithms (Euclidean algorithm, Bézout, modular inverse)

---

## 🚀 Features

### 🔑 Cryptography

* **Caesar Cipher**
* **Affine Cipher**
* **Stream Cipher (XOR-based)**

### 🧠 Mathematics

* Euclidean Algorithm (GCD)
* Extended Euclidean Algorithm (Bézout)
* Modular Multiplicative Inverse

### ⚙️ Bit Manipulation

* `bytes ↔ bits` conversion
* Bitwise operations utilities

### 🔄 Pseudorandom Generators

* **FlipFlop**: a single 1-bit memory cell that can be toggled or set
* **Lsfr**: Linear Feedback Shift Register, classical pseudorandom bit generator

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

## 🛠 Future Improvements

* Replace `Vec<bool>` with bit-packed representations
* Add more secure stream cipher implementations
* Improve UTF-8 handling
* Add benchmarks and optimizations

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

If you're learning cryptography or low-level Rust, this crate is for you.

---

