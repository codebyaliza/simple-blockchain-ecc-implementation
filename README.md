# Simple Blockchain & ECC Implementation

A Python-based educational project that demonstrates:
- **A basic blockchain** with SHA‑256 hashing, block linking, and tamper detection.
- **Elliptic Curve Cryptography (ECC)** including point addition, doubling, scalar multiplication, and a simplified EC-ElGamal encryption/decryption.

This repository was created as part of a university lab assignment on data security.

## Features
- **Blockchain**
  - Custom `Block` and `Blockchain` classes.
  - Genesis block creation.
  - SHA‑256 hash verification and chain integrity check.
  - Tampering demonstration – modifying a block invalidates the chain.
- **Elliptic Curve Cryptography**
  - Curve definition ($y^2 = x^3 + ax + b \mod p$).
  - Point addition and doubling with edge‑case handling (point at infinity, $y=0$ doubling).
  - Double‑and‑add scalar multiplication.
  - Message encoding to curve points.
  - Simplified EC‑ElGamal encryption and decryption.
- **Security Analysis**  
  The accompanying PDF provides a line‑by‑line code explanation and security discussion covering collision resistance, ECDLP hardness, randomness requirements, and real‑world limitations.

## Requirements
- Python 3.8 or higher (uses `pow(k, -1, p)` for modular inverse).

No external libraries are required beyond the Python standard library (`hashlib`, `time`, `random`).

## Usage
Clone the repository and run the main script:
```bash


Learning Outcomes
Understand blockchain immutability and cryptographic linking.

Grasp the basics of elliptic curve group operations.

Implement ElGamal encryption using ECC.

Analyze security strengths and weaknesses of educational implementations.

License
This project is for educational purposes. Feel free to use, modify, and share.
git clone https://github.com/[your-username]/blockchain-ecc-basics.git
cd blockchain-ecc-basics
python assignment3.py
