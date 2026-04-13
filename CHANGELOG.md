## Changelog
Welcome to the **QuarkDash Crypto** changelog.
Here you can find information about all stable algorithm versions.

# v.1.1.0
Meet the updated **QuarkDash Crypto**. This version provide a production-ready optimization for heavy calculations inside.

**What's new in 1.1.0?**
- Refactored and optimized **ChaCha** and **Gimli** ciphers;
- 

---

### v.1.0.8
This release includes security fixes based on ``Math.random`` unsafe function in **QuarkDash Key Exchange** module. [Issue](https://github.com/DevsDaddy/quarkdash/issues/13)

**What's new in 1.0.8?**
- Changed ``Math.random`` in ``QuarkDashKeyExchange`` to ``QuarkDashUtils.randomBytes``;
- Added stable ``errorPoly()`` method implementation;

Now the key exchange is more secured by native crypto methods at web applications.

---

### v.1.0.5
For CCA-security reasons created a new release with Ring-LWE changes (shared secret security).

**Changelog:**
- Added ``SHA-256`` and ``SHA-512`` implementation;
- Added Shared secret hash function using ``SHA-256``;
- Changed Ring-LWE calls of ``QuarkDashKeyExchange``;

**What's New?**
- CCA-security for shared secrets;

---

### v.1.0.2
An updated version of the QuarkDash algorithm that includes minor changes to the algorithm without changing the core API.

**New Features:**
- Added Chi-Square test;
- Shake-256 Implementation now based on Keccak function instead SHA-256 emulation;

---

### v.1.0.0
**QuarkDash Crypto** - It is a hybrid cryptographic protocol that provides post-quantum security, high performance, and attack resistance.
This library can be used as shared solution for client and server. Written on **pure typescript**. **Dependency-free**.

### ❓ Why QuarkDash Crypto?<br/>
🔹 **Lightweight library** with zero dependencies;<br/>
🔹 **Powerful crypto** algorithm written in **Typescript**;<br/>
🔹 **Extremely** fast (great for realtime and IoT applications);<br/>
🔹 **Production ready** with benchmarks;

### 🔒 General Components
- **Asymmetric key exchange** – Ring-LWE (N=256, Q=7681) based on NTT;
- **Symmetric encryption** – With ChaCha20 (RFC 7539) or lightweight Gimli ciphers.
- **Key Derivation Function (KDF)** – Based on fast SHAKE256 (emulated via SHA-256).
- **Message Authentication Code (MAC)** – Based on SHAKE256 with key.
- **Replay protection** – timestamp + sequence number.

### ⭐ Key Features
- **Quantum stability** – not broken by Shor and Grover's algorithms;
- **Performance** – encryption up to 2.8 GB/s, session establishment ~10 ms;
- **Forward secrecy** – compromising a long-term key does not reveal past sessions.
- **Built-in protection** against replay, timing attacks, and counterfeiting.
- **Flexibility** – choice of cipher (ChaCha20/Gimli), synchronous and asynchronous API.