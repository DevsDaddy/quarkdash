## Changelog

Welcome to the **QuarkDash Crypto** changelog.
Here you can find information about all stable algorithm versions.

# v1.2.0: A large update for crypto protocol

> What's in this update: Encryption has become lazy and optimized, keys are rotating, passwords are human-readable, NTT is secure, and connecting everything to WebSocket/HTTP/gRPC is now a single line.

**Important changes for update from 1.1.0:** by default `usePerMessageNonce: true`: now `nonce` for every message takes from 12-bytes of `metadata` (time + seq). This eliminates reuse keystream. If you need to use old algorythm: disable per-message nonce in options `new QuarkDash({ usePerMessageNonce: false })`.

**What's new in 1.2.0 (separate modules, do not break anything):**

- `src/cipher/keystream.ts` has lazy keystream. Compute only required tail, create cache of 64 blocks and has API methods for `seek`/`xorInto`/`blocks()`. Optimized memory on large files / messages.
- `src/session/rekey.ts` key rotation in one token. `alice.rekey()` generates 32B of salt, return new keys with KDF and returns encrypted token; `bob.applyRekey(token)` apply at other client. Advanced policy for rotation using `afterBytes / afterMessages / intervalMs`.
- `src/core/passphrase.ts` is now supports passphrases. `PBKDF2-HMAC-SHA256` (with quick way on Node using `crypto.pbkdf2`) and our implementation of `Argon2id-lite` based on SHAKE256 (memory-hard, to destroy GPU/ASIC). `generateSalt()`, `derive()` and `deriveKeyForQuarkDash()` returns `sessionKey + macKey`.
- `src/session/ntt_protection.ts` is an NTT security switchers: `blinding`, `doubleCheck`, `validateInputs`. By-default all security methods is enabled.
- `src/transport/{websocket,http,grpc}.ts` encrypt your channel with wrappers: `QuarkDashWebSocket.wrap(ws)`, `new QuarkDashHTTP(qd).expressMiddleware()` / `createFetchWrapper()`, `new QuarkDashGRPC(qd).wrapClient()`.

**What was carefully corrected in the old code (without changes in API):**
- `src/crypto.ts` added new options `rekey` and `usePerMessageNonce`, methods `rekey`/`applyRekey`/`rotateKeysLocal`/`needsRekey`/`getRekeyStats`, per-message encryption and counters reset in `deriveSessionKeys`.
- `src/cipher/chacha.ts` / `gimli.ts` now inside the `ChaChaKeystream`/`GimliKeystream` classes, `createKeystream()` outside and streaming helpers. Encryption is same, but memory optimized.
- `src/core/utils.ts` method `randomBytes()` slice request by 64 KB, bypassing the limit `crypto.getRandomValues` by 65 KB.
- `src/session/baselwe.ts` method `secureMultiply()` with blinding and double check support, `wlen` cache, normalization `((v%Q)+Q)%Q` is everywhere (include serialization), keys/ciphertext validation.
- `tests/` All new tests and fixed old tests.

# v.1.1.0

Meet the updated **QuarkDash Crypto**. This version provide a production-ready optimization for heavy calculations inside.

**What's new in 1.1.0?**

- Refactored and optimized **ChaCha** and **Gimli** ciphers;
- Optimized pure TypeScript **SHAKE256** and **MAC** implementation (speed-up x10 times);
- Added **WASM** implementation (written on C) for **SHAKE256** implementation with fallback if not supported;

---

### v.1.0.8

This release includes security fixes based on `Math.random` unsafe function in **QuarkDash Key Exchange** module. [Issue](https://github.com/DevsDaddy/quarkdash/issues/13)

**What's new in 1.0.8?**

- Changed `Math.random` in `QuarkDashKeyExchange` to `QuarkDashUtils.randomBytes`;
- Added stable `errorPoly()` method implementation;

Now the key exchange is more secured by native crypto methods at web applications.

---

### v.1.0.5

For CCA-security reasons created a new release with Ring-LWE changes (shared secret security).

**Changelog:**

- Added `SHA-256` and `SHA-512` implementation;
- Added Shared secret hash function using `SHA-256`;
- Changed Ring-LWE calls of `QuarkDashKeyExchange`;

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
