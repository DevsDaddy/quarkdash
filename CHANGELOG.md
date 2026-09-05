## Changelog

Welcome to the **QuarkDash Crypto** changelog.
Here you can find information about all stable algorithm versions.

### v1.2.2: Performance update: WASM implementation of Gimli / ChaCha / NTT (with SIMD), threshold and fastest keystream (05.09.2026)
In this version, we've moved the heaviest calculations to WebAssembly with SIMD optimizations. QuarkDash is now the fastest tool in its class (post-quantum encryption + lightweight stream ciphers).

> **No breaking API changes.** Fallback to pure JS if WASM not available. **Minimal required Node version is bumped** to `Node >=18` (to support bulk-memory + SIMD default).

> **For users:** encryption and decryption are 1.5-2 times faster, and keystream is 6 times faster.

**🚀 Max performance: fastest in the world for this class:**
- **Gimli / ChaCha WASM** (added implementations `assembly/gimli.ts`, `chacha.ts`): real `gimli_block`/`chacha_block` + bulk `gimli_xor`/`chacha_xor` with `v128` 16B `xor` + `u32` tail, `--enable simd --enable bulk-memory -O3`. Cached `key(32B)/nonce(12B)` in WASM memory (copy once per stream), `threshold 1024B` - `<1KB` stays JS to avoid call overhead, `≥1KB` goes bulk single-call.
- **JS keystream fast-path** (`src/cipher/keystream.ts`): `DataView×3` to `Uint32Array`, `cacheQueue` without iterator alloc, sequential encrypt no longer pays `Map` churn.
- **NTT (WASM-SIMD)** (`assembly/ntt.ts` + `src/session/ntt_wasm.ts`): fixed `A=0/B=1024/OUT=2048` layout, `memU32` view cache, no bump-alloc per multiply, `pointwise` scalar 4-unroll, `bulk_xor` via `v128`.
- **Ring-LWE** (`src/session/baselwe.ts`): `naiveMultiply` for `N≤64`, early `N!==256` bypass, de-duplicated `normalize`, `secureMultiply` tries WASM once (and 2× only with `doubleCheck`).

**🧩 Compatibility & fallback:**
- `src/core/wasm_loader.ts` keeps `loadWasmModule` `fs` vs `fetch` + `Map` cache; WASM `importMemory 64/128` (4/8 MB) - iOS/Safari <15 or missing `bulk-memory` → `CompileError` caught → JS. `isSimdSupported`/`isBulkMemorySupported` kept for diagnostics but not gating (rely on compile fallback). All ciphers keep `isReady()` + `try {wasm} catch{fallback}` per `shake.ts` pattern.

---

### v1.2.1: Performance and Correctness audit for NTT, SHA, SHAKE, KDF, KEX fixes (28.08.2026)

> **No breaking API changes.** Idea, key exchange flow and `QuarkDash` public API unchanged. Only internal maths made correct. Ciphertext grows `512 → 544 B` (512 B still accepted for backward compat).

**🔐 Critical security and compatibility fixes (to ensure everything decrypts and signs correctly):**
- **SHA-256/SHA-512 hashes**: fixed a padding bug for messages exactly 56 and 112 bytes long. Previously, the hash was calculated incorrectly for these sizes; the result now matches the official examples (vectors) from the standard.
- **SHAKE-256 hash**: the internal hash processor (Keccak-f) has been completely rewritten. Constant tables and the tailing algorithm have been corrected. SHAKE now produces exactly the same results as Node.js's built-in crypto or Python's hashlib. This is important so that your data hashes consistently across different programming languages.
- **Key Derivation Formula (KDF)**: a fatal bug was identified and fixed: previously, when requesting a long key, the function would enter an infinite loop and return zeros. Now it works as intended: it sequentially generates hash chunks, mixing them with salt and data (following the HKDF principle).
- **Post-quantum exchange (NTT) mathematics:** fixed the "roots" (special numbers used to multiply polynomials). We've implemented a proper fast transformation algorithm (bit-reversible Cooley-Tukey). This necessitated a change in the ciphertext size: it now takes up a precise **544 bytes** (512 bytes of data + 32 bytes of hint). Old 512-byte messages will no longer pass verification, so compatibility with the previous version has been intentionally broken - for the sake of correctness.

**🤝 Fixes to symmetric key exchange (so that both parties receive the same key):**
- **Salt for session keys:** previously, when creating a shared key, each participant generated a random salt. This resulted in different encryption keys. **This has been fixed:** the salt is now strictly fixed (32 zeros), so both clients output identical ``sessionKey`` and ``macKey``.
- **An error occurred in the finalization of the exchange:** the wrong public key was used when calculating the shared secret. This has been fixed; now both parties hash the same recipient's public key, and the secret is converged.
- **Rekeying sequence (Key rotation):** the steps have been reversed. Now, when updating keys, encryption occurs first (with the old key), and only then is the new one deduced. This ensures that the intermediate token can be decrypted with the old keys on both sides, avoiding desynchronization.

**⚡️ Speed-up performance (pure JavaScript optimization):**
- **Significantly accelerated internal algorithms** by working with raw 32-bit arrays (``Uint32Array``) instead of regular objects.
- **ChaCha and Gimli** - encryption of 1 megabyte of data has been accelerated by approximately 2-3 times, while the external library functions have not changed.
- **Optimized the calculation of MAC signatures** (now using "zero copy" of data) and reading large blocks via ``DataView``.

**🧪 WebAssembly (WASM) and tests:**
- **We've updated the WASM version of SHAKE**: it's now synced with the fixed JS code. We've added a smart "backup plan": if WASM fails to load, the library will automatically switch to pure JS, and everything will continue to work.
- **WASM is now moved from C to Assemblyscript**;
- **Added 26 new complex tests (plus 5 more in WASM)**, bringing the total to 62. The tests check hashes, MAC signatures, KDF determinism, round-trip NTT math, and key packaging correctness.
- **The library version has been updated** from ``1.2.0`` to ``1.2.1``, and the build number has been updated from 1024 to 1025. A command for compiling WASM has been added to the build.

This version has stabilized the algorithm and significantly accelerated its performance.
**This version is now available as an LTS solution for your projects.**

---

### v1.2.0: A large update for crypto protocol

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

---

### v.1.1.0

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
