/**
 * QuarkDash Crypto Algorithm Benchmark
 *
 * @git             https://github.com/devsdaddy/quarkdash
 * @version         1.0.0
 * @author          Elijah Rastorguev
 * @build           1000
 * @website         https://dev.to/devsdaddy
 */
import {CipherType, QuarkDash, QuarkDashUtils} from "../src";
import {performance} from 'perf_hooks';

// Вспомогательная функция для измерения
/**
 * Performance Measure
 * @param name {string} Benchmark Name
 * @param fn {Function} Function
 * @param iterations {number} Number of iterations
 */
async function measurePerf(name: string, fn: () => Promise<void>, iterations: number = 100): Promise<number> {
    const start = performance.now();
    for (let i = 0; i < iterations; i++) {
        await fn();
    }
    const end = performance.now();
    const avgMs = (end - start) / iterations;
    console.log(`${name}: ${avgMs.toFixed(3)} ms/op`);
    return avgMs;
}

// Функция для измерения пропускной способности
/**
 * Throughput Measure
 * @param name {string} Benchmark Name
 * @param fn {Function} Function
 * @param iterations {number} Number of iterations
 */
async function measureThroughput(name: string, fn: () => Promise<Uint8Array>, iterations: number = 10): Promise<void> {
    let totalBytes = 0;
    const start = performance.now();
    for (let i = 0; i < iterations; i++) {
        const result = await fn();
        totalBytes += result.length;
    }
    const end = performance.now();
    const seconds = (end - start) / 1000;
    const mbps = (totalBytes / seconds) / (1024 * 1024);
    console.log(`${name}: ${mbps.toFixed(2)} MB/s (${(totalBytes / (1024 * 1024)).toFixed(2)} MB in ${seconds.toFixed(3)} s)`);
}

/**
 * Create Benchmark
 */
async function main() {
    console.log("=== QuarkDash Crypto Benchmark ===\n");

    // 1. Установка сессии (KEM + KDF)
    const alice = new QuarkDash({ cipher: CipherType.ChaCha20 });
    const bob = new QuarkDash({ cipher: CipherType.ChaCha20 });
    const alicePub = await alice.generateKeyPair();
    const bobPub = await bob.generateKeyPair();

    await measurePerf('Session establishment (Alice encapsulate)', async () => {
        await alice.initializeSession(bobPub, true);
    }, 50);

    // Measure for second client
    const ciphertext = await alice.initializeSession(bobPub, true) as Uint8Array;
    await measurePerf('Session establishment (Bob decapsulate)', async () => {
        await bob.initializeSession(alicePub, false);
        await bob.finalizeSession(ciphertext);
    }, 50);

    // 3. Compare with Native AES-256-GCM (only for Node.js)
    if (typeof require !== 'undefined') {
        const crypto = require('crypto');
        console.log("\n--- Comparison with Node.js native AES-256-GCM ---");
        const aesKey = crypto.randomBytes(32);
        const iv = crypto.randomBytes(12);
        const plain1KB = QuarkDashUtils.randomBytes(1024);

        const startAes = performance.now();
        const cipher = crypto.createCipheriv('aes-256-gcm', aesKey, iv);
        const encryptedAes = Buffer.concat([cipher.update(plain1KB), cipher.final()]);
        const authTag = cipher.getAuthTag();
        const endAes = performance.now();
        console.log(`AES-256-GCM encrypt 1KB: ${(endAes - startAes).toFixed(3)} ms`);

        const decipher = crypto.createDecipheriv('aes-256-gcm', aesKey, iv);
        decipher.setAuthTag(authTag);
        const startDecAes = performance.now();
        const decryptedAes = Buffer.concat([decipher.update(encryptedAes), decipher.final()]);
        const endDecAes = performance.now();
        console.log(`AES-256-GCM decrypt 1KB: ${(endDecAes - startDecAes).toFixed(3)} ms`);
    }

    console.log("\n=== Benchmark completed ===");
}

main().catch(console.error);