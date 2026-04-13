/**
 * QuarkDash Crypto Algorithm Benchmark
 *
 * @git             https://github.com/devsdaddy/quarkdash
 * @version         1.0.0
 * @author          Elijah Rastorguev
 * @build           1002
 * @website         https://dev.to/devsdaddy
 */
import {CipherType, QuarkDash, QuarkDashUtils} from "../src";
import {performance} from 'perf_hooks';

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
    console.log(`${name}: ${avgMs.toFixed(3)} ms`);
    return avgMs;
}

/**
 * Create Benchmark
 */
async function main() {
    let byteslen = 1024 * 60;
    const plain1KB = QuarkDashUtils.randomBytes(byteslen);
    console.log('\x1b[1m%s\x1b[0m', `=== Bench at ${Math.round(byteslen/1024)} KB ===`);
    console.log('\x1b[1m%s\x1b[0m', '=== QuarkDash Crypto ===');

    // KEM + KDF
    const client = new QuarkDash({ cipher: CipherType.ChaCha20 });
    const server = new QuarkDash({ cipher: CipherType.ChaCha20 });
    let clientPub : Uint8Array = new Uint8Array(0), serverPub : Uint8Array = new Uint8Array(0);
    await measurePerf('Generate Key Pairs (Client + Server)', async () => {
        clientPub = await client.generateKeyPair();
        serverPub = await server.generateKeyPair();
    });

    // Initialize sessions
    await measurePerf('Session establishment (client encapsulate)', async () => {
        await client.initializeSession(serverPub, true);
    }, 50);

    const ciphertext = await client.initializeSession(serverPub, true) as Uint8Array;
    await measurePerf('Session establishment (server decapsulate)', async () => {
        await server.initializeSession(clientPub, false);
        await server.finalizeSession(ciphertext);
    }, 50);

    // Encrypt
    let encrypted : Uint8Array, decrypted : Uint8Array;
    await measurePerf('Encryption (client)', async () => {
        encrypted = await client.encrypt(plain1KB);
    }, 1);
    await measurePerf('Decryption (server)', async () => {
        decrypted = await server.decrypt(encrypted);
    }, 1)

    // Compare with AES
    if (typeof require !== 'undefined') {
        const crypto = require('crypto');
        console.log('\x1b[1m%s\x1b[0m', '\n=== AES GSM ===');
        const aesKey = crypto.randomBytes(32);
        const iv = crypto.randomBytes(12);

        const startAes = performance.now();
        const cipher = crypto.createCipheriv('aes-256-gcm', aesKey, iv);
        const encryptedAes = Buffer.concat([cipher.update(plain1KB), cipher.final()]);
        const authTag = cipher.getAuthTag();
        const endAes = performance.now();
        console.log(`AES-256-GCM encrypt: ${(endAes - startAes).toFixed(3)} ms`);

        const decipher = crypto.createDecipheriv('aes-256-gcm', aesKey, iv);
        decipher.setAuthTag(authTag);
        const startDecAes = performance.now();
        const decryptedAes = Buffer.concat([decipher.update(encryptedAes), decipher.final()]);
        const endDecAes = performance.now();
        console.log(`AES-256-GCM decrypt: ${(endDecAes - startDecAes).toFixed(3)} ms`);
    }

    console.log("\n=== Benchmark completed ===");
}

main().catch(console.error);