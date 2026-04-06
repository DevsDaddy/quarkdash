/**
 * QuarkDash Crypto Algorithm Test
 *
 * @git             https://github.com/devsdaddy/quarkdash
 * @version         1.0.0
 * @author          Elijah Rastorguev
 * @build           1000
 * @website         https://dev.to/devsdaddy
 */
import {CipherType, QuarkDash, QuarkDashUtils} from "../src";

describe('QuarkDash crypto algorithm tests', () => {
    let alice: QuarkDash;
    let bob: QuarkDash;
    let alicePub: Uint8Array;
    let bobPub: Uint8Array;
    let ciphertext: Uint8Array;

    /* Create crypto assets */
    beforeAll(async () => {
        alice = new QuarkDash({ cipher: CipherType.ChaCha20 });
        bob = new QuarkDash({ cipher: CipherType.ChaCha20 });
        alicePub = await alice.generateKeyPair();
        bobPub = await bob.generateKeyPair();
        ciphertext = await alice.initializeSession(bobPub, true) as Uint8Array;
        await bob.initializeSession(alicePub, false);
        await bob.finalizeSession(ciphertext);
    });

    /* Empty data test */
    test('Empty data', async () => {
        const plain = new Uint8Array(0);
        const enc = await alice.encrypt(plain);
        const dec = await bob.decrypt(enc);
        expect(dec.length).toBe(0);
    });

    /* Simple UTF-8 Encryption */
    test('Simple UTF-8 Text Encryption using Gimli Cipher', async () => {
        const alice = new QuarkDash({ cipher: CipherType.Gimli });
        const bob = new QuarkDash({ cipher: CipherType.Gimli });
        const alicePub = await alice.generateKeyPair();
        const bobPub = await bob.generateKeyPair();

        const ciphertext = await alice.initializeSession(bobPub, true) as Uint8Array;
        await bob.initializeSession(alicePub, false);
        await bob.finalizeSession(ciphertext);

        const plain = QuarkDashUtils.textToBytes('Hello QuarkDash 🔒!');
        const enc = await alice.encrypt(plain);
        const dec = await bob.decrypt(enc);
        expect(QuarkDashUtils.bytesToText(dec)).toBe('Hello QuarkDash 🔒!');
    });

    /* Large Data (1MB) */
    test('Large data (64KB)', async () => {
        const plain = QuarkDashUtils.randomBytes(1024 * 64);
        const enc = await alice.encrypt(plain);
        const dec = await bob.decrypt(enc);
        expect(dec).toEqual(plain);
    });

    /* Reply attack prevention test */
    test('Replay attack prevention', async () => {
        const plain = QuarkDashUtils.textToBytes('test');
        const enc = await alice.encrypt(plain);
        // Pass in first time
        await bob.decrypt(enc);
        // Can't pass in second time
        await expect(bob.decrypt(enc)).rejects.toThrow('Replay detected');
    });

    /* MAC corruption test */
    test('MAC corruption', async () => {
        const plain = QuarkDashUtils.textToBytes('test');
        const enc = await alice.encrypt(plain);
        // Изменяем последний байт MAC
        enc[enc.length - 1] ^= 0xFF;
        await expect(bob.decrypt(enc)).rejects.toThrow('MAC verification failed');
    });

    /* Concurrent sessions test */
    test('Concurrent sessions', async () => {
        const sessions = [];
        for (let i = 0; i < 5; i++) {
            const a = new QuarkDash({ cipher: CipherType.ChaCha20 });
            const b = new QuarkDash({ cipher: CipherType.ChaCha20 });
            const aPub = await a.generateKeyPair();
            const bPub = await b.generateKeyPair();
            const ct = await a.initializeSession(bPub, true) as Uint8Array;
            await b.initializeSession(aPub, false);
            await b.finalizeSession(ct);
            sessions.push({ a, b });
        }
        await Promise.all(sessions.map(async (s, idx) => {
            const msg = QuarkDashUtils.textToBytes(`msg${idx}`);
            const enc = await s.a.encrypt(msg);
            const dec = await s.b.decrypt(enc);
            expect(QuarkDashUtils.bytesToText(dec)).toBe(`msg${idx}`);
        }));
    });

    // Sync tests (only for supported environment)
    if (typeof crypto !== 'undefined' && crypto.subtle === undefined) {
        // Node.js sync methods
        test('Sync API', () => {
            const aliceSync = new QuarkDash({ cipher: CipherType.ChaCha20 });
            const bobSync = new QuarkDash({ cipher: CipherType.ChaCha20 });
            const alicePubSync = aliceSync.generateKeyPairSync();
            const bobPubSync = bobSync.generateKeyPairSync();
            const ciphertextSync = aliceSync.initializeSessionSync(bobPubSync, true);
            bobSync.initializeSessionSync(alicePubSync, false);
            bobSync.finalizeSessionSync(ciphertextSync!);
            const plain = QuarkDashUtils.textToBytes('sync test');
            const enc = aliceSync.encryptSync(plain);
            const dec = bobSync.decryptSync(enc);
            expect(QuarkDashUtils.bytesToText(dec)).toBe('sync test');
        });
    }
});