/**
 * QuarkDash Crypto Features Test
 *
 * @git             https://github.com/devsdaddy/quarkdash
 * @version         1.0.0
 * @author          Elijah Rastorguev
 * @build           1020
 * @website         https://dev.to/devsdaddy
 */
/* Import required modules */
import {
    CipherType,
    QuarkDash,
    QuarkDashUtils,
    QuarkDashChaCha,
    QuarkDashGimli,
    QuarkDashPassphrase,
    BaseRingLWE,
    ChaChaKeystream,
    GimliKeystream,
    QuarkDashHTTP,
    QuarkDashGRPC,
    QuarkDashWebSocket
} from "../src";

/* Describe tests */
describe("Lazy Keystream", () => {
    test("ChaCha lazy vs eager equivalence", async () => {
        const key = QuarkDashUtils.randomBytes(32);
        const nonce = QuarkDashUtils.randomBytes(12);
        const c = new QuarkDashChaCha(key, nonce);
        const data = QuarkDashUtils.randomBytes(5000);
        const eager = c.encryptSync(data);
        const ks = (c as any).createKeystream() as ChaChaKeystream;
        const lazy = ks.xor(data, 0);
        expect(lazy).toEqual(eager);
    });
    test("ChaCha seek and getBytes", () => {
        const key = QuarkDashUtils.randomBytes(32);
        const nonce = new Uint8Array(12);
        const ks = new ChaChaKeystream(key, nonce);
        const full = ks.getBytes(0, 200);
        const part1 = ks.getBytes(0, 100);
        const part2 = ks.getBytes(100, 100);
        const combined = QuarkDashUtils.concatBytes(part1, part2);
        expect(combined).toEqual(full);
        const offset = ks.getBytes(64, 64);
        const block1 = ks.generateBlock(1);
        expect(offset).toEqual(block1);
    });
    test("Gimli lazy xor and stream", () => {
        const key = QuarkDashUtils.randomBytes(32);
        const nonce = QuarkDashUtils.randomBytes(12);
        const g = new QuarkDashGimli(key, nonce);
        const data = QuarkDashUtils.randomBytes(3000);
        const enc = g.encryptSync(data);
        const ks = (g as any).createKeystream() as GimliKeystream;
        const dec = ks.xor(enc, 0);
        expect(dec).toEqual(data);
        const gen = ks.blocks(0);
        const first = gen.next().value as Uint8Array;
        expect(first.length).toBe(48);
        ks.seek(100);
        expect(ks.tell()).toBe(100);
        const read = ks.read(48);
        expect(read).toEqual(ks.getBytes(100, 48));
    });
    test("Large data lazy processing", async () => {
        const alice = new QuarkDash({cipher: CipherType.ChaCha20});
        const bob = new QuarkDash({cipher: CipherType.ChaCha20});
        const aPub = await alice.generateKeyPair();
        const bPub = await bob.generateKeyPair();
        const ct = (await alice.initializeSession(bPub, true)) as Uint8Array;
        await bob.initializeSession(aPub, false);
        await bob.finalizeSession(ct);
        const plain = QuarkDashUtils.randomBytes(1024 * 128);
        const enc = await alice.encrypt(plain);
        const dec = await bob.decrypt(enc);
        expect(dec).toEqual(plain);
    });
});

describe("Rekeying", () => {
    async function makePair() {
        const alice = new QuarkDash({
            cipher: CipherType.ChaCha20,
            rekey: {policy: {afterMessages: 2}} as any,
        });
        const bob = new QuarkDash({cipher: CipherType.ChaCha20});
        const aPub = await alice.generateKeyPair();
        const bPub = await bob.generateKeyPair();
        const ct = (await alice.initializeSession(bPub, true)) as Uint8Array;
        await bob.initializeSession(aPub, false);
        await bob.finalizeSession(ct);
        return {alice, bob};
    }

    test("basic rekey sync", async () => {
        const {alice, bob} = await makePair();
        const plain1 = QuarkDashUtils.textToBytes("before rekey");
        const enc1 = await alice.encrypt(plain1);
        expect(await bob.decrypt(enc1)).toEqual(plain1);
        const token = await alice.rekey();
        await bob.applyRekey(token);
        expect(alice.getRekeyCounter()).toBe(1);
        expect(bob.getRekeyCounter()).toBe(1);
        const plain2 = QuarkDashUtils.textToBytes("after rekey");
        const enc2 = await alice.encrypt(plain2);
        expect(await bob.decrypt(enc2)).toEqual(plain2);
        const enc3 = await bob.encrypt(plain2);
        expect(await alice.decrypt(enc3)).toEqual(plain2);
    });
    test("rekey sync API", () => {
        const alice = new QuarkDash({cipher: CipherType.Gimli});
        const bob = new QuarkDash({cipher: CipherType.Gimli});
        const aPub = alice.generateKeyPairSync();
        const bPub = bob.generateKeyPairSync();
        const ct = alice.initializeSessionSync(bPub, true)!;
        bob.initializeSessionSync(aPub, false);
        bob.finalizeSessionSync(ct);
        const token = alice.rekeySync();
        bob.applyRekeySync(token);
        const plain = QuarkDashUtils.textToBytes("sync rekey");
        const enc = alice.encryptSync(plain);
        expect(bob.decryptSync(enc)).toEqual(plain);
    });
    test("rekey counter mismatch throws", async () => {
        const {alice, bob} = await makePair();
        const token = await alice.rekey();
        await bob.applyRekey(token);
        const token2 = await alice.rekey();
        await expect(bob.applyRekey(token)).rejects.toThrow();
        void token2;
    });
    test("needsRekey policy", async () => {
        const alice = new QuarkDash({
            cipher: CipherType.ChaCha20,
            rekey: {policy: {afterMessages: 1}} as any,
        });
        const bob = new QuarkDash({cipher: CipherType.ChaCha20});
        const aPub = await alice.generateKeyPair();
        const bPub = await bob.generateKeyPair();
        const ct = (await alice.initializeSession(bPub, true)) as Uint8Array;
        await bob.initializeSession(aPub, false);
        await bob.finalizeSession(ct);
        expect(alice.needsRekey()).toBe(false);
        await alice.encrypt(QuarkDashUtils.textToBytes("a"));
        expect(alice.needsRekey()).toBe(true);
    });
    test("bytesEncrypted tracking", async () => {
        const {alice} = await makePair();
        await alice.encrypt(QuarkDashUtils.randomBytes(100));
        expect(alice.getRekeyStats().bytesEncrypted).toBe(100);
        expect(alice.getRekeyStats().messagesEncrypted).toBe(1);
    });
});

describe("Passphrase PBKDF2/Argon2", () => {
    test("PBKDF2 RFC6070 vector iteration 1", async () => {
        const salt = QuarkDashUtils.textToBytes("salt");
        const key = QuarkDashPassphrase.pbkdf2Sync("password", salt, 1, 20);
        const hex = QuarkDashUtils.bytesToHEX(key);
        expect(hex).toBe("120fb6cffcf8b32c43e7225256c4f837a86548c9");
    });
    test("PBKDF2 iteration 4096", async () => {
        const salt = QuarkDashUtils.textToBytes("salt");
        const key = QuarkDashPassphrase.pbkdf2Sync("password", salt, 4096, 20);
        const hex = QuarkDashUtils.bytesToHEX(key);
        expect(hex).toBe("c5e478d59288c841aa530db6845c4c8d962893a0");
    });
    test("PBKDF2 async vs sync same", async () => {
        const salt = QuarkDashUtils.randomBytes(16);
        const a = QuarkDashPassphrase.pbkdf2Sync("hello world", salt, 1000, 32);
        const b = await QuarkDashPassphrase.pbkdf2("hello world", salt, 1000, 32);
        expect(a).toEqual(b);
    });
    test("Argon2 determinism", async () => {
        const salt = QuarkDashUtils.textToBytes("somesalt12345678");
        const k1 = QuarkDashPassphrase.argon2idSync("password", salt, 8, 1, 32);
        const k2 = QuarkDashPassphrase.argon2idSync("password", salt, 8, 1, 32);
        expect(k1).toEqual(k2);
        const k3 = QuarkDashPassphrase.argon2idSync("different", salt, 8, 1, 32);
        expect(k1).not.toEqual(k3);
    });
    test("derive returns salt", async () => {
        const {key, salt} = await QuarkDashPassphrase.derive("my secret", {
            algorithm: "pbkdf2",
            iterations: 1000,
            keyLength: 32,
        });
        expect(key.length).toBe(32);
        expect(salt.length).toBe(32);
    });
    test("different salts produce different keys", async () => {
        const s1 = QuarkDashUtils.randomBytes(16);
        const s2 = QuarkDashUtils.randomBytes(16);
        const k1 = QuarkDashPassphrase.pbkdf2Sync("same", s1, 1000, 32);
        const k2 = QuarkDashPassphrase.pbkdf2Sync("same", s2, 1000, 32);
        expect(k1).not.toEqual(k2);
    });
});

describe("NTT Protection", () => {
    test("ntt roundtrip hardened", async () => {
        const alice = new QuarkDash({cipher: CipherType.ChaCha20});
        const bob = new QuarkDash({cipher: CipherType.ChaCha20});
        (alice as any).config.keyExchange.setNTTProtection({
            enabled: true,
            blinding: true,
            doubleCheck: true,
        });
        (bob as any).config.keyExchange.setNTTProtection({
            enabled: true,
            blinding: true,
            doubleCheck: true,
        });
        const aPub = await alice.generateKeyPair();
        const bPub = await bob.generateKeyPair();
        const ct = (await alice.initializeSession(bPub, true)) as Uint8Array;
        await bob.initializeSession(aPub, false);
        await bob.finalizeSession(ct);
        const plain = QuarkDashUtils.textToBytes("ntt test");
        const enc = await alice.encrypt(plain);
        expect(await bob.decrypt(enc)).toEqual(plain);
    });
    test("secureMultiply vs ntt", () => {
        const lwe = new BaseRingLWE();
        (lwe as any).setNTTProtection({blinding: false, doubleCheck: false});
        const a = Array.from({length: 256}, () =>
            BigInt(Math.floor(Math.random() * 1000) % 7681),
        );
        const b = Array.from({length: 256}, () =>
            BigInt(Math.floor(Math.random() * 1000) % 7681),
        );
        const r1 = (lwe as any).secureMultiply(a, b);
        (lwe as any).setNTTProtection({blinding: true, doubleCheck: true});
        const r2 = (lwe as any).secureMultiply(a, b);
        for (let i = 0; i < 256; i++)
            expect(r1[i].toString()).toBe(r2[i].toString());
    });
    test("invalid public key throws", () => {
        const lwe = new BaseRingLWE();
        expect(() => (lwe as any).validatePublicKey(new Uint8Array(10))).toThrow();
    });
    test("invalid ciphertext throws", async () => {
        const alice = new QuarkDash({cipher: CipherType.ChaCha20});
        const bob = new QuarkDash({cipher: CipherType.ChaCha20});
        const aPub = await alice.generateKeyPair();
        const bPub = await bob.generateKeyPair();
        const ct = (await alice.initializeSession(bPub, true)) as Uint8Array;
        await bob.initializeSession(aPub, false);
        await bob.finalizeSession(ct);
        expect(() =>
            (bob as any).config.keyExchange.validateCiphertext(new Uint8Array(10)),
        ).toThrow();
    });
    test("protection toggle", () => {
        const lwe = new BaseRingLWE();
        lwe.setNTTProtection({enabled: false});
        expect(lwe.getNTTProtection().enabled).toBe(false);
        lwe.setNTTProtection({enabled: true});
        expect(lwe.getNTTProtection().enabled).toBe(true);
    });
});

describe("Transport", () => {
    test("HTTP encrypt/decrypt", async () => {
        const alice = new QuarkDash({cipher: CipherType.ChaCha20});
        const bob = new QuarkDash({cipher: CipherType.ChaCha20});
        const aPub = await alice.generateKeyPair();
        const bPub = await bob.generateKeyPair();
        const ct = (await alice.initializeSession(bPub, true)) as Uint8Array;
        await bob.initializeSession(aPub, false);
        await bob.finalizeSession(ct);
        const httpAlice = new QuarkDashHTTP(alice);
        const httpBob = new QuarkDashHTTP(bob);
        const {body} = await httpAlice.encryptBody({hello: "world"});
        const dec = await httpBob.decryptToJSON(body);
        expect(dec).toEqual({hello: "world"});
    });
    test("HTTP sync", async () => {
        const alice = new QuarkDash({cipher: CipherType.ChaCha20});
        const bob = new QuarkDash({cipher: CipherType.ChaCha20});
        const aPub = alice.generateKeyPairSync();
        const bPub = bob.generateKeyPairSync();
        const ct = alice.initializeSessionSync(bPub, true)!;
        bob.initializeSessionSync(aPub, false);
        bob.finalizeSessionSync(ct);
        const httpAlice = new QuarkDashHTTP(alice);
        const httpBob = new QuarkDashHTTP(bob);
        const {body} = httpAlice.encryptBodySync("hello http");
        const dec = QuarkDashUtils.bytesToText(httpBob.decryptBodySync(body));
        expect(dec).toBe("hello http");
    });
    test("gRPC encrypt/decrypt", async () => {
        const alice = new QuarkDash({cipher: CipherType.Gimli});
        const bob = new QuarkDash({cipher: CipherType.Gimli});
        const aPub = await alice.generateKeyPair();
        const bPub = await bob.generateKeyPair();
        const ct = (await alice.initializeSession(bPub, true)) as Uint8Array;
        await bob.initializeSession(aPub, false);
        await bob.finalizeSession(ct);
        const grpcAlice = new QuarkDashGRPC(alice);
        const grpcBob = new QuarkDashGRPC(bob);
        const msg = QuarkDashUtils.textToBytes("grpc payload");
        const enc = await grpcAlice.encryptMessage(msg);
        const dec = await grpcBob.decryptMessage(enc);
        expect(dec).toEqual(msg);
    });
    test("WebSocket wrapper mock", async () => {
        const alice = new QuarkDash({cipher: CipherType.ChaCha20});
        const bob = new QuarkDash({cipher: CipherType.ChaCha20});
        const aPub = await alice.generateKeyPair();
        const bPub = await bob.generateKeyPair();
        const ct = (await alice.initializeSession(bPub, true)) as Uint8Array;
        await bob.initializeSession(aPub, false);
        await bob.finalizeSession(ct);
        let captured: Uint8Array | null = null;
        const mockWs: any = {
            send: (d: Uint8Array) => {
                captured = d;
            },
            on: (ev: string, h: any) => {
                mockWs._h = h;
            },
        };
        const wrapped = QuarkDashWebSocket.wrap(alice, mockWs);
        await wrapped.send("hello ws");
        expect(captured).not.toBeNull();
        const dec = await bob.decrypt(captured!);
        expect(QuarkDashUtils.bytesToText(dec)).toBe("hello ws");
    });
    test("gRPC wrapClient", async () => {
        const alice = new QuarkDash({cipher: CipherType.ChaCha20});
        const bob = new QuarkDash({cipher: CipherType.ChaCha20});
        const aPub = await alice.generateKeyPair();
        const bPub = await bob.generateKeyPair();
        const ct = (await alice.initializeSession(bPub, true)) as Uint8Array;
        await bob.initializeSession(aPub, false);
        await bob.finalizeSession(ct);
        const grpc = new QuarkDashGRPC(alice);
        const fakeClient: any = {echo: async (x: Uint8Array) => x};
        const wrapped = grpc.wrapClient(fakeClient);
        const payload = QuarkDashUtils.textToBytes("wrap test");
        const res = await wrapped.echo(payload);
        expect(res).toBeDefined();
    });
});
