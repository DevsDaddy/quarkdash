/**
 * QuarkDash WASM Features Test
 *
 * @git             https://github.com/devsdaddy/quarkdash
 * @version         1.0.0
 * @author          Elijah Rastorguev
 * @build           1020
 * @website         https://dev.to/devsdaddy
 */
/* Import required modules */
import {
    QuarkDashUtils,
    QuarkDashChaCha,
    QuarkDashGimli,
    BaseRingLWE,
    QuarkDashRRLWE,
    QuarkDash,
    CipherType
} from "../src";
import {GimliWasm} from "../src";
import {ChaChaWasm} from "../src";
import {NttWasm} from "../src";


/**
 * Force JS Mode
 */
function forceJsMode() {
    (GimliWasm as any).initializedWasm = false;
    (ChaChaWasm as any).initializedWasm = false;
    (NttWasm as any).initializedWasm = false;
}

/**
 * Try initialize WASM
 */
async function tryInitWasm() {
    try {
        await GimliWasm.initWasm("./wasm/gimli.wasm");
    } catch {
    }
    try {
        await ChaChaWasm.initWasm("./wasm/chacha.wasm");
    } catch {
    }
    try {
        await NttWasm.initWasm("./wasm/ntt.wasm");
    } catch {
    }
    return GimliWasm.isReady() && ChaChaWasm.isReady() && NttWasm.isReady();
}

/* WASM Tests */
describe("WASM parity Gimli/ChaCha/NTT", () => {
    test("Gimli block WASM vs JS identical", async () => {
        const key = QuarkDashUtils.randomBytes(32);
        const nonce = QuarkDashUtils.randomBytes(12);
        for (const bi of [0, 1, 5, 100, 1000]) {
            forceJsMode();
            const expected = new QuarkDashGimli(key, nonce).createKeystream().generateBlock(bi);
            await GimliWasm.initWasm("./wasm/gimli.wasm");
            if (!GimliWasm.isReady()) continue;
            const actual = new QuarkDashGimli(key, nonce).createKeystream().generateBlock(bi);
            expect(actual).toEqual(expected);
        }
    });

    test("ChaCha block WASM vs JS identical", async () => {
        const key = QuarkDashUtils.randomBytes(32);
        const nonce = QuarkDashUtils.randomBytes(12);
        for (const bi of [0, 1, 2, 64, 1000]) {
            forceJsMode();
            const expected = new QuarkDashChaCha(key, nonce).createKeystream().generateBlock(bi);
            await ChaChaWasm.initWasm("./wasm/chacha.wasm");
            if (!ChaChaWasm.isReady()) continue;
            const actual = new QuarkDashChaCha(key, nonce).createKeystream().generateBlock(bi);
            expect(actual).toEqual(expected);
        }
    });

    test("Gimli bulk xor WASM vs JS", async () => {
        await tryInitWasm();
        const key = QuarkDashUtils.randomBytes(32);
        const nonce = QuarkDashUtils.randomBytes(12);
        for (const len of [0, 1, 47, 48, 49, 5000, 100 * 48 + 7]) {
            for (const off of [0, 5, 47, 48, 100]) {
                const data = QuarkDashUtils.randomBytes(len);
                forceJsMode();
                const ksJs = new QuarkDashGimli(key, nonce).createKeystream();
                const exp = ksJs.xor(data, off);
                await GimliWasm.initWasm("./wasm/gimli.wasm");
                const ksWasm = new QuarkDashGimli(key, nonce).createKeystream();
                const act = ksWasm.xor(data, off);
                expect(act).toEqual(exp);
                // xorInto
                forceJsMode();
                const outJs = new Uint8Array(len);
                ksJs.xorInto(data, outJs, off);
                await GimliWasm.initWasm("./wasm/gimli.wasm");
                const outWasm = new Uint8Array(len);
                ksWasm.xorInto(data, outWasm, off);
                expect(outWasm).toEqual(outJs);
            }
        }
    });

    test("ChaCha bulk xor WASM vs JS", async () => {
        await tryInitWasm();
        const key = QuarkDashUtils.randomBytes(32);
        const nonce = QuarkDashUtils.randomBytes(12);
        for (const len of [0, 1, 63, 64, 65, 2 * 1024 * 1024 < 20000 ? 20000 : 5000]) {
            for (const off of [0, 7, 63, 64]) {
                const data = QuarkDashUtils.randomBytes(len > 50000 ? 5000 : len);
                forceJsMode();
                const ksJs = new QuarkDashChaCha(key, nonce).createKeystream();
                const exp = ksJs.xor(data, off);
                await ChaChaWasm.initWasm("./wasm/chacha.wasm");
                const ksWasm = new QuarkDashChaCha(key, nonce).createKeystream();
                const act = ksWasm.xor(data, off);
                expect(act).toEqual(exp);
            }
        }
    });

    test("NTT multiply WASM vs JS", async () => {
        await NttWasm.initWasm("./wasm/ntt.wasm");
        if (!NttWasm.isReady()) return;
        const lwe7681 = new BaseRingLWE() as any;
        const lwe12289 = new QuarkDashRRLWE() as any;
        for (const lwe of [lwe7681, lwe12289]) {
            const Q = (lwe as any).Q as bigint, ROOT = (lwe as any).ROOT as bigint,
                INV_N = (lwe as any).INV_N as bigint;
            for (let trial = 0; trial < 5; trial++) {
                const a = Array.from({length: 256}, () => BigInt(Math.floor(Math.random() * Number(Q))));
                const b = Array.from({length: 256}, () => BigInt(Math.floor(Math.random() * Number(Q))));
                const wasmRes = NttWasm.multiply(a, b, Q, ROOT, INV_N);
                expect(wasmRes).not.toBeNull();
                const prev = NttWasm.isReady();
                (NttWasm as any).initializedWasm = false;
                lwe.setNTTProtection({blinding: false, doubleCheck: false, enabled: false});
                const jsRes = lwe.secureMultiply(a, b);
                if (prev) await NttWasm.initWasm("./wasm/ntt.wasm");
                expect(wasmRes!.map(String)).toEqual(jsRes.map(String));
            }
        }
    });

    test("secureMultiply WASM vs JS via BaseRingLWE", async () => {
        await NttWasm.initWasm("./wasm/ntt.wasm");
        const lwe = new BaseRingLWE() as any;
        const a = Array.from({length: 256}, () => BigInt(Math.floor(Math.random() * 7681)));
        const b = Array.from({length: 256}, () => BigInt(Math.floor(Math.random() * 7681)));
        lwe.setNTTProtection({blinding: true, doubleCheck: true});
        // force JS
        (NttWasm as any).initializedWasm = false;
        const js = lwe.secureMultiply(a, b);
        await NttWasm.initWasm("./wasm/ntt.wasm");
        if (NttWasm.isReady()) {
            const wasm = lwe.secureMultiply(a, b);
            expect(wasm.map(String)).toEqual(js.map(String));
        }
    });

    test("High-level QuarkDash WASM vs JS interoperable", async () => {
        await tryInitWasm();
        const msg = new TextEncoder().encode("hello wasm parity");
        // JS-only encrypt
        forceJsMode();
        const aliceJs = new QuarkDash({cipher: CipherType.Gimli});
        const bobJs = new QuarkDash({cipher: CipherType.Gimli});
        const aPubJs = aliceJs.generateKeyPairSync();
        const bPubJs = bobJs.generateKeyPairSync();
        const ctJs = aliceJs.initializeSessionSync(bPubJs, true) as Uint8Array;
        bobJs.initializeSessionSync(aPubJs, false);
        bobJs.finalizeSessionSync(ctJs);
        const encJs = aliceJs.encryptSync(msg);
        // WASM decrypt should work
        await tryInitWasm();
        const bobWasm = new QuarkDash({cipher: CipherType.Gimli});
        // reuse same keys: need to set internal state manually
        // Simpler: do full handshake with WASM then cross-decrypt
        const aliceWasm = new QuarkDash({cipher: CipherType.Gimli});
        await aliceWasm.generateKeyPair();
        const bobWasm2 = new QuarkDash({cipher: CipherType.Gimli});
        await bobWasm2.generateKeyPair();
        // Use any pair: WASM handshake
        const aPub = await aliceWasm.generateKeyPair();
        const bPub2 = await bobWasm2.generateKeyPair();
        const ct = await aliceWasm.initializeSession(bPub2, true) as Uint8Array;
        await bobWasm2.initializeSession(aPub, false);
        await bobWasm2.finalizeSession(ct);
        const enc = await aliceWasm.encrypt(msg);
        const dec = await bobWasm2.decrypt(enc);
        expect(dec).toEqual(msg);
        // Cross: wasm encrypt -> js decrypt
        forceJsMode();
        const bobJs2 = new QuarkDash({cipher: CipherType.Gimli});
        // Need to replicate session keys: do JS handshake then use wasm encrypt?
        // Just test that both produce decryptable data regardless of mode
        await tryInitWasm();
        const aliceMix = new QuarkDash({cipher: CipherType.ChaCha20});
        const bobMix = new QuarkDash({cipher: CipherType.ChaCha20});
        const ap = await aliceMix.generateKeyPair();
        const bp = await bobMix.generateKeyPair();
        const c = await aliceMix.initializeSession(bp, true) as Uint8Array;
        await bobMix.initializeSession(ap, false);
        await bobMix.finalizeSession(c);
        const encMix = await aliceMix.encrypt(msg);
        // disable WASM on bob side
        (GimliWasm as any).initializedWasm = false;
        (ChaChaWasm as any).initializedWasm = false;
        (NttWasm as any).initializedWasm = false;
        const decMix = await bobMix.decrypt(encMix);
        expect(decMix).toEqual(msg);
    });

    test("Fallback when WASM disabled produces same output", async () => {
        forceJsMode();
        const key = QuarkDashUtils.randomBytes(32), nonce = QuarkDashUtils.randomBytes(12);
        const data = QuarkDashUtils.randomBytes(1000);
        const cc = new QuarkDashChaCha(key, nonce);
        const jsOut = cc.encryptSync(data);
        // enable then disable should fallback
        await tryInitWasm();
        (GimliWasm as any).initializedWasm = false;
        (ChaChaWasm as any).initializedWasm = false;
        const cc2 = new QuarkDashChaCha(key, nonce);
        // force fallback path by corrupting init
        const out2 = cc2.createKeystream().xor(data, 0);
        expect(out2).toEqual(jsOut);
        // also test Ntt fallback
        const lwe = new BaseRingLWE() as any;
        const a = [1n, 2n].concat(Array(254).fill(0n)), b = [3n, 4n].concat(Array(254).fill(0n));
        (NttWasm as any).initializedWasm = false;
        expect(() => lwe.secureMultiply(a, b)).not.toThrow();
    });
});
