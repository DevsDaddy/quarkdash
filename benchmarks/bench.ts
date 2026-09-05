/**
 * QuarkDash Benchmarks
 *
 * @git             https://github.com/devsdaddy/quarkdash
 * @version         1.1.0
 * @author          Elijah Rastorguev
 * @build           1013
 * @website         https://dev.to/devsdaddy
 * @updated         05.09.2026
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
    Shake256,
    Shake256Wasm,
} from "../src";
import {GimliWasm} from "../src/cipher/gimli_wasm";
import {ChaChaWasm} from "../src/cipher/chacha_wasm";
import {NttWasm} from "../src/session/ntt_wasm";
import {performance} from "perf_hooks";

/* Benchmark Constants */
type Row = Record<string, string | number>;
const tableRows: Row[] = [];
const header = [
    "Operation",
    "QuarkDash Gimli",
    "QuarkDash ChaCha20",
    "AES-256-GCM",
    "Notes",
];

/**
 * Performance Measure
 * @param name
 * @param fn
 * @param iterations
 */
async function measurePerf(
    name: string,
    fn: () => any,
    iterations = 1,
): Promise<number> {
    const start = performance.now();
    for (let i = 0; i < iterations; i++) await fn();
    const end = performance.now();
    const avg = (end - start) / iterations;
    console.log(
        `${name}: ${avg.toFixed(3)} ms${iterations > 1 ? ` (x${iterations} avg)` : ""} | ${(end - start).toFixed(1)} ms total`,
    );
    return avg;
}

/**
 * Convert to MBps
 * @param bytes
 * @param ms
 */
function fmtMBps(bytes: number, ms: number) {
    return (bytes / 1024 / 1024 / (ms / 1000)).toFixed(1);
}

/**
 * Get ms
 * @param ms
 */
function fmtMs(ms: number) {
    return `${ms.toFixed(2)} ms`;
}

/**
 * Add table row
 * @param op
 * @param gimli
 * @param chacha
 * @param aes
 * @param notes
 */
function addRow(
    op: string,
    gimli: string,
    chacha: string,
    aes: string,
    notes = "",
) {
    tableRows.push({
        Operation: op,
        "QuarkDash Gimli": gimli,
        "QuarkDash ChaCha20": chacha,
        "AES-256-GCM": aes,
        Notes: notes,
    });
}

/**
 * Print table
 */
function printTable() {
    const cols = header;
    const widths = cols.map((c) =>
        Math.max(c.length, ...tableRows.map((r) => String(r[c] ?? "").length)),
    );
    const sep = "+" + widths.map((w) => "-".repeat(w + 2)).join("+") + "+";
    const row = (o: Row) =>
        "| " +
        cols.map((c, i) => String(o[c] ?? "").padEnd(widths[i])).join(" | ") +
        " |";
    console.log("\n" + sep);
    console.log(row(Object.fromEntries(header.map((h) => [h, h])) as Row));
    console.log(sep);
    for (const r of tableRows) {
        console.log(row(r));
    }
    console.log(sep);
}

/**
 * General benchmarks
 */
async function main() {
    console.log("\x1b[1m%s\x1b[0m", `=== QuarkDash v1.2.1 Benchmark ===`);
    console.log(`Node ${process.version} | ${new Date().toISOString()}\n`);

    const encResults: Record<string, Record<number, number>> = {
        Gimli: {},
        ChaCha: {},
    };
    const decResults: Record<string, Record<number, number>> = {
        Gimli: {},
        ChaCha: {},
    };
    const encStatic: Record<string, Record<number, number>> = {
        Gimli: {},
        ChaCha: {},
    };
    const decStatic: Record<string, Record<number, number>> = {
        Gimli: {},
        ChaCha: {},
    };

    const sizes = [1024, 64 * 1024, 1024 * 1024];
    for (const byteslen of sizes) {
        const plain = QuarkDashUtils.randomBytes(byteslen);
        console.log(
            "\x1b[1m%s\x1b[0m",
            `--- Payload ${Math.round(byteslen / 1024)} KB (per-message nonce) ---`,
        );
        for (const ct of [CipherType.Gimli, CipherType.ChaCha20]) {
            const name = ct === CipherType.Gimli ? "Gimli" : "ChaCha";
            const alice = new QuarkDash({cipher: ct});
            const bob = new QuarkDash({cipher: ct});
            const aPub = await alice.generateKeyPair();
            const bPub = await bob.generateKeyPair();
            const ctext = (await alice.initializeSession(bPub, true)) as Uint8Array;
            await bob.initializeSession(aPub, false);
            await bob.finalizeSession(ctext);
            let enc: Uint8Array;
            const encMs = await measurePerf(
                `  ${name} encrypt ${byteslen}B (per-msg nonce)`,
                async () => {
                    enc = await alice.encrypt(plain);
                },
            );
            const decMs = await measurePerf(`  ${name} decrypt (per-msg nonce)`, async () => {
                await bob.decrypt(enc!);
            });
            console.log(
                `    -> ${fmtMBps(byteslen, encMs)} MB/s encrypt, ${fmtMBps(byteslen, decMs)} MB/s decrypt`,
            );
            encResults[name][byteslen] = encMs;
            decResults[name][byteslen] = decMs;
        }
    }

    for (const byteslen of sizes) {
        const plain = QuarkDashUtils.randomBytes(byteslen);
        console.log(
            "\x1b[1m%s\x1b[0m",
            `--- Payload ${Math.round(byteslen / 1024)} KB (static nonce) ---`,
        );
        for (const ct of [CipherType.Gimli, CipherType.ChaCha20]) {
            const name = ct === CipherType.Gimli ? "Gimli" : "ChaCha";
            const alice = new QuarkDash({cipher: ct, usePerMessageNonce: false});
            const bob = new QuarkDash({cipher: ct, usePerMessageNonce: false});
            const aPub = await alice.generateKeyPair();
            const bPub = await bob.generateKeyPair();
            const ctext = (await alice.initializeSession(bPub, true)) as Uint8Array;
            await bob.initializeSession(aPub, false);
            await bob.finalizeSession(ctext);
            let enc: Uint8Array;
            const encMs = await measurePerf(
                `  ${name} encrypt ${byteslen}B (static nonce)`,
                async () => {
                    enc = await alice.encrypt(plain);
                },
            );
            const decMs = await measurePerf(`  ${name} decrypt (static nonce)`, async () => {
                await bob.decrypt(enc!);
            });
            console.log(
                `    -> ${fmtMBps(byteslen, encMs)} MB/s encrypt, ${fmtMBps(byteslen, decMs)} MB/s decrypt`,
            );
            encStatic[name][byteslen] = encMs;
            decStatic[name][byteslen] = decMs;
        }
    }

    console.log("\n\x1b[1m%s\x1b[0m", "=== SHAKE256 (JS vs WASM) ===");
    let shakeWasmReady = false;
    try {
        await Shake256Wasm.initWasm("./wasm/shake.wasm");
        shakeWasmReady = Shake256Wasm.initializedWasm;
        console.log(`WASM SHAKE ${shakeWasmReady ? "ready" : "fallback to JS"}`);
    } catch {
        console.log("WASM SHAKE fallback to JS");
    }
    const shakeSizes = [1024, 64 * 1024, 1024 * 1024];
    const shakeJs: Record<number, number> = {};
    const shakeWasmMs: Record<number, number> = {};
    for (const sz of shakeSizes) {
        const data = QuarkDashUtils.randomBytes(sz);
        shakeJs[sz] = await measurePerf(`SHAKE256 JS ${sz}B ->32B`, () => Shake256.hashSync(data, 32), 20);
        if (shakeWasmReady) {
            shakeWasmMs[sz] = await measurePerf(`SHAKE256 WASM ${sz}B ->32B`, () => Shake256Wasm.shake256Wasm(data, 32), 20);
            const speedup = (shakeJs[sz] / shakeWasmMs[sz]).toFixed(2);
            console.log(`  WASM speedup ${sz}B: ${speedup}x`);
        } else {
            shakeWasmMs[sz] = shakeJs[sz];
        }
    }
    // verify fallback correctness
    const chk = QuarkDashUtils.randomBytes(1024);
    const jsOut = Shake256.hashSync(chk, 32);
    let wasmOut: Uint8Array | null = null;
    if (shakeWasmReady) {
        wasmOut = Shake256Wasm.shake256Wasm(chk, 32);
        console.log(`SHAKE fallback check: ${Buffer.from(jsOut).equals(Buffer.from(wasmOut!)) ? "OK" : "MISMATCH"} (WASM vs JS)`);
    } else {
        wasmOut = Shake256.hashSync(chk, 32);
        console.log(`SHAKE fallback check: JS only (WASM not loaded) -> OK`);
    }

    console.log("\n\x1b[1m%s\x1b[0m", "=== KEM / NTT ===");
    const kem: Record<string, number> = {};
    for (const prot of [
        {blinding: false, doubleCheck: false, label: "NTT fast"},
        {blinding: true, doubleCheck: true, label: "NTT hardened"},
    ]) {
        const lwe = new BaseRingLWE() as any;
        lwe.setNTTProtection(prot);
        kem[`KeyGen ${prot.label}`] = await measurePerf(
            `KeyGen ${prot.label}`,
            () => lwe.generateKeyPairSync(),
            20,
        );
        const alice = new QuarkDash({cipher: CipherType.Gimli});
        const bob = new QuarkDash({cipher: CipherType.Gimli});
        (alice as any).config.keyExchange.setNTTProtection(prot);
        (bob as any).config.keyExchange.setNTTProtection(prot);
        kem[`Handshake ${prot.label}`] = await measurePerf(
            `Handshake ${prot.label}`,
            async () => {
                const ap = await alice.generateKeyPair();
                const bp = await bob.generateKeyPair();
                const ct = (await alice.initializeSession(bp, true)) as Uint8Array;
                await bob.initializeSession(ap, false);
                await bob.finalizeSession(ct);
            },
            10,
        );
    }

    // Add WASM Support
    console.log("\n\x1b[1m%s\x1b[0m", "=== WASM Gimli/ChaCha/NTT ===");
    let gimliWasmReady = false, chachaWasmReady = false, nttWasmReady = false;
    try {
        await GimliWasm.initWasm("./wasm/gimli.wasm");
        gimliWasmReady = GimliWasm.isReady();
    } catch {
        gimliWasmReady = false;
    }
    try {
        await ChaChaWasm.initWasm("./wasm/chacha.wasm");
        chachaWasmReady = ChaChaWasm.isReady();
    } catch {
        chachaWasmReady = false;
    }
    try {
        await NttWasm.initWasm("./wasm/ntt.wasm");
        nttWasmReady = NttWasm.isReady();
    } catch {
        nttWasmReady = false;
    }

    console.log(`WASM Gimli ${gimliWasmReady ? "ready" : "fallback"} | ChaCha ${chachaWasmReady ? "ready" : "fallback"} | NTT ${nttWasmReady ? "ready (SIMD)" : "fallback"}`);
    if (nttWasmReady) {
        const a = Array.from({length: 256}, (_, i) => BigInt(i % 7681));
        const b = Array.from({length: 256}, (_, i) => BigInt((i * 2) % 7681));

        const lwe = new BaseRingLWE() as any;
        lwe.setNTTProtection({blinding: false, doubleCheck: false, enabled: false});

        const was = (NttWasm as any).initializedWasm;
        (NttWasm as any).initializedWasm = false;

        const jsMs = await measurePerf("NTT multiply 256 JS", () => lwe.secureMultiply(a, b), 200);
        (NttWasm as any).initializedWasm = was;

        const wasmMs = await measurePerf("NTT multiply 256 WASM", () => lwe.secureMultiply(a, b), 200);
        console.log(`  NTT speedup: ${(jsMs / wasmMs).toFixed(2)}x`);

        const was2 = (NttWasm as any).initializedWasm;

        // Handshake WASM vs JS
        const aliceW = new QuarkDash({cipher: CipherType.Gimli});
        const bobW = new QuarkDash({cipher: CipherType.Gimli});
        const wasmHs = await measurePerf("Handshake NTT WASM (Gimli)", async () => {
            const ap = await aliceW.generateKeyPair();
            const bp = await bobW.generateKeyPair();
            const ct = await aliceW.initializeSession(bp, true) as Uint8Array;
            await bobW.initializeSession(ap, false);
            await bobW.finalizeSession(ct);
        }, 10);
        (NttWasm as any).initializedWasm = false;

        const aliceJ = new QuarkDash({cipher: CipherType.Gimli});
        const bobJ = new QuarkDash({cipher: CipherType.Gimli});

        (aliceJ as any).config.keyExchange.setNTTProtection({blinding: false, doubleCheck: false, enabled: false});
        (bobJ as any).config.keyExchange.setNTTProtection({blinding: false, doubleCheck: false, enabled: false});

        const jsHs = await measurePerf("Handshake NTT JS (Gimli)", async () => {
            const ap = await aliceJ.generateKeyPair();
            const bp = await bobJ.generateKeyPair();
            const ct = await aliceJ.initializeSession(bp, true) as Uint8Array;
            await bobJ.initializeSession(ap, false);
            await bobJ.finalizeSession(ct);
        }, 10);
        console.log(`  Handshake speedup: ${(jsHs / wasmHs).toFixed(2)}x`);
        (NttWasm as any).initializedWasm = was2;
    }

    // Force JS
    console.log("\n\x1b[1m%s\x1b[0m", "=== Lazy Keystream ===");
    const key = QuarkDashUtils.randomBytes(32);
    const nonce = QuarkDashUtils.randomBytes(12);

    const chacha = new QuarkDashChaCha(key, nonce);
    const gimli = new QuarkDashGimli(key, nonce);

    const big = QuarkDashUtils.randomBytes(2 * 1024 * 1024);
    const ksMs: Record<string, number> = {};

    const forceJs = (flag: { v: boolean }, fn: () => any) => {
        const wasG = (GimliWasm as any).initializedWasm, wasC = (ChaChaWasm as any).initializedWasm;
        if (flag.v) {
            (GimliWasm as any).initializedWasm = false;
            (ChaChaWasm as any).initializedWasm = false;
        }

        const r = fn();
        (GimliWasm as any).initializedWasm = wasG;
        (ChaChaWasm as any).initializedWasm = wasC;

        return r;
    };

    // JS baselines (force fallback)
    {
        const wasG = (GimliWasm as any).initializedWasm, wasC = (ChaChaWasm as any).initializedWasm;
        (GimliWasm as any).initializedWasm = false;
        (ChaChaWasm as any).initializedWasm = false;
        ksMs["ChaCha 2MB JS"] = await measurePerf("ChaCha lazy xor 2MB JS", () => (chacha as any).createKeystream().xor(big, 0));
        ksMs["Gimli 2MB JS"] = await measurePerf("Gimli lazy xor 2MB JS", () => (gimli as any).createKeystream().xor(big, 0));
        (GimliWasm as any).initializedWasm = wasG;
        (ChaChaWasm as any).initializedWasm = wasC;
    }

    if (gimliWasmReady || chachaWasmReady) {
        ksMs["ChaCha 2MB WASM"] = await measurePerf("ChaCha lazy xor 2MB WASM", () => (chacha as any).createKeystream().xor(big, 0));
        ksMs["Gimli 2MB WASM"] = await measurePerf("Gimli lazy xor 2MB WASM", () => (gimli as any).createKeystream().xor(big, 0));
        if (ksMs["ChaCha 2MB JS"] && ksMs["ChaCha 2MB WASM"]) console.log(`  ChaCha speedup: ${(ksMs["ChaCha 2MB JS"] / ksMs["ChaCha 2MB WASM"]).toFixed(2)}x`);
        if (ksMs["Gimli 2MB JS"] && ksMs["Gimli 2MB WASM"]) console.log(`  Gimli speedup: ${(ksMs["Gimli 2MB JS"] / ksMs["Gimli 2MB WASM"]).toFixed(2)}x`);
    } else {
        ksMs["ChaCha 2MB WASM"] = ksMs["ChaCha 2MB JS"];
        ksMs["Gimli 2MB WASM"] = ksMs["Gimli 2MB JS"];
    }

    // verify
    {
        const wasG = (GimliWasm as any).initializedWasm, wasC = (ChaChaWasm as any).initializedWasm;
        (GimliWasm as any).initializedWasm = false;
        (ChaChaWasm as any).initializedWasm = false;

        const js = (chacha as any).createKeystream().xor(big.slice(0, 1024), 0);
        (GimliWasm as any).initializedWasm = wasG;
        (ChaChaWasm as any).initializedWasm = wasC;

        const wasm = (chacha as any).createKeystream().xor(big.slice(0, 1024), 0);
        console.log(`ChaCha fallback check: ${Buffer.from(js).equals(Buffer.from(wasm)) ? "OK" : "MISMATCH"}`);

        const gjs = (gimli as any).createKeystream().xor(big.slice(0, 1024), 0);
        const was2 = (GimliWasm as any).initializedWasm;
        (GimliWasm as any).initializedWasm = wasG;

        const gwasm = (gimli as any).createKeystream().xor(big.slice(0, 1024), 0);
        console.log(`Gimli fallback check: ${Buffer.from(gjs).equals(Buffer.from(gwasm)) ? "OK" : "MISMATCH"}`);
    }

    ksMs["seek 64KB@1M"] = await measurePerf(
        "ChaCha getBytes seek 64KB @1M offset",
        () => (chacha as any).createKeystream().getBytes(1024 * 1024, 64 * 1024),
    );

    ksMs["blocks 32"] = await measurePerf(
        "ChaCha blocks generator 32 blocks",
        () => {
            let n = 0;
            for (const _ of (chacha as any).keystreamBlocks(0)) {
                if (++n >= 32) break;
            }
        },
    );

    console.log("\n\x1b[1m%s\x1b[0m", "=== Re-keying ===");
    const rk: Record<string, number> = {};
    {
        const alice = new QuarkDash({cipher: CipherType.ChaCha20});
        const bob = new QuarkDash({cipher: CipherType.ChaCha20});
        const ap = await alice.generateKeyPair();
        const bp = await bob.generateKeyPair();
        const ct = (await alice.initializeSession(bp, true)) as Uint8Array;
        await bob.initializeSession(ap, false);
        await bob.finalizeSession(ct);
        rk["async"] = await measurePerf(
            "rekey (generate token)",
            async () => {
                const t = await alice.rekey();
                await bob.applyRekey(t);
            },
            20,
        );
        rk["sync"] = await measurePerf(
            "rekeySync",
            () => {
                const t = alice.rekeySync();
                bob.applyRekeySync(t);
            },
            50,
        );
    }

    console.log("\n\x1b[1m%s\x1b[0m", "=== Passphrase KDF ===");
    const salt = QuarkDashPassphrase.generateSalt(32);
    const kdf: Record<string, number> = {};
    kdf["PBKDF2 100k"] = await measurePerf("PBKDF2 100k iter (sync)", () =>
        QuarkDashPassphrase.pbkdf2Sync("password", salt, 100_000, 32),
    );
    kdf["PBKDF2 10k"] = await measurePerf("PBKDF2 10k iter (sync)", () =>
        QuarkDashPassphrase.pbkdf2Sync("password", salt, 10_000, 32),
    );
    kdf["Argon2 32/3"] = await measurePerf("Argon2id-lite 32MB/3t (sync)", () =>
        QuarkDashPassphrase.argon2idSync("password", salt, 32, 3, 32),
    );
    kdf["Argon2 8/1"] = await measurePerf("Argon2id-lite 8MB/1t (sync)", () =>
        QuarkDashPassphrase.argon2idSync("password", salt, 8, 1, 32),
    );

    let aesEncMs = 0,
        aesDecMs = 0;
    if (typeof require !== "undefined") {
        try {
            const crypto = require("crypto");
            console.log("\x1b[1m%s\x1b[0m", "\n=== AES-256-GCM (Node crypto) ===");
            const plain = QuarkDashUtils.randomBytes(1024 * 1024);
            const aesKey = crypto.randomBytes(32);
            const iv = crypto.randomBytes(12);
            const s = performance.now();
            const c = crypto.createCipheriv("aes-256-gcm", aesKey, iv);
            const enc = Buffer.concat([c.update(plain), c.final()]);
            const tag = c.getAuthTag();
            aesEncMs = performance.now() - s;
            console.log(
                `encrypt 1MB: ${aesEncMs.toFixed(3)} ms | ${fmtMBps(plain.length, aesEncMs)} MB/s`,
            );
            const s2 = performance.now();
            const d = crypto.createDecipheriv("aes-256-gcm", aesKey, iv);
            d.setAuthTag(tag);
            Buffer.concat([d.update(enc), d.final()]);
            aesDecMs = performance.now() - s2;
            console.log(`decrypt 1MB: ${aesDecMs.toFixed(3)} ms`);
        } catch {
        }
    }

    for (const sz of sizes) {
        addRow(
            `Encrypt ${sz === 1024 ? "1KB" : sz === 64 * 1024 ? "64KB" : "1MB"} (per-msg nonce)`,
            `${fmtMs(encResults["Gimli"][sz])} (${fmtMBps(sz, encResults["Gimli"][sz])} MB/s)`,
            `${fmtMs(encResults["ChaCha"][sz])} (${fmtMBps(sz, encResults["ChaCha"][sz])} MB/s)`,
            sz === 1024 * 1024 && aesEncMs
                ? `${fmtMs(aesEncMs)} (${fmtMBps(sz, aesEncMs)} MB/s)`
                : "-",
            "per-msg nonce",
        );
        addRow(
            `Decrypt ${sz === 1024 ? "1KB" : sz === 64 * 1024 ? "64KB" : "1MB"} (per-msg nonce)`,
            fmtMs(decResults["Gimli"][sz]),
            fmtMs(decResults["ChaCha"][sz]),
            sz === 1024 * 1024 && aesDecMs ? fmtMs(aesDecMs) : "-",
            "per-msg nonce",
        );
    }
    for (const sz of sizes) {
        addRow(
            `Encrypt ${sz === 1024 ? "1KB" : sz === 64 * 1024 ? "64KB" : "1MB"} (static nonce)`,
            `${fmtMs(encStatic["Gimli"][sz])} (${fmtMBps(sz, encStatic["Gimli"][sz])} MB/s)`,
            `${fmtMs(encStatic["ChaCha"][sz])} (${fmtMBps(sz, encStatic["ChaCha"][sz])} MB/s)`,
            "-",
            "static nonce",
        );
        addRow(
            `Decrypt ${sz === 1024 ? "1KB" : sz === 64 * 1024 ? "64KB" : "1MB"} (static nonce)`,
            fmtMs(decStatic["Gimli"][sz]),
            fmtMs(decStatic["ChaCha"][sz]),
            "-",
            "static nonce",
        );
    }
    for (const sz of shakeSizes) {
        const label = sz === 1024 ? "1KB" : sz === 64 * 1024 ? "64KB" : "1MB";
        addRow(
            `SHAKE256 ${label} JS`,
            fmtMs(shakeJs[sz]),
            "-",
            "-",
            "JS fallback",
        );
        if (shakeWasmReady) {
            addRow(
                `SHAKE256 ${label} WASM`,
                fmtMs(shakeWasmMs[sz]),
                "-",
                "-",
                `WASM ${((shakeJs[sz] / shakeWasmMs[sz]).toFixed(2))}x`,
            );
        }
    }
    addRow(
        "KeyGen",
        fmtMs(kem["KeyGen NTT fast"]),
        fmtMs(kem["KeyGen NTT hardened"]),
        "-",
        "blinding+doubleCheck",
    );
    addRow(
        "Handshake",
        fmtMs(kem["Handshake NTT fast"]),
        fmtMs(kem["Handshake NTT hardened"]),
        "-",
        "",
    );
    const gimliJsMs = ksMs["Gimli 2MB JS"] ?? ksMs["Gimli 2MB"];
    const gimliWasmMs = ksMs["Gimli 2MB WASM"] ?? gimliJsMs;
    const chachaJsMs = ksMs["ChaCha 2MB JS"] ?? ksMs["ChaCha 2MB"];
    const chachaWasmMs = ksMs["ChaCha 2MB WASM"] ?? chachaJsMs;
    addRow("Keystream 2MB Gimli JS", fmtMs(gimliJsMs), "-", "-", "lazy JS");
    if (gimliWasmReady) addRow("Keystream 2MB Gimli WASM", fmtMs(gimliWasmMs), "-", "-", `WASM ${(gimliJsMs / gimliWasmMs).toFixed(2)}x`);
    addRow("Keystream 2MB ChaCha JS", fmtMs(chachaJsMs), "-", "-", "lazy JS");
    if (chachaWasmReady) addRow("Keystream 2MB ChaCha WASM", fmtMs(chachaWasmMs), "-", "-", `WASM ${(chachaJsMs / chachaWasmMs).toFixed(2)}x`);
    addRow(
        "Keystream seek 64KB@1M",
        fmtMs(ksMs["seek 64KB@1M"]),
        "-",
        "-",
        "no regen",
    );
    addRow("Re-key async", fmtMs(rk["async"]), "-", "-", "token+apply");
    addRow("Re-key sync", fmtMs(rk["sync"]), "-", "-", "");
    addRow("PBKDF2 100k", fmtMs(kdf["PBKDF2 100k"]), "-", "-", "HMAC-SHA256");
    addRow("PBKDF2 10k", fmtMs(kdf["PBKDF2 10k"]), "-", "-", "");
    addRow(
        "Argon2 32MB/3t",
        fmtMs(kdf["Argon2 32/3"]),
        "-",
        "-",
        "SHAKE256 mem-hard",
    );
    addRow("Argon2 8MB/1t", fmtMs(kdf["Argon2 8/1"]), "-", "-", "");

    console.log("\x1b[1m%s\x1b[0m", "\n=== Comparative Table ===");
    printTable();
    console.log("\n=== Benchmark completed ===");
}

main().catch(console.error);
