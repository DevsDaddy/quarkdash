import {
  CipherType,
  QuarkDash,
  QuarkDashUtils,
  QuarkDashChaCha,
  QuarkDashGimli,
  QuarkDashPassphrase,
  BaseRingLWE,
} from "../src";
import { performance } from "perf_hooks";

type Row = Record<string, string | number>;
const tableRows: Row[] = [];
const header = [
  "Operation",
  "QuarkDash Gimli",
  "QuarkDash ChaCha20",
  "AES-256-GCM",
  "Notes",
];

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
function fmtMBps(bytes: number, ms: number) {
  return (bytes / 1024 / 1024 / (ms / 1000)).toFixed(1);
}
function fmtMs(ms: number) {
  return `${ms.toFixed(2)} ms`;
}
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

async function main() {
  console.log("\x1b[1m%s\x1b[0m", `=== QuarkDash v1.2.0 Benchmark ===`);
  console.log(`Node ${process.version} | ${new Date().toISOString()}\n`);

  const encResults: Record<string, Record<number, number>> = {
    Gimli: {},
    ChaCha: {},
  };
  const decResults: Record<string, Record<number, number>> = {
    Gimli: {},
    ChaCha: {},
  };

  const sizes = [1024, 64 * 1024, 1024 * 1024];
  for (const byteslen of sizes) {
    const plain = QuarkDashUtils.randomBytes(byteslen);
    console.log(
      "\x1b[1m%s\x1b[0m",
      `--- Payload ${Math.round(byteslen / 1024)} KB ---`,
    );
    for (const ct of [CipherType.Gimli, CipherType.ChaCha20]) {
      const name = ct === CipherType.Gimli ? "Gimli" : "ChaCha";
      const alice = new QuarkDash({ cipher: ct });
      const bob = new QuarkDash({ cipher: ct });
      const aPub = await alice.generateKeyPair();
      const bPub = await bob.generateKeyPair();
      const ctext = (await alice.initializeSession(bPub, true)) as Uint8Array;
      await bob.initializeSession(aPub, false);
      await bob.finalizeSession(ctext);
      let enc: Uint8Array;
      const encMs = await measurePerf(
        `  ${name} encrypt ${byteslen}B`,
        async () => {
          enc = await alice.encrypt(plain);
        },
      );
      const decMs = await measurePerf(`  ${name} decrypt`, async () => {
        await bob.decrypt(enc!);
      });
      console.log(
        `    -> ${fmtMBps(byteslen, encMs)} MB/s encrypt, ${fmtMBps(byteslen, decMs)} MB/s decrypt`,
      );
      encResults[name][byteslen] = encMs;
      decResults[name][byteslen] = decMs;
    }
  }

  console.log("\n\x1b[1m%s\x1b[0m", "=== KEM / NTT ===");
  const kem: Record<string, number> = {};
  for (const prot of [
    { blinding: false, doubleCheck: false, label: "NTT fast" },
    { blinding: true, doubleCheck: true, label: "NTT hardened" },
  ]) {
    const lwe = new BaseRingLWE() as any;
    lwe.setNTTProtection(prot);
    kem[`KeyGen ${prot.label}`] = await measurePerf(
      `KeyGen ${prot.label}`,
      () => lwe.generateKeyPairSync(),
      20,
    );
    const alice = new QuarkDash({ cipher: CipherType.Gimli });
    const bob = new QuarkDash({ cipher: CipherType.Gimli });
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

  console.log("\n\x1b[1m%s\x1b[0m", "=== Lazy Keystream ===");
  const key = QuarkDashUtils.randomBytes(32);
  const nonce = QuarkDashUtils.randomBytes(12);
  const chacha = new QuarkDashChaCha(key, nonce);
  const gimli = new QuarkDashGimli(key, nonce);
  const big = QuarkDashUtils.randomBytes(2 * 1024 * 1024);
  const ksMs: Record<string, number> = {};
  ksMs["ChaCha 2MB"] = await measurePerf("ChaCha lazy xor 2MB", () =>
    (chacha as any).createKeystream().xor(big, 0),
  );
  ksMs["Gimli 2MB"] = await measurePerf("Gimli lazy xor 2MB", () =>
    (gimli as any).createKeystream().xor(big, 0),
  );
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
    const alice = new QuarkDash({ cipher: CipherType.ChaCha20 });
    const bob = new QuarkDash({ cipher: CipherType.ChaCha20 });
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
    } catch {}
  }

  for (const sz of sizes) {
    addRow(
      `Encrypt ${sz === 1024 ? "1KB" : sz === 64 * 1024 ? "64KB" : "1MB"}`,
      `${fmtMs(encResults["Gimli"][sz])} (${fmtMBps(sz, encResults["Gimli"][sz])} MB/s)`,
      `${fmtMs(encResults["ChaCha"][sz])} (${fmtMBps(sz, encResults["ChaCha"][sz])} MB/s)`,
      sz === 1024 * 1024 && aesEncMs
        ? `${fmtMs(aesEncMs)} (${fmtMBps(sz, aesEncMs)} MB/s)`
        : "-",
      sz === 1024 ? "per-msg nonce" : "",
    );
    addRow(
      `Decrypt ${sz === 1024 ? "1KB" : sz === 64 * 1024 ? "64KB" : "1MB"}`,
      fmtMs(decResults["Gimli"][sz]),
      fmtMs(decResults["ChaCha"][sz]),
      sz === 1024 * 1024 && aesDecMs ? fmtMs(aesDecMs) : "-",
      "",
    );
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
  addRow(
    "Keystream 2MB xor",
    fmtMs(ksMs["Gimli 2MB"]),
    fmtMs(ksMs["ChaCha 2MB"]),
    "-",
    "lazy seekable",
  );
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
