/**
 * QuarkDash Protocol Passphrase KDF
 * This method is allowed to use protocol without full featured
 * Ring-LWE handshake with password. The passphrase is based
 * on PBDKF2 and Argon2id Lite
 *
 * - PBKDF2 is a classical algorythm (NodeJS native) with HMAC-SHA256 for browser
 * - Argon2id lite - our lightweight memory-hard version with Shake256
 *
 * Both variant is deterministic: one password + one salt = one key
 *
 * @git             https://github.com/devsdaddy/quarkdash
 * @version         1.2.0
 * @author          Elijah Rastorguev
 * @build           1023
 * @website         https://dev.to/devsdaddy
 * @updated         22.08.2026
 */
/* Import required modules */
import {SHA256} from "../hash/sha";
import {QuarkDashUtils} from "./utils";
import {Shake256} from "../hash/shake";

/**
 * HMAC + SHA256 Manual for PBKDF2
 * if Node crypto is not defined
 * @param key {Uint8Array} Key
 * @param data {Uint8Array} Data
 */
function hmacSha256(key: Uint8Array, data: Uint8Array): Uint8Array {
    const blockSize = 64;
    let k = key;

    // If key larger than block - hash. Or fill zeros.
    if (k.length > blockSize) k = SHA256.hash(k, true) as Uint8Array;
    if (k.length < blockSize) {
        const tmp = new Uint8Array(blockSize);
        tmp.set(k);
        k = tmp;
    }

    // Classic HMAC: oPad = k xor 0x5c, iPad = k xor 0x36
    const oKeyPad = new Uint8Array(blockSize);
    const iKeyPad = new Uint8Array(blockSize);
    for (let i = 0; i < blockSize; i++) {
        oKeyPad[i] = k[i] ^ 0x5c;
        iKeyPad[i] = k[i] ^ 0x36;
    }

    const inner = SHA256.hash(
        QuarkDashUtils.concatBytes(iKeyPad, data),
        true,
    ) as Uint8Array;
    return SHA256.hash(
        QuarkDashUtils.concatBytes(oKeyPad, inner),
        true,
    ) as Uint8Array;
}

/**
 * PBKDF2 - HMAC - SHA256 (RFC 8018)
 * with pure typescript without dependency
 * @param password {Uint8Array} Password
 * @param salt {Uint8Array} Salt
 * @param iterations {number} Number of iterations
 * @param dkLen {number} dk length
 */
function pbkdf2Sync(
    password: Uint8Array,
    salt: Uint8Array,
    iterations: number,
    dkLen: number,
): Uint8Array {
    if (iterations < 1) throw new Error("Iterations must be >=1");

    const hLen = 32; // SHA256 = 32B
    const l = Math.ceil(dkLen / hLen);
    const r = dkLen - (l - 1) * hLen;
    const out = new Uint8Array(dkLen);

    for (let i = 1; i <= l; i++) {
        // INT(i) : big-endian 4 bytes
        const intBlock = new Uint8Array(4);
        intBlock[0] = (i >>> 24) & 0xff;
        intBlock[1] = (i >>> 16) & 0xff;
        intBlock[2] = (i >>> 8) & 0xff;
        intBlock[3] = i & 0xff;

        let U = hmacSha256(password, QuarkDashUtils.concatBytes(salt, intBlock));
        const T = new Uint8Array(U);

        // U2 = HMAC(P, U1), U3 = HMAC(P, U2)... and XOR
        for (let c = 1; c < iterations; c++) {
            U = hmacSha256(password, U);
            for (let k = 0; k < hLen; k++) T[k] ^= U[k];
        }

        const destPos = (i - 1) * hLen;
        const len = i === l ? r : hLen;
        out.set(T.subarray(0, len), destPos);
    }
    return out;
}

/**
 * Argon2id Lite
 * Simplified memory-hard implementation based on SHAKE256
 *
 * We do not complete full Argon2, but with same idea:
 * fill memory and randomise blocks.
 *
 * @param password {Uint8Array} Password
 * @param salt {Uint8Array} Salt
 * @param memoryCost {number} Memory cost
 * @param timeCost {number} Time cost
 * @param dkLen {number} dk Length
 */
function argon2idLiteSync(
    password: Uint8Array,
    salt: Uint8Array,
    memoryCost: number,
    timeCost: number,
    dkLen: number,
): Uint8Array {
    const mCost = Math.max(8, memoryCost); // минимум 8 KB
    const tCost = Math.max(1, timeCost);
    const blockSize = 64;
    const blocks = Math.floor((mCost * 1024) / blockSize);

    const mem: Uint8Array[] = new Array(blocks);

    // Initial - password hash + salt + parameters
    const params = QuarkDashUtils.concatBytes(
        password,
        salt,
        new Uint8Array([mCost & 0xff, (mCost >> 8) & 0xff, tCost & 0xff]),
    );
    mem[0] = Shake256.hashSync(
        QuarkDashUtils.concatBytes(params, new Uint8Array([0, 0, 0, 0])),
        blockSize,
    );

    // chaining: every block SHAKE(prev || counter)
    for (let i = 1; i < blocks; i++) {
        const ctr = new Uint8Array(4);
        ctr[0] = i & 0xff;
        ctr[1] = (i >> 8) & 0xff;
        ctr[2] = (i >> 16) & 0xff;
        ctr[3] = (i >> 24) & 0xff;
        mem[i] = Shake256.hashSync(
            QuarkDashUtils.concatBytes(mem[i - 1], ctr),
            blockSize,
        );
    }

    // Mix with timecost rounds: pseudo-random j and mix i with j
    for (let t = 0; t < tCost; t++) {
        for (let i = 0; i < blocks; i++) {
            const pseudo =
                mem[i][0] | (mem[i][1] << 8) | (mem[i][2] << 16) | (mem[i][3] << 24);
            const j = Math.abs(pseudo) % blocks;
            const mixed = Shake256.hashSync(
                QuarkDashUtils.concatBytes(
                    mem[i],
                    mem[j],
                    new Uint8Array([t & 0xff, i & 0xff]),
                ),
                blockSize,
            );
            for (let k = 0; k < blockSize; k++) mem[i][k] ^= mixed[k];
            mem[i] = Shake256.hashSync(mem[i], blockSize);
        }
    }

    // Final hash from first blocks + erase memory (clean from RAM)
    const final = Shake256.hashSync(
        QuarkDashUtils.concatBytes(...mem.slice(0, Math.min(8, blocks))),
        dkLen,
    );
    for (let i = 0; i < blocks; i++) QuarkDashUtils.secureZero(mem[i]);
    return final;
}

/**
 * Passphrase Options
 */
export interface PassphraseOptions {
    salt?: Uint8Array;
    iterations?: number;
    memoryCost?: number;
    timeCost?: number;
    keyLength?: number;
    algorithm?: "pbkdf2" | "argon2id";
}

/**
 * QuarkDash Passphrase
 */
export class QuarkDashPassphrase {
    /**
     * Generate salt
     * @param length {number} Length (by default: 32b)
     */
    public static generateSalt(length: number = 32): Uint8Array {
        return QuarkDashUtils.randomBytes(length);
    }

    /**
     * PBKDF2 in sync mode
     * @param passphrase {string | Uint8Array} Passphrase
     * @param salt {Uint8Array} Salt
     * @param iterations {number} Number of iterations
     * @param dkLen {number} dk length
     */
    public static pbkdf2Sync(
        passphrase: string | Uint8Array,
        salt: Uint8Array,
        iterations: number = 100000,
        dkLen: number = 32,
    ): Uint8Array {
        const pwd =
            typeof passphrase === "string"
                ? QuarkDashUtils.textToBytes(passphrase)
                : passphrase;
        const res = pbkdf2Sync(pwd, salt, iterations, dkLen);
        if (typeof passphrase === "string") QuarkDashUtils.secureZero(pwd);
        return res;
    }

    /**
     * PBKDF2 (uses crypto.pbkdf2 if available, or fallback function from QuarkDash)
     * @param passphrase {string | Uint8Array} Passphrase
     * @param salt {Uint8Array} Salt
     * @param iterations {number} Number of Iterations
     * @param dkLen {number} dk length
     */
    public static async pbkdf2(
        passphrase: string | Uint8Array,
        salt: Uint8Array,
        iterations: number = 100000,
        dkLen: number = 32,
    ): Promise<Uint8Array> {
        const pwd =
            typeof passphrase === "string"
                ? QuarkDashUtils.textToBytes(passphrase)
                : passphrase;
        try {
            if (typeof process !== "undefined" && process.versions?.node) {
                const crypto = await import("crypto");
                if ((crypto as any).pbkdf2) {
                    const bufPwd = Buffer.from(pwd);
                    const bufSalt = Buffer.from(salt);
                    const derived: Buffer = await new Promise((res, rej) =>
                        (crypto as any).pbkdf2(
                            bufPwd,
                            bufSalt,
                            iterations,
                            dkLen,
                            "sha256",
                            (e: any, d: Buffer) => (e ? rej(e) : res(d)),
                        ),
                    );
                    const out = new Uint8Array(derived);
                    if (typeof passphrase === "string") QuarkDashUtils.secureZero(pwd);
                    return out;
                }
            }
        } catch {
        }
        const out = pbkdf2Sync(pwd, salt, iterations, dkLen);
        if (typeof passphrase === "string") QuarkDashUtils.secureZero(pwd);
        return out;
    }

    /**
     * Argon2id in sync mode
     * @param passphrase {string | Uint8Array} Passphrase
     * @param salt {Uint8Array} Salt
     * @param memoryCost {number} Memory cost
     * @param timeCost {number} Time cost
     * @param dkLen {number} dk length
     */
    public static argon2idSync(
        passphrase: string | Uint8Array,
        salt: Uint8Array,
        memoryCost: number = 32,
        timeCost: number = 3,
        dkLen: number = 32,
    ): Uint8Array {
        const pwd =
            typeof passphrase === "string"
                ? QuarkDashUtils.textToBytes(passphrase)
                : passphrase;
        const res = argon2idLiteSync(pwd, salt, memoryCost, timeCost, dkLen);
        if (typeof passphrase === "string") QuarkDashUtils.secureZero(pwd);
        return res;
    }

    /**
     * Argon2id
     * @param passphrase {string | Uint8Array} Passphrase
     * @param salt {Uint8Array} Salt
     * @param memoryCost {number} Memory cost
     * @param timeCost {number} Time cost
     * @param dkLen {number} dk length
     */
    public static async argon2id(
        passphrase: string | Uint8Array,
        salt: Uint8Array,
        memoryCost: number = 32,
        timeCost: number = 3,
        dkLen: number = 32,
    ): Promise<Uint8Array> {
        return QuarkDashPassphrase.argon2idSync(
            passphrase,
            salt,
            memoryCost,
            timeCost,
            dkLen,
        );
    }

    /**
     * Universal derive
     * @param passphrase {string | Uint8Array} Passphrase
     * @param opts {PassphraseOptions} Passphrase Options
     */
    public static async derive(
        passphrase: string | Uint8Array,
        opts: PassphraseOptions = {},
    ): Promise<{ key: Uint8Array; salt: Uint8Array }> {
        const salt = opts.salt ?? QuarkDashPassphrase.generateSalt(32);
        const dkLen = opts.keyLength ?? 32;
        const algo = opts.algorithm ?? "argon2id";
        const key =
            algo === "pbkdf2"
                ? await QuarkDashPassphrase.pbkdf2(
                    passphrase,
                    salt,
                    opts.iterations ?? 100000,
                    dkLen,
                )
                : await QuarkDashPassphrase.argon2id(
                    passphrase,
                    salt,
                    opts.memoryCost ?? 32,
                    opts.timeCost ?? 3,
                    dkLen,
                );
        return {key, salt};
    }

    /**
     * Universal derive in sync mode
     * @param passphrase {string | Uint8Array} Passphrase
     * @param opts {PassphraseOptions} Passphrase Options
     */
    public static deriveSync(
        passphrase: string | Uint8Array,
        opts: PassphraseOptions = {},
    ): { key: Uint8Array; salt: Uint8Array } {
        const salt = opts.salt ?? QuarkDashPassphrase.generateSalt(32);
        const dkLen = opts.keyLength ?? 32;
        const algo = opts.algorithm ?? "argon2id";
        const key =
            algo === "pbkdf2"
                ? QuarkDashPassphrase.pbkdf2Sync(
                    passphrase,
                    salt,
                    opts.iterations ?? 100000,
                    dkLen,
                )
                : QuarkDashPassphrase.argon2idSync(
                    passphrase,
                    salt,
                    opts.memoryCost ?? 32,
                    opts.timeCost ?? 3,
                    dkLen,
                );
        return {key, salt};
    }

    /**
     * Derive key for QuarkDash (32B session + 32B MAC)
     * @param passphrase {string | Uint8Array} Passphrase
     * @param salt {Uint8Array} Salt
     * @param opts {PassphraseOptions} Passphrase Options
     */
    public static async deriveKeyForQuarkDash(
        passphrase: string | Uint8Array,
        salt: Uint8Array,
        opts: PassphraseOptions = {},
    ): Promise<{ sessionKey: Uint8Array; macKey: Uint8Array; salt: Uint8Array }> {
        const dkLen = 64;
        const algo = opts.algorithm ?? "argon2id";
        const key =
            algo === "pbkdf2"
                ? await QuarkDashPassphrase.pbkdf2(
                    passphrase,
                    salt,
                    opts.iterations ?? 100000,
                    dkLen,
                )
                : await QuarkDashPassphrase.argon2id(
                    passphrase,
                    salt,
                    opts.memoryCost ?? 32,
                    opts.timeCost ?? 3,
                    dkLen,
                );
        return {sessionKey: key.slice(0, 32), macKey: key.slice(32, 64), salt};
    }
}
