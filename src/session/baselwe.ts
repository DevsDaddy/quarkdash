/**
 * QuarkDash Protocol Base Ring-LWE
 * Here you can find all maths: polynome, NTT, errors.
 *
 * What's new in 1.2.0:
 * - Normalized coefficient ((v%Q)+Q)%Q
 * - NTT hardened: blinding + double-check (hardware bugs catching)
 * - Input validation and wlen cache for speed-up
 *
 * @git             https://github.com/devsdaddy/quarkdash
 * @version         1.2.0
 * @author          Elijah Rastorguev
 * @build           1030
 * @website         https://dev.to/devsdaddy
 * @updated         28.08.2026
 */
/* Import required modules */
import {QuarkDashUtils} from "../core/utils";
import {SHA256} from "../hash/sha";
import {ICryptoEncapsulated, ICryptoKeyPair} from "../core/types";
import {DEFAULT_NTT_PROTECTION, NTTProtectionOptions} from "./ntt_protection";

/**
 * Base Ring LWE
 */
export class BaseRingLWE {
    // Ring parameters: override in child RLWE and RRLWE
    protected readonly N: number = 256;
    protected readonly Q: bigint = 7681n;
    protected readonly ROOT: bigint = 5685n;
    protected readonly INV_N: bigint = this.modInverse(BigInt(this.N), this.Q);

    // NTT Security setup (can be disabled for benchmarks)
    protected nttProtection: NTTProtectionOptions = {...DEFAULT_NTT_PROTECTION};
    private wlenCache = new Map<number, bigint>();
    private invWlenCache = new Map<number, bigint>();

    /**
     * Set NTT Protection Options
     * @param opts {Partial<NTTProtectionOptions>} Protection Options
     */
    public setNTTProtection(opts: Partial<NTTProtectionOptions>): void {
        this.nttProtection = {...this.nttProtection, ...opts};
    }

    /**
     * Get NTT Protection Options
     */
    public getNTTProtection(): NTTProtectionOptions {
        return {...this.nttProtection};
    }

    /* WORK WITH KEYS */
    /**
     * Generate Key Pair
     */
    public async generateKeyPair(): Promise<ICryptoKeyPair> {
        return this.generateKeyPairSync();  // TODO: Add gpu calculations, now is just a proxy
    }

    /**
     * Generate Key Pair in sync mode
     */
    public generateKeyPairSync(): ICryptoKeyPair {
        const a = this.uniformPoly(); // random public polynome
        const s = this.smallPoly(); // secret small polynome (-1,0,1)
        const e = this.errorPoly(); // noise for grid

        const as = this.multiply(a, s); // a·s in NTT

        // b = a·s + e  (mod Q): classical LWE
        const b = new Array<bigint>(this.N);
        for (let i = 0; i < this.N; i++)
            b[i] = (((as[i] + e[i]) % this.Q) + this.Q) % this.Q;

        // pack: [a | b] for peer normalization
        const publicKey = QuarkDashUtils.concatBytes(
            this.serializePoly(a),
            this.serializePoly(b),
        );
        const privateKey = this.serializePoly(s);
        return {publicKey, privateKey};
    }

    /* KEY ENCAPSULATION */
    /**
     * Encapsulate key
     * @param publicKey {Uint8Array} Public key
     */
    public async encapsulate(
        publicKey: Uint8Array,
    ): Promise<ICryptoEncapsulated> {
        return this.encapsulateSync(publicKey);
    }

    /**
     * Encapsulate key in sync mode
     * @param publicKey {Uint8Array} Public key
     */
    public encapsulateSync(publicKey: Uint8Array): ICryptoEncapsulated {
        this.validatePublicKey(publicKey);

        const a = this.deserializePoly(publicKey.slice(0, this.N * 2));
        const b = this.deserializePoly(publicKey.slice(this.N * 2));

        const sp = this.smallPoly();
        const ep = this.errorPoly();

        const uArr = this.secureMultiply(a, sp);
        for (let i = 0; i < this.N; i++)
            uArr[i] = (((uArr[i] + ep[i]) % this.Q) + this.Q) % this.Q;

        const w = this.secureMultiply(b, sp);
        const {bits: rawSecret, hint} = this.roundToBitsWithHint(w);

        const uBytes = this.serializePoly(uArr);
        const ciphertext = QuarkDashUtils.concatBytes(uBytes, hint);
        const sharedSecret = this.hashSharedSecretSync(
            rawSecret,
            publicKey,
            ciphertext,
        );
        return {ciphertext, sharedSecret};
    }

    /**
     * Decapsulate
     * @param privateKey {Uint8Array} Private Key
     * @param peerPublicKey {Uint8Array} Peer Public Key
     * @param ciphertext {Uint8Array} Ciphertext
     */
    public async decapsulate(
        privateKey: Uint8Array,
        peerPublicKey: Uint8Array,
        ciphertext: Uint8Array,
    ): Promise<Uint8Array> {
        return this.decapsulateSync(privateKey, peerPublicKey, ciphertext);
    }

    /**
     * Decapsulate in sync mode
     * @param privateKey {Uint8Array} Private Key
     * @param peerPublicKey {Uint8Array} Peer Public Key
     * @param ciphertext {Uint8Array} Ciphertext
     */
    public decapsulateSync(
        privateKey: Uint8Array,
        peerPublicKey: Uint8Array,
        ciphertext: Uint8Array,
    ): Uint8Array {
        this.validatePrivateKey(privateKey);
        this.validateCiphertext(ciphertext);
        this.validatePublicKey(peerPublicKey);

        const s = this.deserializePoly(privateKey);
        let u: bigint[];
        let hint: Uint8Array;
        if (ciphertext.length === this.N * 2 + 32) {
            u = this.deserializePoly(ciphertext.slice(0, this.N * 2));
            hint = ciphertext.slice(this.N * 2);
        } else {
            u = this.deserializePoly(ciphertext);
            const wTmp = this.secureMultiply(u, s);
            const rawTmp = this.roundToBits(wTmp);
            return this.hashSharedSecretSync(rawTmp, peerPublicKey, ciphertext);
        }
        const w = this.secureMultiply(u, s);
        const rawSecret = this.recToBits(w, hint);
        return this.hashSharedSecretSync(rawSecret, peerPublicKey, ciphertext);
    }

    /* MATH */
    /**
     * Mod Inverse
     * @param a {bigint}
     * @param m {bigint}
     * @protected
     */
    protected modInverse(a: bigint, m: bigint): bigint {
        let [old_r, r] = [a, m];
        let [old_s, s] = [1n, 0n];
        while (r !== 0n) {
            const q = old_r / r;
            [old_r, r] = [r, old_r - q * r];
            [old_s, s] = [s, old_s - q * s];
        }
        return ((old_s % m) + m) % m;
    }

    /**
     * Pow Mod
     * @param base {bigint}
     * @param exp {bigint}
     * @param mod {bigint}
     * @protected
     */
    protected powMod(base: bigint, exp: bigint, mod: bigint): bigint {
        let result = 1n,
            b = base % mod,
            e = exp;
        while (e > 0n) {
            if (e & 1n) result = (result * b) % mod;
            b = (b * b) % mod;
            e >>= 1n;
        }
        return result;
    }

    /**
     * Round to bits
     * Q/2 - 1 bit for coeff, 256 coeff - 32 bytes
     * @param poly {bigint[]} Polynome
     * @protected
     */
    protected roundToBits(poly: bigint[]): Uint8Array {
        const result = new Uint8Array(32);
        for (let i = 0; i < this.N; i++) {
            const bit = 2n * poly[i] > this.Q ? 1 : 0;
            if (bit) result[i >> 3] |= 1 << (i & 7);
        }
        return result;
    }

    /**
     * Rec helper function
      * @param v {bigint} Vector
     * @protected
     */
    protected helpRec(v: bigint): number {
        if (4n * v < this.Q) return 0;
        if (2n * v < this.Q) return 1;
        if (4n * v < 3n * this.Q) return 0;
        return 1;
    }

    /**
     * Rec
     * @param v {bigint} Vector
     * @param hint {number} Hint
     * @protected
     */
    protected rec(v: bigint, hint: number): number {
        const eightVp = 8n * v;
        const Q = this.Q;
        const c0 = hint === 0 ? Q : 3n * Q;
        const c1 = hint === 0 ? 5n * Q : 7n * Q;
        const dist = (target: bigint) => {
            let d = eightVp >= target ? eightVp - target : target - eightVp;
            if (d > 4n * Q) d = 8n * Q - d;
            return d;
        };
        return dist(c0) < dist(c1) ? 0 : 1;
    }

    /**
     * Round to bits with hint
     * @param poly {bigint[]} Polynome
     * @protected
     */
    protected roundToBitsWithHint(poly: bigint[]): { bits: Uint8Array; hint: Uint8Array } {
        const bits = new Uint8Array(32);
        const hint = new Uint8Array(32);
        for (let i = 0; i < this.N; i++) {
            const b = 2n * poly[i] > this.Q ? 1 : 0;
            if (b) bits[i >> 3] |= 1 << (i & 7);
            const h = this.helpRec(poly[i]);
            if (h) hint[i >> 3] |= 1 << (i & 7);
        }
        return {bits, hint};
    }

    /**
     * Rec to bits
     * @param poly {bigint[]} Polynome
     * @param hint {Uint8Array} Hint
     * @protected
     */
    protected recToBits(poly: bigint[], hint: Uint8Array): Uint8Array {
        const bits = new Uint8Array(32);
        for (let i = 0; i < this.N; i++) {
            const h = (hint[i >> 3] >> (i & 7)) & 1;
            const b = this.rec(poly[i], h);
            if (b) bits[i >> 3] |= 1 << (i & 7);
        }
        return bits;
    }

    /* VALIDATION AND SERIALIZATION */
    /**
     * Validate polynome
     * @param poly {bigint[]} Polynome
     * @protected
     */
    protected validatePoly(poly: bigint[]): void {
        if (poly.length !== this.N)
            throw new Error(`Invalid poly length ${poly.length} expected ${this.N}`);
        if (this.nttProtection.validateInputs) {
            for (let i = 0; i < poly.length; i++) {
                const v = poly[i];
                if (v < -this.Q || v >= this.Q)
                    throw new Error(`Poly coefficient out of range at ${i}: ${v}`);
            }
        }
    }

    /**
     * Validate public key
     * @param pk {Uint8Array}
     * @protected
     */
    protected validatePublicKey(pk: Uint8Array): void {
        if (pk.length !== this.N * 4)
            throw new Error(
                `Invalid public key length ${pk.length} expected ${this.N * 4}`,
            );
    }

    /**
     * Validate private key
     * @param sk {Uint8Array}
     * @protected
     */
    protected validatePrivateKey(sk: Uint8Array): void {
        if (sk.length !== this.N * 2) throw new Error(`Invalid private key length`);
    }

    /**
     * Validate ciphertext
     * @param ct {Uint8Array} Ciphertext
     * @protected
     */
    protected validateCiphertext(ct: Uint8Array): void {
        if (ct.length !== this.N * 2 && ct.length !== this.N * 2 + 32)
            throw new Error(`Invalid ciphertext length`);
    }

    /**
     * Deserialize polynome
     * @param bytes {Uint8Array} Serialized polynome
     * @protected
     */
    protected deserializePoly(bytes: Uint8Array): bigint[] {
        if (bytes.length !== this.N * 2)
            throw new Error(`Invalid poly bytes length ${bytes.length}`);
        const poly = new Array<bigint>(this.N);
        for (let i = 0; i < this.N; i++) {
            const val = bytes[2 * i] | (bytes[2 * i + 1] << 8);
            let bv = BigInt(val);
            if (bv >= this.Q && this.nttProtection.validateInputs) bv = bv % this.Q;
            poly[i] = bv;
        }
        return poly;
    }

    /**
     * Serialize polynome
     * @param poly {bigint[]} Polynome
     * @protected
     */
    protected serializePoly(poly: bigint[]): Uint8Array {
        const bytes = new Uint8Array(this.N * 2);
        for (let i = 0; i < this.N; i++) {
            const norm = Number(((poly[i] % this.Q) + this.Q) % this.Q);
            bytes[2 * i] = norm & 0xff;
            bytes[2 * i + 1] = (norm >> 8) & 0xff;
        }
        return bytes;
    }

    /* NTT */
    /**
     * Multiply
     * @param a {bigint[]}
     * @param b {bigint[]}
     * @protected
     */
    protected multiply(a: bigint[], b: bigint[]): bigint[] {
        return this.secureMultiply(a, b);
    }

    /**
     * Secure Multiplication
     * @param a {bigint[]}
     * @param b {bigint[]}
     * @protected
     */
    protected secureMultiply(a: bigint[], b: bigint[]): bigint[] {
        if (this.nttProtection.validateInputs) {
            this.validatePoly(a);
            this.validatePoly(b);
        }

        const aNorm = this.normalizePoly(a),
            bNorm = this.normalizePoly(b);

        // Fast way without NTT
        if (!this.nttProtection.enabled) {
            const aNTT = this.ntt(aNorm),
                bNTT = this.ntt(bNorm);
            const prod = new Array<bigint>(this.N);
            for (let i = 0; i < this.N; i++) prod[i] = (aNTT[i] * bNTT[i]) % this.Q;
            return this.invNTT(prod);
        }

        // blinding: a·r , b·r^{-1} : multiplication result doesn't change, but in-memory fingerprint is changing
        let aEff = aNorm,
            bEff = bNorm;
        if (this.nttProtection.blinding) {
            const rnd = QuarkDashUtils.randomBytes(2);
            const blindingFactor =
                (BigInt(rnd[0] | (rnd[1] << 8)) % (this.Q - 1n)) + 1n;
            const inv = this.modInverse(blindingFactor, this.Q);
            aEff = aNorm.map((v) => (v * blindingFactor) % this.Q);
            bEff = bNorm.map((v) => (v * inv) % this.Q);
        }

        const aNTT = this.hardenedNTT(aEff);
        const bNTT = this.hardenedNTT(bEff);
        const prod = new Array<bigint>(this.N);
        for (let i = 0; i < this.N; i++) prod[i] = (aNTT[i] * bNTT[i]) % this.Q;

        const res = this.hardenedInvNTT(prod);

        // double-check to catch errors injects
        if (this.nttProtection.doubleCheck) {
            const aNTT2 = this.hardenedNTT(aEff),
                bNTT2 = this.hardenedNTT(bEff);
            const prod2 = new Array<bigint>(this.N);
            for (let i = 0; i < this.N; i++)
                prod2[i] = (aNTT2[i] * bNTT2[i]) % this.Q;
            const res2 = this.hardenedInvNTT(prod2);
            for (let i = 0; i < this.N; i++)
                if (res[i] !== res2[i])
                    throw new Error("NTT fault detected: double-check mismatch");
        }
        return res;
    }

    /**
     * Cached WLen
     * @param len {number} Length
     * @protected
     */
    protected getWlen(len: number): bigint {
        let v = this.wlenCache.get(len);
        if (v === undefined) {
            v = this.powMod(this.ROOT, BigInt(this.N / len), this.Q);
            this.wlenCache.set(len, v);
        }
        return v;
    }

    /**
     * Get Inv WLen
     * @param len {number} Length
     * @protected
     */
    protected getInvWlen(len: number): bigint {
        let v = this.invWlenCache.get(len);
        if (v === undefined) {
            const w = this.getWlen(len);
            v = this.modInverse(w, this.Q);
            this.invWlenCache.set(len, v);
        }
        return v;
    }

    /**
     * Bit reverse
     * @param a {bigint[]} Input value
     * @protected
     */
    protected bitReverse(a: bigint[]): bigint[] {
        const n = a.length;
        const res = [...a];
        let j = 0;
        for (let i = 1; i < n; i++) {
            let bit = n >> 1;
            for (; j & bit; bit >>= 1) j ^= bit;
            j ^= bit;
            if (i < j) {
                const tmp = res[i];
                res[i] = res[j];
                res[j] = tmp;
            }
        }
        return res;
    }

    /**
     * Hardened NTT
     * (as a basic NTT but without trees in secret)
     * @param poly {bigint[]} Polynome
     * @protected
     */
    protected hardenedNTT(poly: bigint[]): bigint[] {
        const res = this.bitReverse([...poly]);
        let len = 2;
        while (len <= this.N) {
            const wlen = this.getWlen(len);
            for (let i = 0; i < this.N; i += len) {
                let w = 1n;
                for (let j = 0; j < len / 2; j++) {
                    const u = res[i + j];
                    const v = (res[i + j + len / 2] * w) % this.Q;
                    res[i + j] = (u + v) % this.Q;
                    res[i + j + len / 2] = (u - v + this.Q) % this.Q;
                    w = (w * wlen) % this.Q;
                }
            }
            len <<= 1;
        }
        return res;
    }

    /**
     * Hardened inv NTT
     * @param poly {bigint[]} Polynome
     * @protected
     */
    protected hardenedInvNTT(poly: bigint[]): bigint[] {
        const res = this.bitReverse([...poly]);
        let len = 2;
        while (len <= this.N) {
            const wlen = this.getInvWlen(len);
            for (let i = 0; i < this.N; i += len) {
                let w = 1n;
                for (let j = 0; j < len / 2; j++) {
                    const u = res[i + j];
                    const v = (res[i + j + len / 2] * w) % this.Q;
                    res[i + j] = (u + v) % this.Q;
                    res[i + j + len / 2] = (u - v + this.Q) % this.Q;
                    w = (w * wlen) % this.Q;
                }
            }
            len <<= 1;
        }
        for (let i = 0; i < this.N; i++) res[i] = (res[i] * this.INV_N) % this.Q;
        return res;
    }

    /* Original NTT */
    /**
     * Inv NTT
     * @param poly {bigint[]} Polynome
     * @protected
     */
    protected invNTT(poly: bigint[]): bigint[] {
        const res = this.bitReverse([...poly]);
        let len = 2;
        while (len <= this.N) {
            const wlen = this.modInverse(this.powMod(this.ROOT, BigInt(this.N / len), this.Q), this.Q);
            for (let i = 0; i < this.N; i += len) {
                let w = 1n;
                for (let j = 0; j < len / 2; j++) {
                    const u = res[i + j];
                    const v = (res[i + j + len / 2] * w) % this.Q;
                    res[i + j] = (u + v) % this.Q;
                    res[i + j + len / 2] = (u - v + this.Q) % this.Q;
                    w = (w * wlen) % this.Q;
                }
            }
            len <<= 1;
        }
        for (let i = 0; i < this.N; i++) res[i] = (res[i] * this.INV_N) % this.Q;
        return res;
    }

    protected ntt(poly: bigint[]): bigint[] {
        const res = this.bitReverse([...poly]);
        let len = 2;
        while (len <= this.N) {
            const wlen = this.powMod(this.ROOT, BigInt(this.N / len), this.Q);
            for (let i = 0; i < this.N; i += len) {
                let w = 1n;
                for (let j = 0; j < len / 2; j++) {
                    const u = res[i + j];
                    const v = (res[i + j + len / 2] * w) % this.Q;
                    res[i + j] = (u + v) % this.Q;
                    res[i + j + len / 2] = (u - v + this.Q) % this.Q;
                    w = (w * wlen) % this.Q;
                }
            }
            len <<= 1;
        }
        return res;
    }

    /* POLYNOMES GENERATION */
    /**
     * Error polynome
     * @protected
     */
    protected errorPoly(): bigint[] {
        const poly = new Array<bigint>(this.N);
        const SIGMA = 3.19;
        for (let i = 0; i < this.N; i++) {
            let sum = 0;
            const randBytes = QuarkDashUtils.randomBytes(12);
            for (let j = 0; j < 12; j++) sum += randBytes[j];
            const centered = sum / 255 - 6; // ~ N(0,1) using 12
            const error = Math.floor(centered * SIGMA);
            poly[i] = BigInt(
                Math.max(-Number(this.Q), Math.min(Number(this.Q) - 1, error)),
            );
        }
        return poly;
    }

    /**
     * Uniform polynome
     * @protected
     */
    protected uniformPoly(): bigint[] {
        const poly = new Array<bigint>(this.N);
        const bytes = QuarkDashUtils.randomBytes(this.N * 2);
        for (let i = 0; i < this.N; i++) {
            const val = (bytes[2 * i] | (bytes[2 * i + 1] << 8)) % Number(this.Q);
            poly[i] = BigInt(val);
        }
        return poly;
    }

    /**
     * Small polynome
     * @protected
     */
    protected smallPoly(): bigint[] {
        const poly = new Array<bigint>(this.N);
        const bytesNeeded = Math.ceil((this.N * 2) / 8);
        const randomBytes = QuarkDashUtils.randomBytes(bytesNeeded);
        for (let i = 0; i < this.N; i++) {
            const byteIdx = Math.floor((i * 2) / 8);
            const bitShift = (i * 2) % 8;
            const val = (randomBytes[byteIdx] >> bitShift) & 0x03;
            if (val === 0) poly[i] = -1n;
            else if (val === 1) poly[i] = 0n;
            else poly[i] = 1n; // 2 and 3 to 1
        }
        return poly;
    }

    /**
     * Hash shared secret sync
     * @param ss
     * @param publicKey
     * @param ciphertext
     * @protected
     */
    protected hashSharedSecretSync(
        ss: Uint8Array,
        publicKey: Uint8Array,
        ciphertext: Uint8Array,
    ): Uint8Array {
        return SHA256.hash(
            QuarkDashUtils.concatBytes(ss, publicKey, ciphertext),
            true,
        ) as Uint8Array;
    }

    // Normalize any polynome to [0, Q) for -1 will be Q-1 etc.
    private normalizePoly(poly: bigint[]): bigint[] {
        return poly.map((v) => ((v % this.Q) + this.Q) % this.Q);
    }
}
