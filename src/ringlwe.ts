/**
 * QuarkDash Ring-LWE Implementation
 *
 * @git             https://github.com/devsdaddy/quarkdash
 * @version         1.0.0
 * @author          Elijah Rastorguev
 * @build           1002
 * @website         https://dev.to/devsdaddy
 * @updated         12.04.2026
 */
/* Import Required Modules */
import {ICryptoEncapsulated, ICryptoKeyPair, IKeyExchange} from "./types";
import {QuarkDashUtils} from "./utils";
import {SHA256} from "./sha";

/**
 * Ring-LWE based key exchange implementation
 */
export class QuarkDashKeyExchange implements IKeyExchange {
    // Ring-LWE Constants
    private static readonly N = 256;
    private static readonly Q = 7681n;
    private static readonly ROOT = 7n;
    private static readonly INV_N = this.modInverse(BigInt(this.N), this.Q);

    /**
     * Generate crypto key pair async
     * @returns {ICryptoKeyPair} Crypto key pair
     * TODO: GPU Calculations
     */
    public async generateKeyPair(): Promise<ICryptoKeyPair> {
        return this.generateKeyPairSync();
    }

    /**
     * Generate crypto key pair sync
     * @returns {ICryptoKeyPair} Crypto key pair
     */
    public generateKeyPairSync(): ICryptoKeyPair {
        const a = QuarkDashKeyExchange.uniformPoly();
        const s = QuarkDashKeyExchange.smallPoly();
        const e = QuarkDashKeyExchange.errorPoly();
        const as = QuarkDashKeyExchange.multiply(a, s);
        const b = new Array<bigint>(QuarkDashKeyExchange.N);
        for (let i = 0; i < QuarkDashKeyExchange.N; i++) {
            b[i] = (as[i] + e[i]) % QuarkDashKeyExchange.Q;
        }
        const publicKey = QuarkDashUtils.concatBytes(
            QuarkDashKeyExchange.serializePoly(a),
            QuarkDashKeyExchange.serializePoly(b)
        );
        const privateKey = QuarkDashKeyExchange.serializePoly(s);
        return { publicKey, privateKey };
    }

    /**
     * Encapsulate async
     * @param publicKey {Uint8Array} Public key buffer
     * @returns {Promise<ICryptoEncapsulated>} Encapsulated data
     * TODO: GPU Calculations
     */
    public async encapsulate(publicKey: Uint8Array): Promise<ICryptoEncapsulated> {
        return this.encapsulateSync(publicKey);
    }

    /**
     * Encapsulate sync
     * @param publicKey {Uint8Array} Public key buffer
     * @returns {ICryptoEncapsulated} Encapsulated data
     */
    public encapsulateSync(publicKey: Uint8Array): ICryptoEncapsulated {
        const aBytes = publicKey.slice(0, QuarkDashKeyExchange.N * 2);
        const bBytes = publicKey.slice(QuarkDashKeyExchange.N * 2);
        const a = QuarkDashKeyExchange.deserializePoly(aBytes);
        const b = QuarkDashKeyExchange.deserializePoly(bBytes);
        const sp = QuarkDashKeyExchange.smallPoly();
        const ep = QuarkDashKeyExchange.errorPoly();
        const uArr = QuarkDashKeyExchange.multiply(a, sp);
        for (let i = 0; i < QuarkDashKeyExchange.N; i++) {
            uArr[i] = (uArr[i] + ep[i]) % QuarkDashKeyExchange.Q;
        }
        const w = QuarkDashKeyExchange.multiply(b, sp);
        const rawSecret = QuarkDashKeyExchange.roundToBits(w);
        const ciphertext = QuarkDashKeyExchange.serializePoly(uArr);
        const sharedSecret = QuarkDashKeyExchange.hashSharedSecret(rawSecret, publicKey, ciphertext);
        return { ciphertext, sharedSecret };
    }

    /**
     * Decapsulate async
     * @param privateKey {Uint8Array} Private key buffer
     * @param peerPublicKey {Uint8Array} Peer public key
     * @param ciphertext {Uint8Array} Cipher text buffer
     * @returns {Promise<Uint8Array>} Buffer data
     * TODO: GPU Calculations
     */
    public async decapsulate(privateKey: Uint8Array, peerPublicKey: Uint8Array, ciphertext: Uint8Array): Promise<Uint8Array> {
        return this.decapsulateSync(privateKey, peerPublicKey, ciphertext);
    }

    /**
     * Decapsulate sync
     * @param privateKey {Uint8Array} Private key buffer
     * @param peerPublicKey{Uint8Array} Peer public key buffer
     * @param ciphertext {Uint8Array} Cipher text buffer
     * @returns {Uint8Array} Buffer data
     */
    public decapsulateSync(privateKey: Uint8Array, peerPublicKey: Uint8Array, ciphertext: Uint8Array): Uint8Array {
        const s = QuarkDashKeyExchange.deserializePoly(privateKey);
        const u = QuarkDashKeyExchange.deserializePoly(ciphertext);
        const w = QuarkDashKeyExchange.multiply(u, s);
        const rawSecret = QuarkDashKeyExchange.roundToBits(w);
        return QuarkDashKeyExchange.hashSharedSecret(rawSecret, peerPublicKey, ciphertext);
    }

    /**
     * Get small polygon
     * @returns {bigint[]} Small polygon
     * @private
     */
    private static smallPoly(): bigint[] {
        const poly = new Array<bigint>(this.N);
        const bytesNeeded = Math.ceil(this.N * 2 / 8);
        const randomBytes = QuarkDashUtils.randomBytes(bytesNeeded);
        for (let i = 0; i < this.N; i++) {
            const byteIdx = Math.floor(i * 2 / 8);
            const bitShift = (i * 2) % 8;
            const val = (randomBytes[byteIdx] >> bitShift) & 0x03; // 0..3
            if (val === 0) poly[i] = -1n;
            else if (val === 1) poly[i] = 0n;
            else if (val === 2) poly[i] = 1n;
            else {
                poly[i] = 1n;
            }
        }
        return poly;
    }

    /**
     * Uniform polygon
     * @returns {bigint[]}
     * @private
     */
    private static uniformPoly(): bigint[] {
        const poly = new Array<bigint>(this.N);
        const bytes = QuarkDashUtils.randomBytes(this.N * 2);
        for (let i = 0; i < this.N; i++) {
            const val = (bytes[2 * i] | (bytes[2 * i + 1] << 8)) % Number(this.Q);
            poly[i] = BigInt(val);
        }
        return poly;
    }

    /**
     * Error polygon
     * @private
     */
    private static errorPoly(): bigint[] {
        const poly = new Array<bigint>(this.N);
        const SIGMA = 3.19;
        for (let i = 0; i < this.N; i++) {
            let sum = 0;
            const randBytes = QuarkDashUtils.randomBytes(12);
            for (let j = 0; j < 12; j++) {
                sum += randBytes[j];
            }
            // Центрируем и масштабируем к [-6,6]
            const centered = (sum / 255) - 6;
            const error = Math.floor(centered * SIGMA);
            poly[i] = BigInt(Math.max(-Number(this.Q), Math.min(Number(this.Q) - 1, error)));
        }
        return poly;
    }

    /**
     * NTT Operation
     * @param poly {bigint[]} Polygon
     * @private
     */
    private static ntt(poly: bigint[]): bigint[] {
        const res = [...poly];
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

    /**
     * Inverse NTT
     * @param poly {bigint[]} Polygon
     * @private
     */
    private static invNTT(poly: bigint[]): bigint[] {
        const res = [...poly];
        let len = this.N;
        while (len >= 2) {
            const wlen = this.powMod(this.ROOT, BigInt(this.N / len), this.Q);
            for (let i = 0; i < this.N; i += len) {
                let w = 1n;
                for (let j = 0; j < len / 2; j++) {
                    const u = res[i + j];
                    const v = res[i + j + len / 2];
                    res[i + j] = (u + v) % this.Q;
                    res[i + j + len / 2] = ((u - v + this.Q) * w) % this.Q;
                    w = (w * wlen) % this.Q;
                }
            }
            len >>= 1;
        }
        for (let i = 0; i < this.N; i++) {
            res[i] = (res[i] * this.INV_N) % this.Q;
        }
        return res;
    }

    /**
     * Multiply
     * @param a {bigint[]} Polygon
     * @param b {bigint[]} Polygon
     * @returns {bigint[]} Multiplied polygons
     */
    public static multiply(a: bigint[], b: bigint[]): bigint[] {
        const aNTT = this.ntt(a);
        const bNTT = this.ntt(b);
        const prod = new Array<bigint>(this.N);
        for (let i = 0; i < this.N; i++) {
            prod[i] = (aNTT[i] * bNTT[i]) % this.Q;
        }
        return this.invNTT(prod);
    }

    /**
     * Serialize polygon
     * @param poly {bigint[]} Polygon
     * @returns {Uint8Array} Polygon buffer
     * @private
     */
    private static serializePoly(poly: bigint[]): Uint8Array {
        const bytes = new Uint8Array(this.N * 2);
        for (let i = 0; i < this.N; i++) {
            const val = Number(poly[i]);
            bytes[2 * i] = val & 0xFF;
            bytes[2 * i + 1] = (val >> 8) & 0xFF;
        }
        return bytes;
    }

    /**
     * Deserialize Polygon
     * @param bytes {Uint8Array} Polygon buffer
     * @returns {bigint[]} Polygon
     * @private
     */
    private static deserializePoly(bytes: Uint8Array): bigint[] {
        const poly = new Array<bigint>(this.N);
        for (let i = 0; i < this.N; i++) {
            const val = bytes[2 * i] | (bytes[2 * i + 1] << 8);
            poly[i] = BigInt(val);
        }
        return poly;
    }

    /**
     * Round to bits
     * @param poly {bigint[]} Polygon
     * @returns {Uint8Array} rounded buffer
     * @private
     */
    private static roundToBits(poly: bigint[]): Uint8Array {
        const result = new Uint8Array(32);
        for (let i = 0; i < this.N; i++) {
            const bit = (Number(poly[i]) > Number(this.Q) / 2) ? 1 : 0;
            if (bit) result[i >> 3] |= (1 << (i & 7));
        }
        return result;
    }

    /**
     * Modular exponentiation
     * @param base {bigint} Base
     * @param exp {bigint} exponential
     * @param mod {bigint} module
     * @returns {bigint} Result of modular exponentiation
     * @private
     */
    private static powMod(base: bigint, exp: bigint, mod: bigint): bigint {
        let result = 1n;
        let b = base % mod;
        let e = exp;
        while (e > 0n) {
            if (e & 1n) result = (result * b) % mod;
            b = (b * b) % mod;
            e >>= 1n;
        }
        return result;
    }

    /**
     * Modular inverse
     * @param a {bigint}
     * @param m {bigint}
     * @returns {bigint} Inversion result
     * @private
     */
    private static modInverse(a: bigint, m: bigint): bigint {
        let [old_r, r] = [a, m];
        let [old_s, s] = [1n, 0n];
        while (r !== 0n) {
            const q = old_r / r;
            [old_r, r] = [r, old_r - q * r];
            [old_s, s] = [s, old_s - q * s];
        }
        return (old_s % m + m) % m;
    }

    /**
     * Hash shared secret
     * @param ss {Uint8Array} Shared secret buffer
     * @param publicKey {Uint8Array} Public key buffer
     * @param ciphertext {Uint8Array} Cipher text buffer
     * @returns {Uint8Array} Shared secret hash
     * @private
     */
    private static hashSharedSecret(ss: Uint8Array, publicKey: Uint8Array, ciphertext: Uint8Array): Uint8Array {
        const data = QuarkDashUtils.concatBytes(ss, publicKey, ciphertext);
        return SHA256.hash(data, true) as Uint8Array;
    }
}