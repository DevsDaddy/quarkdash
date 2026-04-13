/**
 * QuarkDash Basic LWE Utils Implementation
 *
 * @git             https://github.com/devsdaddy/quarkdash
 * @version         1.1.0
 * @author          Elijah Rastorguev
 * @build           1003
 * @website         https://dev.to/devsdaddy
 * @updated         13.04.2026
 */
import {QuarkDashUtils} from "../core/utils";
import {SHA256} from "../hash/sha";
import {ICryptoEncapsulated, ICryptoKeyPair} from "../core/types";

/**
 * Base Ring-LWE Function
 */
export class BaseRingLWE {
    // Constants for override
    protected readonly N = 256;
    protected readonly Q : any = 7681n;
    protected readonly ROOT = 7n;
    protected readonly INV_N = this.modInverse(BigInt(this.N), this.Q);

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
        const a = this.uniformPoly();
        const s = this.smallPoly();
        const e = this.errorPoly();
        const as = this.multiply(a, s);
        const b = new Array<bigint>(this.N);
        for (let i = 0; i < this.N; i++) {
            b[i] = (as[i] + e[i]) % this.Q;
        }
        const publicKey = QuarkDashUtils.concatBytes(
            this.serializePoly(a),
            this.serializePoly(b)
        );
        const privateKey = this.serializePoly(s);
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
        const aBytes = publicKey.slice(0, this.N * 2);
        const bBytes = publicKey.slice(this.N * 2);
        const a = this.deserializePoly(aBytes);
        const b = this.deserializePoly(bBytes);
        const sp = this.smallPoly();
        const ep = this.errorPoly();
        const uArr = this.multiply(a, sp);
        for (let i = 0; i < this.N; i++) {
            uArr[i] = (uArr[i] + ep[i]) % this.Q;
        }
        const w = this.multiply(b, sp);
        const rawSecret = this.roundToBits(w);
        const ciphertext = this.serializePoly(uArr);
        const sharedSecret = this.hashSharedSecretSync(rawSecret, publicKey, ciphertext);
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
        const s = this.deserializePoly(privateKey);
        const u = this.deserializePoly(ciphertext);
        const w = this.multiply(u, s);
        const rawSecret = this.roundToBits(w);
        return this.hashSharedSecretSync(rawSecret, peerPublicKey, ciphertext);
    }

    /**
     * Modular inverse
     * @param a {bigint}
     * @param m {bigint}
     * @returns {bigint} Inversion result
     * @private
     */
    protected modInverse(a: bigint, m: bigint): bigint {
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
     * Modular exponentiation
     * @param base {bigint} Base
     * @param exp {bigint} exponential
     * @param mod {bigint} module
     * @returns {bigint} Result of modular exponentiation
     * @private
     */
    protected powMod(base: bigint, exp: bigint, mod: bigint): bigint {
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
     * Round to bits
     * @param poly {bigint[]} Polygon
     * @returns {Uint8Array} rounded buffer
     * @private
     */
    protected roundToBits(poly: bigint[]): Uint8Array {
        const result = new Uint8Array(32);
        for (let i = 0; i < this.N; i++) {
            const bit = (Number(poly[i]) > Number(this.Q) / 2) ? 1 : 0;
            if (bit) result[i >> 3] |= (1 << (i & 7));
        }
        return result;
    }

    /**
     * Deserialize Polygon
     * @param bytes {Uint8Array} Polygon buffer
     * @returns {bigint[]} Polygon
     * @private
     */
    protected deserializePoly(bytes: Uint8Array): bigint[] {
        const poly = new Array<bigint>(this.N);
        for (let i = 0; i < this.N; i++) {
            const val = bytes[2 * i] | (bytes[2 * i + 1] << 8);
            poly[i] = BigInt(val);
        }
        return poly;
    }

    /**
     * Serialize polygon
     * @param poly {bigint[]} Polygon
     * @returns {Uint8Array} Polygon buffer
     * @private
     */
    protected serializePoly(poly: bigint[]): Uint8Array {
        const bytes = new Uint8Array(this.N * 2);
        for (let i = 0; i < this.N; i++) {
            const val = Number(poly[i]);
            bytes[2 * i] = val & 0xFF;
            bytes[2 * i + 1] = (val >> 8) & 0xFF;
        }
        return bytes;
    }

    /**
     * Multiply
     * @param a {bigint[]} Polygon
     * @param b {bigint[]} Polygon
     * @returns {bigint[]} Multiplied polygons
     */
    protected multiply(a: bigint[], b: bigint[]): bigint[] {
        const aNTT = this.ntt(a);
        const bNTT = this.ntt(b);
        const prod = new Array<bigint>(this.N);
        for (let i = 0; i < this.N; i++) {
            prod[i] = (aNTT[i] * bNTT[i]) % this.Q;
        }
        return this.invNTT(prod);
    }

    /**
     * Inverse NTT
     * @param poly {bigint[]} Polygon
     * @private
     */
    protected invNTT(poly: bigint[]): bigint[] {
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
     * NTT Operation
     * @param poly {bigint[]} Polygon
     * @private
     */
    protected ntt(poly: bigint[]): bigint[] {
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
                    res[i + j + len / 2] = BigInt((u - v + this.Q) % this.Q);
                    w = (w * wlen) % this.Q;
                }
            }
            len <<= 1;
        }
        return res;
    }

    /**
     * Error polygon
     * @private
     */
    protected errorPoly(): bigint[] {
        const poly = new Array<bigint>(this.N);
        const SIGMA = 3.19;
        for (let i = 0; i < this.N; i++) {
            let sum = 0;
            const randBytes = QuarkDashUtils.randomBytes(12);
            for (let j = 0; j < 12; j++) {
                sum += randBytes[j];
            }
            const centered = (sum / 255) - 6;
            const error = Math.floor(centered * SIGMA);
            poly[i] = BigInt(Math.max(-Number(this.Q), Math.min(Number(this.Q) - 1, error)));
        }
        return poly;
    }

    /**
     * Uniform polygon
     * @returns {bigint[]}
     * @private
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
     * Get small polygon
     * @returns {bigint[]} Small polygon
     * @private
     */
    protected smallPoly(): bigint[] {
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
     * Hash shared secret
     * @param ss {Uint8Array} Shared Secret
     * @param publicKey {Uint8Array} Public Key
     * @param ciphertext {Uint8Array} Cipher text
     * @returns {Uint8Array} Hash buffer
     * @protected
     */
    protected hashSharedSecretSync(ss: Uint8Array, publicKey: Uint8Array, ciphertext: Uint8Array): Uint8Array {
        const data = QuarkDashUtils.concatBytes(ss, publicKey, ciphertext);
        return SHA256.hash(data, true) as Uint8Array;
    }
}