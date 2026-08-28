/**
 * QuarkDash Protocol Gimli Implementation
 * Gimli - a lightweight cipher, best for IoT.
 *
 * What's new:
 * - Now support lazy keystream with one block 48B
 * - Cacheable and now support seek
 *
 * @git             https://github.com/devsdaddy/quarkdash
 * @version         1.2.0
 * @author          Elijah Rastorguev
 * @build           1028
 * @website         https://dev.to/devsdaddy
 * @updated         28.08.2026
 */
/* Import required modules */
import {QuarkDashUtils} from "../core/utils";
import {ICipher} from "../core/types";
import {LazyKeystream} from "./keystream";

/**
 * Gimpli Keystream Implementation
 * 48bytes per block, 12 weords by 4B
 */
export class GimliKeystream extends LazyKeystream {
    private readonly key32: Uint32Array;
    private readonly nonce32: Uint32Array;
    private readonly work: Uint32Array;
    private readonly outBuf: Uint8Array;
    private readonly out32: Uint32Array;

    /**
     * Create Gimli Keystream
     * @param key {Uint8Array} Key
     * @param nonce {Uint8Array} Nonce
     */
    constructor(
        private readonly key: Uint8Array,
        private readonly nonce: Uint8Array,
    ) {
        super(48);
        this.key32 = new Uint32Array(8);
        for (let i = 0; i < 8; i++) this.key32[i] = QuarkDashUtils.readUint32LE(this.key, i * 4);
        this.nonce32 = new Uint32Array(3);
        for (let i = 0; i < 3; i++) this.nonce32[i] = QuarkDashUtils.readUint32LE(this.nonce, i * 4);
        this.work = new Uint32Array(12);
        this.outBuf = new Uint8Array(48);
        this.out32 = new Uint32Array(this.outBuf.buffer);
    }

    /**
     * Generate block
     * @param blockIndex {number} Block index
     */
    public generateBlock(blockIndex: number): Uint8Array {
        const k = this.key32, n = this.nonce32, w = this.work;
        w[0] = k[0];
        w[1] = k[1];
        w[2] = k[2];
        w[3] = k[3];
        w[4] = k[4];
        w[5] = k[5];
        w[6] = k[6];
        w[7] = k[7];
        w[8] = n[0];
        w[9] = n[1];
        w[10] = n[2];
        w[11] = blockIndex;
        for (let round = 0; round < 24; round++) {
            let x0 = w[0], y0 = w[4], z0 = w[8];
            w[0] = x0 ^ (z0 << 1) ^ ((y0 & z0) << 2);
            w[4] = y0 ^ x0 ^ ((x0 | z0) << 1);
            w[8] = z0 ^ y0 ^ ((x0 & y0) << 3);
            let x1 = w[1], y1 = w[5], z1 = w[9];
            w[1] = x1 ^ (z1 << 1) ^ ((y1 & z1) << 2);
            w[5] = y1 ^ x1 ^ ((x1 | z1) << 1);
            w[9] = z1 ^ y1 ^ ((x1 & y1) << 3);
            let x2 = w[2], y2 = w[6], z2 = w[10];
            w[2] = x2 ^ (z2 << 1) ^ ((y2 & z2) << 2);
            w[6] = y2 ^ x2 ^ ((x2 | z2) << 1);
            w[10] = z2 ^ y2 ^ ((x2 & y2) << 3);
            let x3 = w[3], y3 = w[7], z3 = w[11];
            w[3] = x3 ^ (z3 << 1) ^ ((y3 & z3) << 2);
            w[7] = y3 ^ x3 ^ ((x3 | z3) << 1);
            w[11] = z3 ^ y3 ^ ((x3 & y3) << 3);
            const t = w[1];
            w[1] = w[2];
            w[2] = w[3];
            w[3] = t;
            if ((round & 3) === 0) w[0] ^= 0x9e377900 | round;
        }
        const o = this.out32;
        o[0] = w[0];
        o[1] = w[1];
        o[2] = w[2];
        o[3] = w[3];
        o[4] = w[4];
        o[5] = w[5];
        o[6] = w[6];
        o[7] = w[7];
        o[8] = w[8];
        o[9] = w[9];
        o[10] = w[10];
        o[11] = w[11];
        return this.outBuf.slice();
    }
}

/**
 * QuarkDash Gimli Implementation
 */
export class QuarkDashGimli implements ICipher {
    // Key and Nonce
    private readonly key: Uint8Array;
    private readonly nonce: Uint8Array;

    // Block size
    private static readonly BLOCK_SIZE = 48;

    /**
     * Create Gimli Cipher
     * @param key {Uint8Array} Key
     * @param nonce {Uint8Array} Nonce
     */
    constructor(key: Uint8Array, nonce: Uint8Array) {
        if (key.length !== 32) throw new Error("Key must be 32 bytes");
        if (nonce.length !== 12) throw new Error("Nonce must be 12 bytes");
        this.key = key;
        this.nonce = nonce;
    }

    /**
     * Encrypt data
     * @param data {Uint8Array} Raw data
     */
    public async encrypt(data: Uint8Array): Promise<Uint8Array> {
        return this.process(data);
    }

    /**
     * Decrypt data
     * @param data {Uint8Array} Encrypted data
     */
    public async decrypt(data: Uint8Array): Promise<Uint8Array> {
        return this.process(data);
    }

    /**
     * Encrypt data in sync mode
     * @param data {Uint8Array} Raw data
     */
    public encryptSync(data: Uint8Array): Uint8Array {
        return this.process(data);
    }

    /**
     * Decrypt data in sync mode
     * @param data {Uint8Array} Encrypted data
     */
    public decryptSync(data: Uint8Array): Uint8Array {
        return this.process(data);
    }

    /**
     * Create keystream
     */
    public createKeystream(): GimliKeystream {
        return new GimliKeystream(this.key, this.nonce);
    }

    /**
     * Keystream blocks
     * @param startCounter {number} Start counter
     */
    * keystreamBlocks(startCounter: number = 0): Generator<Uint8Array> {
        yield* this.createKeystream().blocks(startCounter);
    }

    /**
     * Get keystream bytes
     * @param offset {number} Offset
     * @param length {number} Length
     */
    public getKeystreamBytes(offset: number, length: number): Uint8Array {
        return this.createKeystream().getBytes(offset, length);
    }

    /**
     * Process with offset
     * @param data {Uint8Array} Data
     * @param offset {number} Offset
     */
    public processWithOffset(data: Uint8Array, offset: number = 0): Uint8Array {
        return this.createKeystream().xor(data, offset);
    }

    /**
     * Process data
     * @param data {Uint8Array} Data
     * @private
     */
    private process(data: Uint8Array): Uint8Array {
        return this.createKeystream().xor(data, 0);
    }
}
