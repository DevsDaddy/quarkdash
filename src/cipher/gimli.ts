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
 * @build           1024
 * @website         https://dev.to/devsdaddy
 * @updated         24.08.2026
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
    }

    /**
     * Generate block
     * @param blockIndex {number} Index
     */
    public generateBlock(blockIndex: number): Uint8Array {
        const state = new Uint32Array(12);

        // key 32B - 8 words
        for (let i = 0; i < 8; i++)
            state[i] = QuarkDashUtils.readUint32LE(this.key, i * 4);

        // nonce 12B - 3 words, last word - block counter
        state[8] = QuarkDashUtils.readUint32LE(this.nonce, 0);
        state[9] = QuarkDashUtils.readUint32LE(this.nonce, 4);
        state[10] = QuarkDashUtils.readUint32LE(this.nonce, 8);
        state[11] = blockIndex;

        const working = new Uint32Array(state);

        // 24 rounds of Gimli - same logic as in early version, but in one place
        for (let round = 0; round < 24; round++) {
            for (let i = 0; i < 4; i++) {
                const x = working[i],
                    y = working[i + 4],
                    z = working[i + 8];
                working[i] = x ^ (z << 1) ^ ((y & z) << 2);
                working[i + 4] = y ^ x ^ ((x | z) << 1);
                working[i + 8] = z ^ y ^ ((x & y) << 3);
            }

            // Gimli specification
            const t = working[1];
            working[1] = working[2];
            working[2] = working[3];
            working[3] = t;
            if ((round & 3) === 0) working[0] ^= 0x9e377900 | round;
        }

        const out = new Uint8Array(48);
        for (let i = 0; i < 12; i++)
            QuarkDashUtils.writeUint32LE(working[i], out, i * 4);
        return out;
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
    * keystreamBlocks(startCounter : number = 0): Generator<Uint8Array> {
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
    public processWithOffset(data: Uint8Array, offset : number = 0): Uint8Array {
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
