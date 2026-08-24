/**
 * QuarkDash Protocol ChaCha Implementation
 * Generates ChaCha cipher using key, nonce, counter and constants with 20 rounds.
 *
 * What's new:
 * - Generates 64B every block instead 2KB Batch by request
 * - Seek feature without re-compute all stream (Lazy Keystream)
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
 * ChaCha Keystream
 * 64bytes per block
 * Lazy computing
 */
export class ChaChaKeystream extends LazyKeystream {
    /**
     * Create ChaCha Keystream
     * @param key {Uint8Array} Key
     * @param nonce {Uint8Array} Nonce
     */
    constructor(
        private readonly key: Uint8Array,
        private readonly nonce: Uint8Array,
    ) {
        super(64);
    }

    /**
     * Generate block
     * @param blockIndex {number} Block index
     */
    public generateBlock(blockIndex: number): Uint8Array {
        const state = new Uint32Array(16);

        // magic constants "expand 32-byte k"
        state[0] = 0x61707865;
        state[1] = 0x3320646e;
        state[2] = 0x79622d32;
        state[3] = 0x6b206574;

        // key 32B - 8 words
        for (let i = 0; i < 8; i++)
            state[4 + i] = QuarkDashUtils.readUint32LE(this.key, i * 4);

        // nonce 12B - 3 words, counter - in state[12]
        for (let i = 0; i < 3; i++)
            state[13 + i] = QuarkDashUtils.readUint32LE(this.nonce, i * 4);
        state[12] = blockIndex;

        const working = new Uint32Array(state);

        // A little helper for quarter round to avoid 8 duplicates
        const qr = (s: Uint32Array, a: number, b: number, c: number, d: number) => {
            s[a] += s[b];
            s[d] ^= s[a];
            s[d] = (s[d] << 16) | (s[d] >>> 16);
            s[c] += s[d];
            s[b] ^= s[c];
            s[b] = (s[b] << 12) | (s[b] >>> 20);
            s[a] += s[b];
            s[d] ^= s[a];
            s[d] = (s[d] << 8) | (s[d] >>> 24);
            s[c] += s[d];
            s[b] ^= s[c];
            s[b] = (s[b] << 7) | (s[b] >>> 25);
        };

        for (let round = 0; round < 10; round++) {
            qr(working, 0, 4, 8, 12);
            qr(working, 1, 5, 9, 13);
            qr(working, 2, 6, 10, 14);
            qr(working, 3, 7, 11, 15);
            qr(working, 0, 5, 10, 15);
            qr(working, 1, 6, 11, 12);
            qr(working, 2, 7, 8, 13);
            qr(working, 3, 4, 9, 14);
        }

        for (let i = 0; i < 16; i++) working[i] += state[i];

        const out = new Uint8Array(64);
        for (let i = 0; i < 16; i++)
            QuarkDashUtils.writeUint32LE(working[i], out, i * 4);
        return out;
    }
}

/**
 * QuarkDash ChaCha Basic Implementation
 */
export class QuarkDashChaCha implements ICipher {
    // Key and Nonce
    private readonly key: Uint8Array;
    private readonly nonce: Uint8Array;

    // Block size
    private static readonly BLOCK_SIZE = 64;

    /**
     * ChaCha Cipher
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
    public createKeystream(): ChaChaKeystream {
        return new ChaChaKeystream(this.key, this.nonce);
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

    private process(data: Uint8Array): Uint8Array {
        return this.createKeystream().xor(data, 0);
    }
}
