/**
 * QuarkDash ChaCha Implementation
 *
 * @git             https://github.com/devsdaddy/quarkdash
 * @version         1.1.0
 * @author          Elijah Rastorguev
 * @build           1002
 * @website         https://dev.to/devsdaddy
 * @updated         13.04.2026
 */
import {QuarkDashUtils} from "../core/utils";
import {ICipher} from "../core/types";

/**
 * ChaCha20 Based Cipher Implementation
 */
export class QuarkDashChaCha implements ICipher {
    // Key and Nonce
    private readonly key: Uint8Array;
    private readonly nonce: Uint8Array;
    private static readonly BLOCK_SIZE = 64;
    private static readonly BLOCKS_PER_BATCH = 32;   // 2048 байт за раз
    private static readonly BATCH_SIZE = QuarkDashChaCha.BLOCK_SIZE * QuarkDashChaCha.BLOCKS_PER_BATCH;

    /**
     * Create ChaCha20 Cipher
     * @param key {Uint8Array} Key buffer
     * @param nonce {Uint8Array} Nonce buffer
     */
    constructor(key: Uint8Array, nonce: Uint8Array) {
        if (key.length !== 32) throw new Error('Key must be 32 bytes');
        if (nonce.length !== 12) throw new Error('Nonce must be 12 bytes');
        this.key = key;
        this.nonce = nonce;
    }

    /**
     * Encrypt data async using ChaCha20
     * @param data {Uint8Array} Raw data buffer
     * @returns {Promise<Uint8Array>} Result buffer
     * TODO: GPU Calculations
     */
    public async encrypt(data: Uint8Array): Promise<Uint8Array> { return this.process(data); }

    /**
     * Decrypt data async using ChaCha20
     * @param data {Uint8Array} Encrypted raw data buffer
     * @returns {Promise<Uint8Array>} Result buffer
     * TODO: GPU Calculations
     */
    public async decrypt(data: Uint8Array): Promise<Uint8Array> { return this.process(data); }

    /**
     * Encrypt data sync using ChaCha20
     * @param data {Uint8Array} Raw data buffer
     * @returns {Uint8Array} Result buffer
     */
    public encryptSync(data: Uint8Array): Uint8Array { return this.process(data); }

    /**
     * Decrypt data sync using ChaCha20
     * @param data {Uint8Array} Encrypted raw data buffer
     * @returns {Uint8Array} Result buffer
     */
    public decryptSync(data: Uint8Array): Uint8Array { return this.process(data); }

    /**
     * Process ChaCha20 Cipher
     * @param data {Uint8Array} Data for processing
     * @returns {Uint8Array} Processing result
     * @private
     */
    private process(data: Uint8Array): Uint8Array {
        const out = new Uint8Array(data.length);
        let offset = 0;
        let blockCounter = 0;

        while (offset < data.length) {
            const blocksRemaining = Math.ceil((data.length - offset) / QuarkDashChaCha.BLOCK_SIZE);
            const blocksThisBatch = Math.min(QuarkDashChaCha.BLOCKS_PER_BATCH, blocksRemaining);
            const batchSize = blocksThisBatch * QuarkDashChaCha.BLOCK_SIZE;
            const keystream = this.generateKeystreamBatch(blockCounter, blocksThisBatch);
            const bytesToProcess = Math.min(batchSize, data.length - offset);
            for (let i = 0; i < bytesToProcess; i++) {
                out[offset + i] = data[offset + i] ^ keystream[i];
            }

            offset += bytesToProcess;
            blockCounter += blocksThisBatch;
        }

        return out;
    }

    /**
     * Quarter Round
     * @param s {Uint8Array} Buffer
     * @param a {number}
     * @param b {number}
     * @param c {number}
     * @param d {number}
     * @private
     */
    private quarterRound(s: Uint32Array, a: number, b: number, c: number, d: number): void {
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
    }

    /**
     * Generate Keystream Batch
     * @param startCounter {number} Start counter
     * @param count {number} Count
     * @private
     */
    private generateKeystreamBatch(startCounter: number, count: number): Uint8Array {
        const out = new Uint8Array(count * QuarkDashChaCha.BLOCK_SIZE);
        const state = new Uint32Array(16);

        state[0] = 0x61707865;
        state[1] = 0x3320646e;
        state[2] = 0x79622d32;
        state[3] = 0x6b206574;

        // Ключ
        for (let i = 0; i < 8; i++) {
            state[4 + i] = QuarkDashUtils.readUint32LE(this.key, i * 4);
        }

        // Nonce
        for (let i = 0; i < 3; i++) {
            state[13 + i] = QuarkDashUtils.readUint32LE(this.nonce, i * 4);
        }

        for (let block = 0; block < count; block++) {
            state[12] = startCounter + block;

            const working = new Uint32Array(state);
            for (let round = 0; round < 10; round++) {
                this.quarterRound(working, 0, 4, 8, 12);
                this.quarterRound(working, 1, 5, 9, 13);
                this.quarterRound(working, 2, 6, 10, 14);
                this.quarterRound(working, 3, 7, 11, 15);
                this.quarterRound(working, 0, 5, 10, 15);
                this.quarterRound(working, 1, 6, 11, 12);
                this.quarterRound(working, 2, 7, 8, 13);
                this.quarterRound(working, 3, 4, 9, 14);
            }

            for (let i = 0; i < 16; i++) {
                working[i] += state[i];
            }

            const outOffset = block * QuarkDashChaCha.BLOCK_SIZE;
            for (let i = 0; i < 16; i++) {
                QuarkDashUtils.writeUint32LE(working[i], out, outOffset + i * 4);
            }
        }

        return out;
    }
}