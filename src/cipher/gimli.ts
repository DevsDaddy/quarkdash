/**
 * QuarkDash Gimli Implementation
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
 * Gimli Cipher
 */
export class QuarkDashGimli implements ICipher {
    // Key and Nonce
    private readonly key: Uint8Array;
    private readonly nonce: Uint8Array;
    private static readonly BLOCK_SIZE = 48;
    private static readonly BLOCKS_PER_BATCH = 32;   // 1536 байт за раз
    private static readonly BATCH_SIZE = QuarkDashGimli.BLOCK_SIZE * QuarkDashGimli.BLOCKS_PER_BATCH;

    /**
     * Create Gimli Cipher
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
     * Encrypt data async using Gimli
     * @param data {Uint8Array} Raw data buffer
     * @returns {Promise<Uint8Array>} Result buffer
     * TODO: GPU Calculations
     */
    public async encrypt(data: Uint8Array): Promise<Uint8Array> { return this.process(data); }

    /**
     * Decrypt data async using Gimli
     * @param data {Uint8Array} Encrypted raw data buffer
     * @returns {Promise<Uint8Array>} Result buffer
     * TODO: GPU Calculations
     */
    public async decrypt(data: Uint8Array): Promise<Uint8Array> { return this.process(data); }

    /**
     * Encrypt data sync using Gimli
     * @param data {Uint8Array} Raw data buffer
     * @returns {Uint8Array} Result buffer
     */
    public encryptSync(data: Uint8Array): Uint8Array { return this.process(data); }

    /**
     * Decrypt data sync using Gimli
     * @param data {Uint8Array} Encrypted raw data buffer
     * @returns {Uint8Array} Result buffer
     */
    public decryptSync(data: Uint8Array): Uint8Array { return this.process(data); }

    /**
     * Process Gimli Cipher
     * @param data {Uint8Array} Input buffer
     * @returns {Uint8Array} Output buffer
     * @private
     */
    private process(data: Uint8Array): Uint8Array {
        const out = new Uint8Array(data.length);
        let offset = 0;
        let blockCounter = 0;

        while (offset < data.length) {
            const blocksRemaining = Math.ceil((data.length - offset) / QuarkDashGimli.BLOCK_SIZE);
            const blocksThisBatch = Math.min(QuarkDashGimli.BLOCKS_PER_BATCH, blocksRemaining);
            const batchSize = blocksThisBatch * QuarkDashGimli.BLOCK_SIZE;

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
     * Generate keystream batch
     * @param startCounter {number} Start counter
     * @param count {number} Count
     * @private
     */
    private generateKeystreamBatch(startCounter: number, count: number): Uint8Array {
        const out = new Uint8Array(count * QuarkDashGimli.BLOCK_SIZE);
        const state = new Uint32Array(12);

        for (let i = 0; i < 8; i++) {
            state[i] = QuarkDashUtils.readUint32LE(this.key, i * 4);
        }
        // Nonce
        state[8] = QuarkDashUtils.readUint32LE(this.nonce, 0);
        state[9] = QuarkDashUtils.readUint32LE(this.nonce, 4);
        state[10] = QuarkDashUtils.readUint32LE(this.nonce, 8);

        for (let block = 0; block < count; block++) {
            state[11] = startCounter + block;

            const working = new Uint32Array(state);

            for (let round = 0; round < 24; round++) {
                this.gimliRound(working, round);
            }

            const outOffset = block * QuarkDashGimli.BLOCK_SIZE;
            for (let i = 0; i < 12; i++) {
                QuarkDashUtils.writeUint32LE(working[i], out, outOffset + i * 4);
            }
        }

        return out;
    }

    /**
     * Gimli Round
     * @param state {Uint32Array} State buffer
     * @param round {number} Round number
     * @private
     */
    private gimliRound(state:Uint32Array, round:number){
        for (let i = 0; i < 4; i++) {
            const x = state[i];
            const y = state[i + 4];
            const z = state[i + 8];
            const newX = x ^ (z << 1) ^ ((y & z) << 2);
            const newY = y ^ x ^ ((x | z) << 1);
            const newZ = z ^ y ^ ((x & y) << 3);
            state[i] = newX;
            state[i + 4] = newY;
            state[i + 8] = newZ;
        }
        // Перестановка слов
        const t = state[1];
        state[1] = state[2];
        state[2] = state[3];
        state[3] = t;
        if ((round & 3) === 0) {
            state[0] ^= (0x9e377900 | round);
        }
    }
}