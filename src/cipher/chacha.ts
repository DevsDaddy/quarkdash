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
 * @build           1033
 * @website         https://dev.to/devsdaddy
 * @updated         05.09.2026
 */
/* Import required modules */
import {QuarkDashUtils} from "../core/utils";
import {ICipher} from "../core/types";
import {LazyKeystream} from "./keystream";
import {ChaChaWasm} from "./chacha_wasm";

/**
 * ChaCha Keystream
 * 64bytes per block
 * Lazy computing
 */
export class ChaChaKeystream extends LazyKeystream {
    private readonly key32: Uint32Array;
    private readonly nonce32: Uint32Array;
    private readonly stateTpl: Uint32Array;
    private readonly work: Uint32Array;
    private readonly outBuf: Uint8Array;
    private readonly out32: Uint32Array;

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
        this.key32 = new Uint32Array(8);
        for (let i = 0; i < 8; i++) this.key32[i] = QuarkDashUtils.readUint32LE(this.key, i * 4);
        this.nonce32 = new Uint32Array(3);
        for (let i = 0; i < 3; i++) this.nonce32[i] = QuarkDashUtils.readUint32LE(this.nonce, i * 4);
        this.stateTpl = new Uint32Array(16);
        this.stateTpl[0] = 0x61707865;
        this.stateTpl[1] = 0x3320646e;
        this.stateTpl[2] = 0x79622d32;
        this.stateTpl[3] = 0x6b206574;
        this.work = new Uint32Array(16);
        this.outBuf = new Uint8Array(64);
        this.out32 = new Uint32Array(this.outBuf.buffer);
    }

    /**
     * Generate block
     * @param blockIndex {number} Block index
     */
    public generateBlock(blockIndex: number): Uint8Array {
        if (ChaChaWasm.isReady()) {
            const wasmOut = ChaChaWasm.chachaBlock(this.key, this.nonce, blockIndex);
            if (wasmOut) return wasmOut;
        }
        const s = this.stateTpl;
        const k = this.key32;
        const n = this.nonce32;
        const w = this.work;
        s[4] = k[0];
        s[5] = k[1];
        s[6] = k[2];
        s[7] = k[3];
        s[8] = k[4];
        s[9] = k[5];
        s[10] = k[6];
        s[11] = k[7];
        s[12] = blockIndex;
        s[13] = n[0];
        s[14] = n[1];
        s[15] = n[2];
        w[0] = s[0];
        w[1] = s[1];
        w[2] = s[2];
        w[3] = s[3];
        w[4] = s[4];
        w[5] = s[5];
        w[6] = s[6];
        w[7] = s[7];
        w[8] = s[8];
        w[9] = s[9];
        w[10] = s[10];
        w[11] = s[11];
        w[12] = s[12];
        w[13] = s[13];
        w[14] = s[14];
        w[15] = s[15];
        for (let r = 0; r < 10; r++) {
            let a0 = w[0], b0 = w[4], c0 = w[8], d0 = w[12];
            a0 += b0;
            d0 ^= a0;
            d0 = (d0 << 16) | (d0 >>> 16);
            c0 += d0;
            b0 ^= c0;
            b0 = (b0 << 12) | (b0 >>> 20);
            a0 += b0;
            d0 ^= a0;
            d0 = (d0 << 8) | (d0 >>> 24);
            c0 += d0;
            b0 ^= c0;
            b0 = (b0 << 7) | (b0 >>> 25);
            w[0] = a0;
            w[4] = b0;
            w[8] = c0;
            w[12] = d0;
            let a1 = w[1], b1 = w[5], c1 = w[9], d1 = w[13];
            a1 += b1;
            d1 ^= a1;
            d1 = (d1 << 16) | (d1 >>> 16);
            c1 += d1;
            b1 ^= c1;
            b1 = (b1 << 12) | (b1 >>> 20);
            a1 += b1;
            d1 ^= a1;
            d1 = (d1 << 8) | (d1 >>> 24);
            c1 += d1;
            b1 ^= c1;
            b1 = (b1 << 7) | (b1 >>> 25);
            w[1] = a1;
            w[5] = b1;
            w[9] = c1;
            w[13] = d1;
            let a2 = w[2], b2 = w[6], c2 = w[10], d2 = w[14];
            a2 += b2;
            d2 ^= a2;
            d2 = (d2 << 16) | (d2 >>> 16);
            c2 += d2;
            b2 ^= c2;
            b2 = (b2 << 12) | (b2 >>> 20);
            a2 += b2;
            d2 ^= a2;
            d2 = (d2 << 8) | (d2 >>> 24);
            c2 += d2;
            b2 ^= c2;
            b2 = (b2 << 7) | (b2 >>> 25);
            w[2] = a2;
            w[6] = b2;
            w[10] = c2;
            w[14] = d2;
            let a3 = w[3], b3 = w[7], c3 = w[11], d3 = w[15];
            a3 += b3;
            d3 ^= a3;
            d3 = (d3 << 16) | (d3 >>> 16);
            c3 += d3;
            b3 ^= c3;
            b3 = (b3 << 12) | (b3 >>> 20);
            a3 += b3;
            d3 ^= a3;
            d3 = (d3 << 8) | (d3 >>> 24);
            c3 += d3;
            b3 ^= c3;
            b3 = (b3 << 7) | (b3 >>> 25);
            w[3] = a3;
            w[7] = b3;
            w[11] = c3;
            w[15] = d3;
            let a4 = w[0], b4 = w[5], c4 = w[10], d4 = w[15];
            a4 += b4;
            d4 ^= a4;
            d4 = (d4 << 16) | (d4 >>> 16);
            c4 += d4;
            b4 ^= c4;
            b4 = (b4 << 12) | (b4 >>> 20);
            a4 += b4;
            d4 ^= a4;
            d4 = (d4 << 8) | (d4 >>> 24);
            c4 += d4;
            b4 ^= c4;
            b4 = (b4 << 7) | (b4 >>> 25);
            w[0] = a4;
            w[5] = b4;
            w[10] = c4;
            w[15] = d4;
            let a5 = w[1], b5 = w[6], c5 = w[11], d5 = w[12];
            a5 += b5;
            d5 ^= a5;
            d5 = (d5 << 16) | (d5 >>> 16);
            c5 += d5;
            b5 ^= c5;
            b5 = (b5 << 12) | (b5 >>> 20);
            a5 += b5;
            d5 ^= a5;
            d5 = (d5 << 8) | (d5 >>> 24);
            c5 += d5;
            b5 ^= c5;
            b5 = (b5 << 7) | (b5 >>> 25);
            w[1] = a5;
            w[6] = b5;
            w[11] = c5;
            w[12] = d5;
            let a6 = w[2], b6 = w[7], c6 = w[8], d6 = w[13];
            a6 += b6;
            d6 ^= a6;
            d6 = (d6 << 16) | (d6 >>> 16);
            c6 += d6;
            b6 ^= c6;
            b6 = (b6 << 12) | (b6 >>> 20);
            a6 += b6;
            d6 ^= a6;
            d6 = (d6 << 8) | (d6 >>> 24);
            c6 += d6;
            b6 ^= c6;
            b6 = (b6 << 7) | (b6 >>> 25);
            w[2] = a6;
            w[7] = b6;
            w[8] = c6;
            w[13] = d6;
            let a7 = w[3], b7 = w[4], c7 = w[9], d7 = w[14];
            a7 += b7;
            d7 ^= a7;
            d7 = (d7 << 16) | (d7 >>> 16);
            c7 += d7;
            b7 ^= c7;
            b7 = (b7 << 12) | (b7 >>> 20);
            a7 += b7;
            d7 ^= a7;
            d7 = (d7 << 8) | (d7 >>> 24);
            c7 += d7;
            b7 ^= c7;
            b7 = (b7 << 7) | (b7 >>> 25);
            w[3] = a7;
            w[4] = b7;
            w[9] = c7;
            w[14] = d7;
        }
        w[0] += s[0];
        w[1] += s[1];
        w[2] += s[2];
        w[3] += s[3];
        w[4] += s[4];
        w[5] += s[5];
        w[6] += s[6];
        w[7] += s[7];
        w[8] += s[8];
        w[9] += s[9];
        w[10] += s[10];
        w[11] += s[11];
        w[12] += s[12];
        w[13] += s[13];
        w[14] += s[14];
        w[15] += s[15];
        const out32 = this.out32;
        out32[0] = w[0];
        out32[1] = w[1];
        out32[2] = w[2];
        out32[3] = w[3];
        out32[4] = w[4];
        out32[5] = w[5];
        out32[6] = w[6];
        out32[7] = w[7];
        out32[8] = w[8];
        out32[9] = w[9];
        out32[10] = w[10];
        out32[11] = w[11];
        out32[12] = w[12];
        out32[13] = w[13];
        out32[14] = w[14];
        out32[15] = w[15];
        return this.outBuf.slice();
    }

    /**
     * XOR
     * @param data {Uint8Array} Data
     * @param keystreamOffset {number} Keystream offset
     */
    public override xor(data: Uint8Array, keystreamOffset: number = 0): Uint8Array {
        if (data.length >= 1024 && ChaChaWasm.isReady()) {
            const r = ChaChaWasm.chachaXor(this.key, this.nonce, data, keystreamOffset);
            if (r) return r;
        }
        return super.xor(data, keystreamOffset);
    }

    /**
     * XOR Into
     * @param input {Uint8Array} Input data
     * @param output {Uint8Array} Output data
     * @param keystreamOffset {number} Keystream offset
     */
    public override xorInto(input: Uint8Array, output: Uint8Array, keystreamOffset: number = 0): void {
        if (input.length >= 1024 && ChaChaWasm.isReady()) {
            const r = ChaChaWasm.chachaXor(this.key, this.nonce, input, keystreamOffset);
            if (r) { output.set(r); return; }
        }
        super.xorInto(input, output, keystreamOffset);
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

    private process(data: Uint8Array): Uint8Array {
        return this.createKeystream().xor(data, 0);
    }
}
