/**
 * QuarkDash Crypto SHAKE-256 Implementation
 *
 * @git             https://github.com/devsdaddy/quarkdash
 * @version         1.1.0
 * @author          Elijah Rastorguev
 * @build           1005
 * @website         https://dev.to/devsdaddy
 * @updated         14.04.2026
 */
/* Import required modules */
import { loadWasmModule } from "../core/wasm_loader";

// Shake256 Constants
const KECCAK_ROUNDS = 24;
const RATE_BYTES = 136;
const RHO: number[] = [
    0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14
];
const RC: number[] = [
    0x00000001, 0x00008082, 0x8000808a, 0x80008000,
    0x0000808b, 0x80000001, 0x80008081, 0x00008009,
    0x0000008a, 0x00000088, 0x80008009, 0x8000000a,
    0x8000808b, 0x0000008b, 0x80008089, 0x80008003,
    0x80008002, 0x00000080, 0x0000800a, 0x8000000a,
    0x80008081, 0x00008080, 0x80000001, 0x80008008
];

/**
 * Shake-256 Web Assembly Implementation
 */
export class Shake256Wasm {
    // WASM Instances
    public static initializedWasm = false;
    private static instance: WebAssembly.Instance | null = null;
    private static memory: WebAssembly.Memory | null = null;
    private static shake256Func: ((inputPtr: number, inputLen: number, outputPtr: number, outputLen: number) => void) | null = null;
    private static nextPtr: number = 0;

    /**
     * Alloc
     * @param size
     * @private
     */
    private static alloc(size: number): number {
        const ptr = this.nextPtr;
        this.nextPtr += size;
        return ptr;
    }

    /**
     * Initialize WASM Module
     * @param wasmUrl {string} Path to module
     */
    public static async initWasm(wasmUrl: string): Promise<void> {
        try{
            if(this.initializedWasm) return Promise.resolve();

            // Initialize Module
            const module = await loadWasmModule(wasmUrl);
            const imports = {
                env: {
                    memory: new WebAssembly.Memory({ initial: 256, maximum: 512 }),
                }
            };

            this.instance = await WebAssembly.instantiate(module, imports);
            const exports = this.instance.exports as any;
            this.shake256Func = exports.shake256;
            this.memory = imports.env.memory;
            this.nextPtr = 0;
            this.initializedWasm = true;
        }catch(e){
            console.error(`WASM module initialization error. Switched to fallback.`);
            this.initializedWasm = false;
        }
    }

    /**
     * Shake 256 Using WASM
     * @param input {Uint8Array} Input buffer
     * @param outputLen {number} Output length
     * @returns {Uint8Array} Output buffer
     */
    public static shake256Wasm(input: Uint8Array, outputLen: number): Uint8Array {
        try{
            if (!this.shake256Func || !this.memory) throw new Error('WASM not initialized. Call initWasm() first.');
            const mem = new Uint8Array(this.memory.buffer);
            const inputPtr = this.alloc(input.length);
            const outputPtr = this.alloc(outputLen);
            mem.set(input, inputPtr);
            this.shake256Func(inputPtr, input.length, outputPtr, outputLen);
            const output = new Uint8Array(outputLen);
            output.set(mem.slice(outputPtr, outputPtr + outputLen));
            return output;
        }catch (e){
            // Not supported - fallback to JS
            console.log("WASM Shake is not supported on this platform. Switched to fallback.")
            this.initializedWasm = false;
            return Shake256.hashSync(input, outputLen);
        }
    }
}

/**
 * Returns is wasm shake or not
 */
export function isWasmShake() {
    return Shake256Wasm.initializedWasm;
}

/**
 * Keccak State
 */
export class KeccakState {
    private readonly stateLow: Uint32Array;
    private readonly stateHigh: Uint32Array;

    /**
     * Create Keccak State
     */
    constructor() {
        this.stateLow = new Uint32Array(25);
        this.stateHigh = new Uint32Array(25);
    }

    /**
     * XOR of byte to state
     * @param byte
     * @param index
     */
    public absorbByte(byte: number, index: number): void {
        const lane = index >> 3;
        const shift = (index & 7) << 3;
        if (shift < 32) {
            this.stateLow[lane] ^= (byte << shift);
        } else {
            this.stateHigh[lane] ^= (byte << (shift - 32));
        }
    }

    /**
     * Extract byte from state
     * @param index {number}
     */
    public extractByte(index: number): number {
        const lane = index >> 3;
        const shift = (index & 7) << 3;
        let word: number;
        if (shift < 32) {
            word = this.stateLow[lane];
        } else {
            word = this.stateHigh[lane];
        }
        return (word >>> shift) & 0xFF;
    }

    /**
     * Permute Keccak-f[1600]
     */
    public permute(): void {
        const stateLow = this.stateLow;
        const stateHigh = this.stateHigh;

        for (let round = 0; round < KECCAK_ROUNDS; round++) {
            // Theta step
            const C0 = new Array(5);
            const C1 = new Array(5);
            for (let x = 0; x < 5; x++) {
                let l = stateLow[x];
                let h = stateHigh[x];
                for (let y = 1; y < 5; y++) {
                    const idx = x + y*5;
                    l ^= stateLow[idx];
                    h ^= stateHigh[idx];
                }
                C0[x] = l;
                C1[x] = h;
            }
            const D0 = new Array(5);
            const D1 = new Array(5);
            for (let x = 0; x < 5; x++) {
                const prev = (x+4)%5;
                const next = (x+1)%5;
                // rot(C[next], 1)
                let rotL = C0[next];
                let rotH = C1[next];
                const t = (rotL >>> 31) | (rotH << 1);
                rotH = (rotH >>> 31) | (rotL << 1);
                rotL = t;
                D0[x] = C0[prev] ^ rotL;
                D1[x] = C1[prev] ^ rotH;
            }
            for (let i = 0; i < 25; i++) {
                const x = i % 5;
                stateLow[i] ^= D0[x];
                stateHigh[i] ^= D1[x];
            }

            let x = 1, y = 0;
            let curL = stateLow[1];
            let curH = stateHigh[1];
            for (let t = 0; t < 24; t++) {
                const nx = y;
                const ny = (2*x + 3*y) % 5;
                const idx = nx + ny*5;
                const nextL = stateLow[idx];
                const nextH = stateHigh[idx];
                const r = RHO[t+1];
                // rot(cur, r)
                let rotL = curL, rotH = curH;
                if (r >= 32) {
                    const r2 = r - 32;
                    const tL = (rotL >>> r2) | (rotH << (32 - r2));
                    const tH = (rotH >>> r2) | (rotL << (32 - r2));
                    rotL = tL;
                    rotH = tH;
                } else if (r > 0) {
                    const tL = (rotL >>> r) | (rotH << (32 - r));
                    const tH = (rotH >>> r) | (rotL << (32 - r));
                    rotL = tL;
                    rotH = tH;
                }
                stateLow[idx] = rotL;
                stateHigh[idx] = rotH;
                curL = nextL;
                curH = nextH;
                x = nx;
                y = ny;
            }

            for (let y = 0; y < 5; y++) {
                const base = y*5;
                const rowL0 = stateLow[base];
                const rowH0 = stateHigh[base];
                const rowL1 = stateLow[base+1];
                const rowH1 = stateHigh[base+1];
                const rowL2 = stateLow[base+2];
                const rowH2 = stateHigh[base+2];
                const rowL3 = stateLow[base+3];
                const rowH3 = stateHigh[base+3];
                const rowL4 = stateLow[base+4];
                const rowH4 = stateHigh[base+4];
                // new0 = row0 ^ ((~row1) & row2)
                stateLow[base]   = rowL0 ^ ((~rowL1) & rowL2);
                stateHigh[base]  = rowH0 ^ ((~rowH1) & rowH2);
                stateLow[base+1] = rowL1 ^ ((~rowL2) & rowL3);
                stateHigh[base+1]= rowH1 ^ ((~rowH2) & rowH3);
                stateLow[base+2] = rowL2 ^ ((~rowL3) & rowL4);
                stateHigh[base+2]= rowH2 ^ ((~rowH3) & rowH4);
                stateLow[base+3] = rowL3 ^ ((~rowL4) & rowL0);
                stateHigh[base+3]= rowH3 ^ ((~rowH4) & rowH0);
                stateLow[base+4] = rowL4 ^ ((~rowL0) & rowL1);
                stateHigh[base+4]= rowH4 ^ ((~rowH0) & rowH1);
            }

            // Iota step
            stateLow[0] ^= RC[round] & 0xFFFFFFFF;
            stateHigh[0] ^= (RC[round] >>> 0) & 0xFFFFFFFF;
        }
    }
}

/**
 * Shake-256 Hash
 */
export class Shake256 {
    /**
     * Shake-256 async
     * @param input {Uint8Array} Input buffer
     * @param outputLength {number} Output buffer length
     * @returns {Uint8Array} Output buffer
     */
    public static async hash(input: Uint8Array, outputLength: number): Promise<Uint8Array> {
        return this.process(input, outputLength);
    }

    /**
     * Shake-256 sync
     * @param input {Uint8Array} Input buffer
     * @param outputLength {number} Output buffer length
     * @returns {Uint8Array} Output buffer
     */
    public static hashSync(input: Uint8Array, outputLength: number): Uint8Array {
        return this.process(input, outputLength);
    }

    /**
     * Process SHAKE-256
     * @param input {Uint8Array} Input buffer
     * @param outputLength {number} Output length
     * @returns {Uint8Array} Output buffer
     * @private
     */
    private static process(input: Uint8Array, outputLength: number): Uint8Array {
        const state = new KeccakState();
        let offset = 0;
        const inputLen = input.length;

        while (offset < inputLen) {
            let blockSize = Math.min(RATE_BYTES, inputLen - offset);
            for (let i = 0; i < blockSize; i++) {
                state.absorbByte(input[offset + i], i);
            }
            offset += blockSize;
            if (blockSize === RATE_BYTES || offset === inputLen) {
                if (offset === inputLen) {
                    state.absorbByte(0x1F, blockSize);
                    state.absorbByte(0x80, blockSize + 1);
                }
                state.permute();
            }
        }

        const out = new Uint8Array(outputLength);
        let outPos = 0;
        while (outPos < outputLength) {
            for (let i = 0; i < RATE_BYTES && outPos < outputLength; i++) {
                out[outPos++] = state.extractByte(i);
            }
            if (outPos < outputLength) {
                state.permute();
            }
        }
        return out;
    }
}