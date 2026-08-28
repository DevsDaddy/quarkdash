/**
 * QuarkDash SHAKE Implementation
 *
 * @git             https://github.com/devsdaddy/quarkdash
 * @version         1.2.0
 * @author          Elijah Rastorguev
 * @build           1028
 * @website         https://dev.to/devsdaddy
 * @updated         28.08.2026
 */
/* Load WASM Module */
import {loadWasmModule} from "../core/wasm_loader";

/* SHAKE Constants */
const RATE_BYTES = 136;
const RC = new Uint32Array([1, 0, 32898, 0, 32906, 2147483648, 2147516416, 2147483648, 32907, 0, 2147483649,
    0, 2147516545, 2147483648, 32777, 2147483648, 138, 0, 136, 0, 2147516425, 0,
    2147483658, 0, 2147516555, 0, 139, 2147483648, 32905, 2147483648, 32771,
    2147483648, 32770, 2147483648, 128, 2147483648, 32778, 0, 2147483658, 2147483648,
    2147516545, 2147483648, 32896, 2147483648, 2147483649, 0, 2147516424, 2147483648]);

/**
 * Keccak Function
 * @param s
 */
function keccakF(s: Uint32Array) {
    let h: number, l: number, n: number, c0: number, c1: number, c2: number, c3: number, c4: number, c5: number,
        c6: number, c7: number, c8: number, c9: number,
        b0: number, b1: number, b2: number, b3: number, b4: number, b5: number, b6: number, b7: number, b8: number,
        b9: number, b10: number, b11: number, b12: number, b13: number, b14: number, b15: number, b16: number,
        b17: number,
        b18: number, b19: number, b20: number, b21: number, b22: number, b23: number, b24: number, b25: number,
        b26: number, b27: number, b28: number, b29: number, b30: number, b31: number, b32: number, b33: number,
        b34: number, b35: number, b36: number, b37: number, b38: number, b39: number, b40: number, b41: number,
        b42: number, b43: number, b44: number, b45: number, b46: number, b47: number, b48: number, b49: number;
    for (n = 0; n < 48; n += 2) {
        c0 = s[0] ^ s[10] ^ s[20] ^ s[30] ^ s[40];
        c1 = s[1] ^ s[11] ^ s[21] ^ s[31] ^ s[41];
        c2 = s[2] ^ s[12] ^ s[22] ^ s[32] ^ s[42];
        c3 = s[3] ^ s[13] ^ s[23] ^ s[33] ^ s[43];
        c4 = s[4] ^ s[14] ^ s[24] ^ s[34] ^ s[44];
        c5 = s[5] ^ s[15] ^ s[25] ^ s[35] ^ s[45];
        c6 = s[6] ^ s[16] ^ s[26] ^ s[36] ^ s[46];
        c7 = s[7] ^ s[17] ^ s[27] ^ s[37] ^ s[47];
        c8 = s[8] ^ s[18] ^ s[28] ^ s[38] ^ s[48];
        c9 = s[9] ^ s[19] ^ s[29] ^ s[39] ^ s[49];
        h = c8 ^ ((c2 << 1) | (c3 >>> 31));
        l = c9 ^ ((c3 << 1) | (c2 >>> 31));
        s[0] ^= h;
        s[1] ^= l;
        s[10] ^= h;
        s[11] ^= l;
        s[20] ^= h;
        s[21] ^= l;
        s[30] ^= h;
        s[31] ^= l;
        s[40] ^= h;
        s[41] ^= l;
        h = c0 ^ ((c4 << 1) | (c5 >>> 31));
        l = c1 ^ ((c5 << 1) | (c4 >>> 31));
        s[2] ^= h;
        s[3] ^= l;
        s[12] ^= h;
        s[13] ^= l;
        s[22] ^= h;
        s[23] ^= l;
        s[32] ^= h;
        s[33] ^= l;
        s[42] ^= h;
        s[43] ^= l;
        h = c2 ^ ((c6 << 1) | (c7 >>> 31));
        l = c3 ^ ((c7 << 1) | (c6 >>> 31));
        s[4] ^= h;
        s[5] ^= l;
        s[14] ^= h;
        s[15] ^= l;
        s[24] ^= h;
        s[25] ^= l;
        s[34] ^= h;
        s[35] ^= l;
        s[44] ^= h;
        s[45] ^= l;
        h = c4 ^ ((c8 << 1) | (c9 >>> 31));
        l = c5 ^ ((c9 << 1) | (c8 >>> 31));
        s[6] ^= h;
        s[7] ^= l;
        s[16] ^= h;
        s[17] ^= l;
        s[26] ^= h;
        s[27] ^= l;
        s[36] ^= h;
        s[37] ^= l;
        s[46] ^= h;
        s[47] ^= l;
        h = c6 ^ ((c0 << 1) | (c1 >>> 31));
        l = c7 ^ ((c1 << 1) | (c0 >>> 31));
        s[8] ^= h;
        s[9] ^= l;
        s[18] ^= h;
        s[19] ^= l;
        s[28] ^= h;
        s[29] ^= l;
        s[38] ^= h;
        s[39] ^= l;
        s[48] ^= h;
        s[49] ^= l;
        b0 = s[0];
        b1 = s[1];
        b32 = (s[11] << 4) | (s[10] >>> 28);
        b33 = (s[10] << 4) | (s[11] >>> 28);
        b14 = (s[20] << 3) | (s[21] >>> 29);
        b15 = (s[21] << 3) | (s[20] >>> 29);
        b46 = (s[31] << 9) | (s[30] >>> 23);
        b47 = (s[30] << 9) | (s[31] >>> 23);
        b28 = (s[40] << 18) | (s[41] >>> 14);
        b29 = (s[41] << 18) | (s[40] >>> 14);
        b20 = (s[2] << 1) | (s[3] >>> 31);
        b21 = (s[3] << 1) | (s[2] >>> 31);
        b2 = (s[13] << 12) | (s[12] >>> 20);
        b3 = (s[12] << 12) | (s[13] >>> 20);
        b34 = (s[22] << 10) | (s[23] >>> 22);
        b35 = (s[23] << 10) | (s[22] >>> 22);
        b16 = (s[33] << 13) | (s[32] >>> 19);
        b17 = (s[32] << 13) | (s[33] >>> 19);
        b48 = (s[42] << 2) | (s[43] >>> 30);
        b49 = (s[43] << 2) | (s[42] >>> 30);
        b40 = (s[5] << 30) | (s[4] >>> 2);
        b41 = (s[4] << 30) | (s[5] >>> 2);
        b22 = (s[14] << 6) | (s[15] >>> 26);
        b23 = (s[15] << 6) | (s[14] >>> 26);
        b4 = (s[25] << 11) | (s[24] >>> 21);
        b5 = (s[24] << 11) | (s[25] >>> 21);
        b36 = (s[34] << 15) | (s[35] >>> 17);
        b37 = (s[35] << 15) | (s[34] >>> 17);
        b18 = (s[45] << 29) | (s[44] >>> 3);
        b19 = (s[44] << 29) | (s[45] >>> 3);
        b10 = (s[6] << 28) | (s[7] >>> 4);
        b11 = (s[7] << 28) | (s[6] >>> 4);
        b42 = (s[17] << 23) | (s[16] >>> 9);
        b43 = (s[16] << 23) | (s[17] >>> 9);
        b24 = (s[26] << 25) | (s[27] >>> 7);
        b25 = (s[27] << 25) | (s[26] >>> 7);
        b6 = (s[36] << 21) | (s[37] >>> 11);
        b7 = (s[37] << 21) | (s[36] >>> 11);
        b38 = (s[47] << 24) | (s[46] >>> 8);
        b39 = (s[46] << 24) | (s[47] >>> 8);
        b30 = (s[8] << 27) | (s[9] >>> 5);
        b31 = (s[9] << 27) | (s[8] >>> 5);
        b12 = (s[18] << 20) | (s[19] >>> 12);
        b13 = (s[19] << 20) | (s[18] >>> 12);
        b44 = (s[29] << 7) | (s[28] >>> 25);
        b45 = (s[28] << 7) | (s[29] >>> 25);
        b26 = (s[38] << 8) | (s[39] >>> 24);
        b27 = (s[39] << 8) | (s[38] >>> 24);
        b8 = (s[48] << 14) | (s[49] >>> 18);
        b9 = (s[49] << 14) | (s[48] >>> 18);
        s[0] = b0 ^ (~b2 & b4);
        s[1] = b1 ^ (~b3 & b5);
        s[10] = b10 ^ (~b12 & b14);
        s[11] = b11 ^ (~b13 & b15);
        s[20] = b20 ^ (~b22 & b24);
        s[21] = b21 ^ (~b23 & b25);
        s[30] = b30 ^ (~b32 & b34);
        s[31] = b31 ^ (~b33 & b35);
        s[40] = b40 ^ (~b42 & b44);
        s[41] = b41 ^ (~b43 & b45);
        s[2] = b2 ^ (~b4 & b6);
        s[3] = b3 ^ (~b5 & b7);
        s[12] = b12 ^ (~b14 & b16);
        s[13] = b13 ^ (~b15 & b17);
        s[22] = b22 ^ (~b24 & b26);
        s[23] = b23 ^ (~b25 & b27);
        s[32] = b32 ^ (~b34 & b36);
        s[33] = b33 ^ (~b35 & b37);
        s[42] = b42 ^ (~b44 & b46);
        s[43] = b43 ^ (~b45 & b47);
        s[4] = b4 ^ (~b6 & b8);
        s[5] = b5 ^ (~b7 & b9);
        s[14] = b14 ^ (~b16 & b18);
        s[15] = b15 ^ (~b17 & b19);
        s[24] = b24 ^ (~b26 & b28);
        s[25] = b25 ^ (~b27 & b29);
        s[34] = b34 ^ (~b36 & b38);
        s[35] = b35 ^ (~b37 & b39);
        s[44] = b44 ^ (~b46 & b48);
        s[45] = b45 ^ (~b47 & b49);
        s[6] = b6 ^ (~b8 & b0);
        s[7] = b7 ^ (~b9 & b1);
        s[16] = b16 ^ (~b18 & b10);
        s[17] = b17 ^ (~b19 & b11);
        s[26] = b26 ^ (~b28 & b20);
        s[27] = b27 ^ (~b29 & b21);
        s[36] = b36 ^ (~b38 & b30);
        s[37] = b37 ^ (~b39 & b31);
        s[46] = b46 ^ (~b48 & b40);
        s[47] = b47 ^ (~b49 & b41);
        s[8] = b8 ^ (~b0 & b2);
        s[9] = b9 ^ (~b1 & b3);
        s[18] = b18 ^ (~b10 & b12);
        s[19] = b19 ^ (~b11 & b13);
        s[28] = b28 ^ (~b20 & b22);
        s[29] = b29 ^ (~b21 & b23);
        s[38] = b38 ^ (~b30 & b32);
        s[39] = b39 ^ (~b31 & b33);
        s[48] = b48 ^ (~b40 & b42);
        s[49] = b49 ^ (~b41 & b43);
        s[0] ^= RC[n];
        s[1] ^= RC[n + 1];
    }
}

/**
 * Shake WASM
 */
export class Shake256Wasm {
    public static initializedWasm = false;
    private static instance: WebAssembly.Instance | null = null;
    private static memory: WebAssembly.Memory | null = null;
    private static shake256Func: ((inputPtr: number, inputLen: number, outputPtr: number, outputLen: number) => void) | null = null;
    private static nextPtr: number = 0;
    private static bufferPtr: number = 0;
    private static bufferCap: number = 0;

    /**
     * Initialize WASM
     * @param wasmUrl {string} WASM Url
     */
    public static async initWasm(wasmUrl: string): Promise<void> {
        try {
            if (this.initializedWasm) return;
            const module = await loadWasmModule(wasmUrl);
            const memory = new WebAssembly.Memory({initial: 256, maximum: 512});
            const imports: any = {
                env: {
                    memory, abort: () => {
                        throw new Error("wasm abort");
                    }
                }
            };
            try {
                this.instance = await WebAssembly.instantiate(module, imports);
            } catch {
                const imports2: any = {env: {memory}};
                this.instance = await WebAssembly.instantiate(module, imports2);
            }
            const exports = this.instance.exports as any;
            this.shake256Func = exports.shake256 ?? exports._shake256 ?? null;
            if (!this.shake256Func) throw new Error("shake256 export missing");
            this.memory = (exports.memory as WebAssembly.Memory) ?? memory;
            this.bufferCap = this.memory!.buffer.byteLength;
            this.nextPtr = 0;
            this.initializedWasm = true;
        } catch (e) {
            this.initializedWasm = false;
        }
    }

    /**
     * SHAKE256 WASM
     * @param input {Uint8Array} Input
     * @param outputLen {number} Output length
     */
    public static shake256Wasm(input: Uint8Array, outputLen: number): Uint8Array {
        try {
            if (!this.shake256Func || !this.memory) throw new Error("WASM not initialized");
            if (input.length + outputLen + 64 > this.memory.buffer.byteLength) {
                const needed = input.length + outputLen + 65536;
                const pages = Math.ceil(needed / 65536);
                try {
                    this.memory.grow(pages - this.memory.buffer.byteLength / 65536);
                    this.bufferCap = this.memory.buffer.byteLength;
                } catch {
                }
            }
            const mem = new Uint8Array(this.memory.buffer);
            const inputPtr = this.alloc(input.length);
            const outputPtr = this.alloc(outputLen);
            if (inputPtr === 0 && input.length > 0) throw new Error("alloc failed");
            mem.set(input, inputPtr);
            this.shake256Func(inputPtr, input.length, outputPtr, outputLen);
            const out = new Uint8Array(outputLen);
            out.set(mem.subarray(outputPtr, outputPtr + outputLen));
            this.nextPtr = outputPtr + outputLen;
            return out;
        } catch (e) {
            this.initializedWasm = false;
            return Shake256.hashSync(input, outputLen);
        }
    }

    // Allocation
    private static alloc(size: number): number {
        const ptr = this.nextPtr;
        const next = ptr + ((size + 7) & ~7);
        if (next > this.bufferCap) {
            this.nextPtr = 0;
            return 0;
        }
        this.nextPtr = next;
        return ptr;
    }
}

/**
 * Check if wasm is initialized
 */
export function isWasmShake() {
    return Shake256Wasm.initializedWasm;
}

/**
 * Keccak State
 */
export class KeccakState {
    public s: Uint32Array;
    private pos: number = 0;

    /**
     * Create Keccak state
     */
    constructor() {
        this.s = new Uint32Array(50);
    }

    /**
     * Reset Keccak State
     */
    public reset() {
        this.s.fill(0);
        this.pos = 0;
    }

    /**
     * Absorb Byte
     * @param byte {number} Byte
     * @param index {number} Index
     */
    public absorbByte(byte: number, index: number): void {
        const wordLane = index >> 2;
        const wordShift = (index & 3) << 3;
        this.s[wordLane] ^= byte << wordShift;
    }

    /**
     * Absorb bytes bulk
     * @param data {Uint8Array} Data
     * @param inOffset {number} In offset
     * @param len {number} Length
     */
    public absorbBulk(data: Uint8Array, inOffset: number, len: number): number {
        let written = 0;
        while (written < len) {
            const space = RATE_BYTES - this.pos;
            const take = Math.min(space, len - written);
            let p = this.pos;
            let src = inOffset + written;
            const s = this.s;
            let i = 0;
            for (; i + 3 < take; i += 4) {
                const w = data[src + i] | (data[src + i + 1] << 8) | (data[src + i + 2] << 16) | (data[src + i + 3] << 24);
                const lane = (p + i) >> 2;
                const shift = ((p + i) & 3) << 3;
                if (shift === 0) s[lane] ^= w;
                else {
                    s[lane] ^= w << shift;
                    s[lane + 1] ^= w >>> (32 - shift);
                }
            }
            for (; i < take; i++) {
                const lane = (p + i) >> 2;
                const shift = ((p + i) & 3) << 3;
                s[lane] ^= data[src + i] << shift;
            }
            this.pos += take;
            written += take;
            if (this.pos === RATE_BYTES) {
                keccakF(this.s);
                this.pos = 0;
            }
        }
        return written;
    }

    /**
     * Pad and Permute
     */
    public padAndPermute() {
        const p = this.pos;
        this.s[p >> 2] ^= 0x1f << ((p & 3) << 3);
        this.s[(RATE_BYTES - 1) >> 2] ^= 0x80 << (((RATE_BYTES - 1) & 3) << 3);
        keccakF(this.s);
        this.pos = 0;
    }

    /**
     * Extract byte
     * @param index {number} Index
     */
    public extractByte(index: number): number {
        const wordLane = index >> 2;
        const wordShift = (index & 3) << 3;
        return (this.s[wordLane] >>> wordShift) & 0xff;
    }

    /**
     * Squeeze into
     * @param out {Uint8Array} Output
     * @param outOff {number} Offset
     * @param len {number} Length
     */
    public squeezeInto(out: Uint8Array, outOff: number, len: number) {
        let pos = 0;
        let squeezePos = 0;
        while (pos < len) {
            const take = Math.min(RATE_BYTES - squeezePos, len - pos);
            for (let i = 0; i < take; i++) out[outOff + pos + i] = (this.s[(squeezePos + i) >> 2] >>> (((squeezePos + i) & 3) << 3)) & 0xff;
            pos += take;
            squeezePos += take;
            if (squeezePos === RATE_BYTES) {
                if (pos < len) keccakF(this.s);
                squeezePos = 0;
            }
        }
    }

    /**
     * Permute
     */
    public permute(): void {
        keccakF(this.s);
    }
}

/**
 * Shake256 Implementation
 */
export class Shake256 {
    /**
     * Hash
     * @param input {Uint8Array} Input
     * @param outputLength {number} Output length
     */
    public static async hash(input: Uint8Array, outputLength: number): Promise<Uint8Array> {
        return this.process(input, outputLength);
    }

    /**
     * Hash in Sync Mode
     * @param input {Uint8Array} Input
     * @param outputLength {number} Output length
     */
    public static hashSync(input: Uint8Array, outputLength: number): Uint8Array {
        return this.process(input, outputLength);
    }

    /**
     * Hash chunks in sync mode
     * @param chunks {Uint8Array} Chunks
     * @param outputLength {number} Output length
     */
    public static hashMultiSync(chunks: Uint8Array[], outputLength: number): Uint8Array {
        const st = new KeccakState();
        for (const c of chunks) if (c.length) st.absorbBulk(c, 0, c.length);
        st.padAndPermute();
        const out = new Uint8Array(outputLength);
        st.squeezeInto(out, 0, outputLength);
        return out;
    }

    /**
     * Hash chunks
     * @param chunks {Uint8Array} Chunks
     * @param outputLength {number} Output length
     */
    public static async hashMulti(chunks: Uint8Array[], outputLength: number): Promise<Uint8Array> {
        return this.hashMultiSync(chunks, outputLength);
    }

    // Process SHAKE hash
    private static process(input: Uint8Array, outputLength: number): Uint8Array {
        const st = new KeccakState();
        if (input.length) st.absorbBulk(input, 0, input.length);
        st.padAndPermute();
        const out = new Uint8Array(outputLength);
        st.squeezeInto(out, 0, outputLength);
        return out;
    }
}
