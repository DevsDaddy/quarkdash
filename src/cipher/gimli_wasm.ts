/**
 * QuarkDash Protocol Gimli WASM Wrapper
 *
 * @git             https://github.com/devsdaddy/quarkdash
 * @version         1.2.0
 * @author          Elijah Rastorguev
 * @build           1033
 * @website         https://dev.to/devsdaddy
 * @updated         05.09.2026
 */
/* Import required modules */
import {loadWasmModule} from "../core/wasm_loader";

/**
 * Gimli WASM
 */
export class GimliWasm {
    // Check initialization
    static initializedWasm = false;

    // Memory methods
    private static instance: WebAssembly.Instance | null = null;
    private static memory: WebAssembly.Memory | null = null;
    private static gimliBlockFunc: ((kp: number, np: number, bi: number, op: number) => void) | null = null;
    private static gimliXorFunc: ((kp: number, np: number, dp: number, op: number, len: number, off: number) => void) | null = null;
    private static nextPtr = 0;
    private static bufferCap = 0;
    private static memU8: Uint8Array | null = null;
    private static cachedKeyPtr = -1;
    private static cachedNoncePtr = -1;
    private static cachedKey: Uint8Array | null = null;
    private static cachedNonce: Uint8Array | null = null;
    private static threshold = 1024;

    /**
     * Initialize WASM
     * @param wasmUrl {string} WASM URL
     */
    public static async initWasm(wasmUrl: string): Promise<void> {
        if (this.initializedWasm) return;
        try {
            const mod = await loadWasmModule(wasmUrl);
            const memory = new WebAssembly.Memory({initial: 64, maximum: 128});
            const imports: any = {
                env: {
                    memory, abort: () => {
                        throw new Error("wasm abort");
                    }
                }
            };
            try {
                this.instance = await WebAssembly.instantiate(mod, imports);
            } catch {
                this.instance = await WebAssembly.instantiate(mod, {env: {memory}} as any);
            }
            const exp = this.instance.exports as any;
            this.gimliBlockFunc = exp.gimli_block ?? null;
            this.gimliXorFunc = exp.gimli_xor ?? null;
            if (!this.gimliBlockFunc) throw new Error("gimli_block missing");
            this.memory = (exp.memory as WebAssembly.Memory) ?? memory;
            this.bufferCap = this.memory.buffer.byteLength;
            this.memU8 = new Uint8Array(this.memory.buffer);
            this.nextPtr = 0;
            this.cachedKeyPtr = this.alloc(32);
            this.cachedNoncePtr = this.alloc(12);
            this.cachedKey = null;
            this.cachedNonce = null;
            this.initializedWasm = true;
        } catch {
            this.initializedWasm = false;
        }
    }

    /**
     * Check is ready
     */
    public static isReady(): boolean {
        return this.initializedWasm && !!this.gimliBlockFunc && !!this.memory;
    }

    /**
     * Gimli Block
     * @param key {Uint8Array} Key
     * @param nonce {Uint8Array} Nonce
     * @param blockIndex {number} Block Index
     */
    public static gimliBlock(key: Uint8Array, nonce: Uint8Array, blockIndex: number): Uint8Array | null {
        try {
            if (!this.isReady()) return null;
            const mem = this.ensureMem();
            this.syncKeyNonce(key, nonce);
            const outPtr = this.alloc(48);
            if (outPtr === -1) {
                this.nextPtr = 48;
                return null;
            }
            this.gimliBlockFunc!(this.cachedKeyPtr, this.cachedNoncePtr, blockIndex, outPtr);
            const out = new Uint8Array(48);
            out.set(mem.subarray(outPtr, outPtr + 48));
            return out;
        } catch {
            this.initializedWasm = false;
            return null;
        }
    }

    /**
     * Gimli XOR
     * @param key {Uint8Array} Key
     * @param nonce {Uint8Array} Nonce
     * @param data {Uint8Array} Data
     * @param offset {number} Offset
     */
    public static gimliXor(key: Uint8Array, nonce: Uint8Array, data: Uint8Array, offset: number): Uint8Array | null {
        try {
            if (!this.isReady() || !this.gimliXorFunc) return null;
            if (data.length < this.threshold) return null;
            const total = data.length;
            const need = total + 64 + 48 + 32;
            if (this.nextPtr + need > this.bufferCap) {
                const grow = Math.ceil((this.nextPtr + need - this.bufferCap) / 65536) + 1;
                try {
                    this.memory!.grow(grow);
                    this.bufferCap = this.memory!.buffer.byteLength;
                    this.memU8 = new Uint8Array(this.memory!.buffer);
                } catch {
                    return null;
                }
            }
            const mem = this.ensureMem();
            this.syncKeyNonce(key, nonce);
            const dataPtr = this.alloc(total);
            const outPtr = this.alloc(total);
            if (dataPtr === -1 || outPtr === -1) return null;
            mem.set(data, dataPtr);
            this.gimliXorFunc!(this.cachedKeyPtr, this.cachedNoncePtr, dataPtr, outPtr, total, offset);
            const out = new Uint8Array(total);
            out.set(mem.subarray(outPtr, outPtr + total));
            return out;
        } catch {
            this.initializedWasm = false;
            return null;
        }
    }

    /**
     * Ensure memory
     * @private
     */
    private static ensureMem(): Uint8Array {
        if (!this.memU8 || this.memU8.buffer !== this.memory!.buffer) this.memU8 = new Uint8Array(this.memory!.buffer);
        return this.memU8!;
    }

    /**
     * Sync Key and Nonce
     * @param key {Uint8Array} Key
     * @param nonce {Uint8Array} Nonce
     * @private
     */
    private static syncKeyNonce(key: Uint8Array, nonce: Uint8Array): boolean {
        const mem = this.ensureMem();
        let changed = false;
        if (!this.cachedKey || this.cachedKey.length !== 32 || !equal(this.cachedKey, key)) {
            mem.set(key, this.cachedKeyPtr);
            this.cachedKey = key.slice();
            changed = true;
        }
        if (!this.cachedNonce || this.cachedNonce.length !== 12 || !equal(this.cachedNonce, nonce)) {
            mem.set(nonce, this.cachedNoncePtr);
            this.cachedNonce = nonce.slice();
            changed = true;
        }
        return changed;
    }

    /**
     * Allocate memory for Gimli
     * @param size {number} Memory size
     * @private
     */
    private static alloc(size: number): number {
        const ptr = this.nextPtr;
        const next = (ptr + 7) & ~7;
        const end = next + ((size + 7) & ~7);
        if (end > this.bufferCap) {
            this.nextPtr = 1024;
            return 1024;
        }
        this.nextPtr = end;
        return next;
    }
}

/**
 * Equal
 * @param a
 * @param b
 */
function equal(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
    return true;
}

/**
 * Is WASM Gimli
 */
export function isWasmGimli(): boolean {
    return GimliWasm.isReady();
}
