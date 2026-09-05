/**
 * QuarkDash Protocol NTT WASM Wrapper
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
 * NTT WASM Wrapper
 */
export class NttWasm {
    // Initialization state
    static initializedWasm = false;

    // For memory management
    private static instance: WebAssembly.Instance | null = null;
    private static memory: WebAssembly.Memory | null = null;
    private static multiplyFunc: ((a: number, b: number, o: number, q: number, root: number, invN: number) => void) | null = null;
    private static nttFunc: ((i: number, o: number, q: number, root: number) => void) | null = null;
    private static invFunc: ((i: number, o: number, q: number, root: number, invN: number) => void) | null = null;
    private static memU32: Uint32Array | null = null;
    private static readonly A_PTR = 0;
    private static readonly B_PTR = 1024;
    private static readonly OUT_PTR = 2048;
    private static readonly TMP_NEEDED = 4096;

    /**
     * Initialize WASM Module
     * @param wasmUrl {string} WASM Url
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

            this.multiplyFunc = exp.multiply ?? null;
            this.nttFunc = exp.ntt ?? null;
            this.invFunc = exp.inv_ntt ?? exp.invNtt ?? null;
            if (!this.multiplyFunc) throw new Error("multiply missing");

            this.memory = (exp.memory as WebAssembly.Memory) ?? memory;
            this.memU32 = new Uint32Array(this.memory.buffer);
            this.initializedWasm = true;
        } catch {
            this.initializedWasm = false;
        }
    }

    /**
     * Check if module is ready
     */
    public static isReady(): boolean {
        return this.initializedWasm && !!this.multiplyFunc && !!this.memory;
    }

    /**
     * Multiply
     * @param a
     * @param b
     * @param q
     * @param root
     * @param invN
     */
    public static multiply(a: bigint[], b: bigint[], q: bigint, root: bigint, invN: bigint): bigint[] | null {
        try {
            if (!this.isReady()) return null;

            const N = a.length;
            if (N !== 256 || b.length !== 256) return null;

            const qn = Number(q), rn = Number(root), invn = Number(invN);
            const v = this.ensureView();

            for (let i = 0; i < N; i++) v[this.A_PTR / 4 + i] = Number(((a[i] % q) + q) % q);
            for (let i = 0; i < N; i++) v[this.B_PTR / 4 + i] = Number(((b[i] % q) + q) % q);

            this.multiplyFunc!(this.A_PTR, this.B_PTR, this.OUT_PTR, qn, rn, invn);

            const res = new Array<bigint>(N);
            const view = this.ensureView();
            for (let i = 0; i < N; i++) res[i] = BigInt(view[this.OUT_PTR / 4 + i]);

            return res;
        } catch {
            this.initializedWasm = false;
            return null;
        }
    }

    /**
     * NTT
     * @param poly
     * @param q
     * @param root
     */
    public static ntt(poly: bigint[], q: bigint, root: bigint): bigint[] | null {
        try {
            if (!this.isReady() || !this.nttFunc) return null;

            const N = poly.length, qn = Number(q), rn = Number(root);
            const v = this.ensureView();

            for (let i = 0; i < N; i++) v[this.A_PTR / 4 + i] = Number(((poly[i] % q) + q) % q);
            this.nttFunc!(this.A_PTR, this.OUT_PTR, qn, rn);
            const res = new Array<bigint>(N);
            const view = this.ensureView();

            for (let i = 0; i < N; i++) res[i] = BigInt(view[this.OUT_PTR / 4 + i]);

            return res;
        } catch {
            this.initializedWasm = false;
            return null;
        }
    }

    /**
     * Inv NTT
     * @param poly
     * @param q
     * @param root
     * @param invN
     */
    public static invNtt(poly: bigint[], q: bigint, root: bigint, invN: bigint): bigint[] | null {
        try {
            if (!this.isReady() || !this.invFunc) return null;

            const N = poly.length, qn = Number(q), rn = Number(root), invn = Number(invN);
            const v = this.ensureView();

            for (let i = 0; i < N; i++) v[this.A_PTR / 4 + i] = Number(((poly[i] % q) + q) % q);

            this.invFunc!(this.A_PTR, this.OUT_PTR, qn, rn, invn);

            const res = new Array<bigint>(N);
            const view = this.ensureView();
            for (let i = 0; i < N; i++) res[i] = BigInt(view[this.OUT_PTR / 4 + i]);

            return res;
        } catch {
            this.initializedWasm = false;
            return null;
        }
    }

    /**
     * Ensure View
     * @private
     */
    private static ensureView(): Uint32Array {
        if (!this.memU32 || this.memU32.buffer !== this.memory!.buffer) this.memU32 = new Uint32Array(this.memory!.buffer);
        return this.memU32!;
    }
}

/**
 * Is WASM NTT
 */
export function isWasmNtt(): boolean {
    return NttWasm.isReady();
}
