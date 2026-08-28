/**
 * QuarkDash Protocol MAC (SHAKE256 Based)
 * A simple and powerful MAC: key + data over SHAKE256 (with WASM if supported)
 * Take a 32B tag. Check with constant-time.
 *
 * We use reusable 64B buffer to prevent allocation every `signTwo()` call
 *
 * @git             https://github.com/devsdaddy/quarkdash
 * @version         1.2.0
 * @author          Elijah Rastorguev
 * @build           1028
 * @website         https://dev.to/devsdaddy
 * @updated         28.08.2026
 */
/* Import required modules */
import {IMAC} from "./types";
import {QuarkDashUtils} from "./utils";
import {Shake256, Shake256Wasm, isWasmShake} from "../hash/shake";

/**
 * QuarkDash MAC Implementation
 */
export class QuarkDashMAC implements IMAC {
    // Reusable 64KB buffer. If need more - extend
    private tempBuffer: Uint8Array;

    /**
     * Create QuarkDash MAC
     */
    constructor() {
        this.tempBuffer = new Uint8Array(64 * 1024);
    }

    /**
     * Sign with 32B tag
     * @param data {Uint8Array} Data buffer
     * @param key {Uint8Array} Key
     */
    public async sign(data: Uint8Array, key: Uint8Array): Promise<Uint8Array> {
        if (isWasmShake()) {
            const full = QuarkDashUtils.concatBytes(key, data);
            return Shake256Wasm.shake256Wasm(full, 32);
        }
        return Shake256.hashMulti([key, data], 32);
    }

    /**
     * Sing with 32B tag in sync mode
     * @param data {Uint8Array} Data buffer
     * @param key {Uint8Array} Key
     */
    public signSync(data: Uint8Array, key: Uint8Array): Uint8Array {
        if (isWasmShake()) {
            const full = QuarkDashUtils.concatBytes(key, data);
            return Shake256Wasm.shake256Wasm(full, 32);
        }
        return Shake256.hashMultiSync([key, data], 32);
    }

    /**
     * Verify MAC tag to prevent timing-attacks
     * @param data {Uint8Array} Data buffer
     * @param key {Uint8Array} Key
     * @param tag {Uint8Array} Tag
     */
    public async verify(
        data: Uint8Array,
        key: Uint8Array,
        tag: Uint8Array,
    ): Promise<boolean> {
        const expected = await this.sign(data, key);
        return QuarkDashUtils.constantTimeEqual(expected, tag);
    }

    /**
     * Verify MAC tag to prevent timing-attacks in sync mode
     * @param data {Uint8Array} Data buffer
     * @param key {Uint8Array} Key
     * @param tag {Uint8Array} Tag
     */
    public verifySync(
        data: Uint8Array,
        key: Uint8Array,
        tag: Uint8Array,
    ): boolean {
        const expected = this.signSync(data, key);
        return QuarkDashUtils.constantTimeEqual(expected, tag);
    }

    /**
     * Sign two slices
     * @param data1 {Uint8Array} Data slice
     * @param data2 {Uint8Array} Data slice
     * @param key {Uint8Array} Key
     */
    public async signTwo(
        data1: Uint8Array,
        data2: Uint8Array,
        key: Uint8Array,
    ): Promise<Uint8Array> {
        if (isWasmShake()) {
            const totalLen = key.length + data1.length + data2.length;
            if (totalLen > this.tempBuffer.length)
                this.tempBuffer = new Uint8Array(totalLen);
            this.tempBuffer.set(key, 0);
            this.tempBuffer.set(data1, key.length);
            this.tempBuffer.set(data2, key.length + data1.length);
            return Shake256Wasm.shake256Wasm(this.tempBuffer.subarray(0, totalLen), 32);
        }
        return Shake256.hashMulti([key, data1, data2], 32);
    }

    /**
     * Sign two slices in sync mode
     * @param data1 {Uint8Array} Data slice
     * @param data2 {Uint8Array} Data slice
     * @param key {Uint8Array} Key
     */
    public signTwoSync(
        data1: Uint8Array,
        data2: Uint8Array,
        key: Uint8Array,
    ): Uint8Array {
        if (isWasmShake()) {
            const totalLen = key.length + data1.length + data2.length;
            const combined = new Uint8Array(totalLen);
            combined.set(key, 0);
            combined.set(data1, key.length);
            combined.set(data2, key.length + data1.length);
            return Shake256Wasm.shake256Wasm(combined, 32);
        }
        return Shake256.hashMultiSync([key, data1, data2], 32);
    }
}
