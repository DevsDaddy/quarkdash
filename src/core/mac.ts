/**
 * QuarkDash Shake256 Based MAC
 *
 * @git             https://github.com/devsdaddy/quarkdash
 * @version         1.1.0
 * @author          Elijah Rastorguev
 * @build           1003
 * @website         https://dev.to/devsdaddy
 * @updated         14.04.2026
 */
/* Import Required Modules */
import {IMAC} from "./types";
import {QuarkDashUtils} from "./utils";
import {Shake256, Shake256Wasm, isWasmShake} from "../hash/shake";

/**
 * MAC implementation using Shake-256
 */
export class QuarkDashMAC implements IMAC {
    // Temporary buffer
    private tempBuffer: Uint8Array;
    constructor() {
        this.tempBuffer = new Uint8Array(64 * 1024);
    }

    /**
     * Sign data async
     * @param data {Uint8Array} Data buffer
     * @param key {Uint8Array} Key buffer
     * @returns {Promise<Uint8Array>} Signed result buffer
     * TODO: GPU Calculations
     */
    public async sign(data: Uint8Array, key: Uint8Array): Promise<Uint8Array> {
        const full = QuarkDashUtils.concatBytes(key, data);
        return (isWasmShake()) ? Shake256Wasm.shake256Wasm(full, 32) : Shake256.hash(full, 32);
    }

    /**
     * Verify async
     * @param data {Uint8Array} data buffer
     * @param key {Uint8Array} key buffer
     * @param tag {Uint8Array} tag buffer
     * @returns {Promise<boolean>} Is verified?
     * TODO: GPU Calculations
     */
    public async verify(data: Uint8Array, key: Uint8Array, tag: Uint8Array): Promise<boolean> {
        const expected = await this.sign(data, key);
        return QuarkDashUtils.constantTimeEqual(expected, tag);
    }

    /**
     * Sign two async
     * @param data1 {Uint8Array} First buffer
     * @param data2 {Uint8Array} Second buffer
     * @param key {Uint8Array} Key
     * @returns {Promise<Uint8Array>}
     */
    public async signTwo(data1: Uint8Array, data2: Uint8Array, key: Uint8Array): Promise<Uint8Array> {
        const totalLen = key.length + data1.length + data2.length;
        if (totalLen > this.tempBuffer.length) {
            this.tempBuffer = new Uint8Array(totalLen);
        }
        this.tempBuffer.set(key, 0);
        this.tempBuffer.set(data1, key.length);
        this.tempBuffer.set(data2, key.length + data1.length);
        return (isWasmShake()) ? Shake256Wasm.shake256Wasm(this.tempBuffer.subarray(0, totalLen), 32) : Shake256.hash(this.tempBuffer.subarray(0, totalLen), 32);
    }

    /**
     * Sign two sync
     * @param data1 {Uint8Array} First buffer
     * @param data2 {Uint8Array} Second buffer
     * @param key {Uint8Array} Key
     * @returns {Uint8Array}
     */
    public signTwoSync(data1: Uint8Array, data2: Uint8Array, key: Uint8Array): Uint8Array {
        const totalLen = key.length + data1.length + data2.length;
        const combined = new Uint8Array(totalLen);
        combined.set(key, 0);
        combined.set(data1, key.length);
        combined.set(data2, key.length + data1.length);
        return (isWasmShake()) ? Shake256Wasm.shake256Wasm(combined, 32) : Shake256.hashSync(combined, 32);
    }

    /**
     * Sign data sync
     * @param data {Uint8Array} Data buffer
     * @param key {Uint8Array} Key buffer
     * @returns {Uint8Array} Signed result buffer
     */
    public signSync(data: Uint8Array, key: Uint8Array): Uint8Array {
        const full = QuarkDashUtils.concatBytes(key, data);
        return QuarkDashUtils.shake256Sync(full, 32);
    }

    /**
     * Verify sync
     * @param data {Uint8Array} data buffer
     * @param key {Uint8Array} key buffer
     * @param tag {Uint8Array} tag buffer
     * @returns {Promise<boolean>} Is verified?
     */
    public verifySync(data: Uint8Array, key: Uint8Array, tag: Uint8Array): boolean {
        const expected = this.signSync(data, key);
        return QuarkDashUtils.constantTimeEqual(expected, tag);
    }
}