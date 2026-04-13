/**
 * QuarkDash Shake256 Based MAC
 *
 * @git             https://github.com/devsdaddy/quarkdash
 * @version         1.1.0
 * @author          Elijah Rastorguev
 * @build           1001
 * @website         https://dev.to/devsdaddy
 * @updated         13.04.2026
 */
/* Import Required Modules */
import {IMAC} from "./types";
import {QuarkDashUtils} from "./utils";

/**
 * MAC implementation using Shake-256
 */
export class QuarkDashMAC implements IMAC {
    /**
     * Sign data async
     * @param data {Uint8Array} Data buffer
     * @param key {Uint8Array} Key buffer
     * @returns {Promise<Uint8Array>} Signed result buffer
     * TODO: GPU Calculations
     */
    public async sign(data: Uint8Array, key: Uint8Array): Promise<Uint8Array> {
        const full = QuarkDashUtils.concatBytes(key, data);
        return await QuarkDashUtils.shake256(full, 32);
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