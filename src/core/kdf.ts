/**
 * QuarkDash Shake256 Based KDF
 *
 * @git             https://github.com/devsdaddy/quarkdash
 * @version         1.1.0
 * @author          Elijah Rastorguev
 * @build           1001
 * @website         https://dev.to/devsdaddy
 * @updated         13.04.2026
 */
/* Import Required Modules */
import type {IKDF} from "./types";
import { QuarkDashUtils } from "./utils";

/**
 * KDF implementation using Shake-256
 */
export class QuarkDashKDF implements IKDF {
    /**
     * Derive KDF async
     * @param ikm {Uint8Array} IKM buffer
     * @param salt {Uint8Array} Salt buffer
     * @param info {Uint8Array} Meta buffer
     * @param length {number} Buffer length
     * @returns {Promise<Uint8Array>} Result
     * TODO: GPU Calculations
     */
    public async derive(ikm: Uint8Array, salt: Uint8Array, info: Uint8Array, length: number): Promise<Uint8Array> {
        const prk = await QuarkDashUtils.shake256(QuarkDashUtils.concatBytes(salt, ikm), 64) as Uint8Array;
        const result = new Uint8Array(length);
        let t = new Uint8Array(0) as Uint8Array;
        let i = 1;
        while (result.length < length) {
            const input = QuarkDashUtils.concatBytes(t, info, new Uint8Array([i])) as Uint8Array;
            t = await QuarkDashUtils.shake256(QuarkDashUtils.concatBytes(prk, input), 64);
            const take = Math.min(t.length, length - result.length);
            result.set(t.slice(0, take), result.length);
            i++;
        }
        return result;
    }

    /**
     * Derive KDF sync
     * @param ikm {Uint8Array} IKM buffer
     * @param salt {Uint8Array} Salt buffer
     * @param info {Uint8Array} Meta buffer
     * @param length {number} Buffer length
     * @returns {Uint8Array} Result
     */
    public deriveSync(ikm: Uint8Array, salt: Uint8Array, info: Uint8Array, length: number): Uint8Array {
        const prk = QuarkDashUtils.shake256Sync(QuarkDashUtils.concatBytes(salt, ikm), 64);
        const result = new Uint8Array(length);
        let t = new Uint8Array(0) as Uint8Array;
        let i = 1;
        while (result.length < length) {
            const input = QuarkDashUtils.concatBytes(t, info, new Uint8Array([i]));
            t = QuarkDashUtils.shake256Sync(QuarkDashUtils.concatBytes(prk, input), 64);
            const take = Math.min(t.length, length - result.length);
            result.set(t.slice(0, take), result.length);
            i++;
        }
        return result;
    }
}