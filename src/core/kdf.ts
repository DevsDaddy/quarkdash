/**
 * QuarkDash KDF Implementation
 *
 * @git             https://github.com/devsdaddy/quarkdash
 * @version         1.1.0
 * @author          Elijah Rastorguev
 * @build           1009
 * @website         https://dev.to/devsdaddy
 * @updated         28.08.2026
 */
/* Import required modules */
import type {IKDF} from "./types";
import {QuarkDashUtils} from "./utils";

/**
 * QuarkDash KDF
 */
export class QuarkDashKDF implements IKDF {
    /**
     * Derive KDF
     * @param ikm {Uint8Array} IKM
     * @param salt {Uint8Array} Salt
     * @param info {Uint8Array} Information
     * @param length {number} Length
     */
    public async derive(
        ikm: Uint8Array,
        salt: Uint8Array,
        info: Uint8Array,
        length: number,
    ): Promise<Uint8Array> {
        const prk = (await QuarkDashUtils.shake256(
            QuarkDashUtils.concatBytes(salt, ikm),
            64,
        )) as Uint8Array;
        const result = new Uint8Array(length);
        let t = new Uint8Array(0) as Uint8Array;
        let pos = 0;
        let i = 1;
        while (pos < length) {
            const input = QuarkDashUtils.concatBytes(
                t,
                info,
                new Uint8Array([i]),
            ) as Uint8Array;
            t = await QuarkDashUtils.shake256(
                QuarkDashUtils.concatBytes(prk, input),
                64,
            );
            const take = Math.min(t.length, length - pos);
            result.set(t.slice(0, take), pos);
            pos += take;
            i++;
        }
        return result;
    }

    /**
     * Derive in sync mode
     * @param ikm {Uint8Array} IKM
     * @param salt {Uint8Array} Salt
     * @param info {Uint8Array} Information
     * @param length {number} Length
     */
    public deriveSync(
        ikm: Uint8Array,
        salt: Uint8Array,
        info: Uint8Array,
        length: number,
    ): Uint8Array {
        const prk = QuarkDashUtils.shake256Sync(
            QuarkDashUtils.concatBytes(salt, ikm),
            64,
        );
        const result = new Uint8Array(length);
        let t = new Uint8Array(0) as Uint8Array;
        let pos = 0;
        let i = 1;
        while (pos < length) {
            const input = QuarkDashUtils.concatBytes(t, info, new Uint8Array([i]));
            t = QuarkDashUtils.shake256Sync(
                QuarkDashUtils.concatBytes(prk, input),
                64,
            );
            const take = Math.min(t.length, length - pos);
            result.set(t.slice(0, take), pos);
            pos += take;
            i++;
        }
        return result;
    }
}
