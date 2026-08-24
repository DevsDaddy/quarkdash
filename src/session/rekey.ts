/**
 * QuarkDash Protocol Re-keying (Keys rotation)
 * This module is required for keys lifetime.
 * We need to change our keys (session and mac) and replace it
 * with KDF. Old keys replace with secureZero
 *
 * How it works:
 * - Initiator generates 32B of salt, calculate payload [0x51 | counter | salt]
 * - Both sides make KDF (oldKey||oldMac, salt, "quarkdash-rekey-v1:counter") - 64B
 * - First 32B - new session key, second 32B - new mac key
 * - Counter is growth, statistic is reset
 *
 * @git             https://github.com/devsdaddy/quarkdash
 * @version         1.2.0
 * @author          Elijah Rastorguev
 * @build           1023
 * @website         https://dev.to/devsdaddy
 * @updated         22.08.2026
 */
/* Import required modules */
import {QuarkDashUtils} from "../core/utils";
import {IKDF} from "../core/types";

/**
 * Key rotation policy
 * When we need to switch keys.
 * Can do it by bytes, messages or time
 */
export interface RekeyPolicy {
    afterBytes: number;               // for example, after 64 MB
    afterMessages: number;            // for example, after 10k messages
    intervalMs: number;               // 0 = without time limit
}

/**
 * Default Key rotation policy
 */
export const DEFAULT_REKEY_POLICY: RekeyPolicy = {
    afterBytes: 64 * 1024 * 1024,
    afterMessages: 10000,
    intervalMs: 0,
};

/**
 * Derive 64B of new material from old keys + new salt
 * @param kdf {IKDF} KDF
 * @param oldKey {Uint8Array} Old key
 * @param oldMac {Uint8Array} Old MAC
 * @param salt {Uint8Array} Salt
 * @param counter {number} Counter
 * @param infoExtra {string} Extra info
 */
export async function deriveRekeyMaterial(
    kdf: IKDF,
    oldKey: Uint8Array,
    oldMac: Uint8Array,
    salt: Uint8Array,
    counter: number,
    infoExtra = "",
): Promise<Uint8Array> {
    // Join both keys - our IKM, salt is separated
    const ikm = QuarkDashUtils.concatBytes(oldKey, oldMac);
    const info = QuarkDashUtils.textToBytes(
        `quarkdash-rekey-v1:${counter}:${infoExtra}`,
    );
    const out = await kdf.derive(ikm, salt, info, 64);
    QuarkDashUtils.secureZero(ikm); // cleanup old material
    return out;
}

/**
 * Derive new material in sync mode
 * @param kdf {IKDF} KDF
 * @param oldKey {Uint8Array} Old key
 * @param oldMac {Uint8Array} Old MAC
 * @param salt {Uint8Array} Salt
 * @param counter {number} Counter
 * @param infoExtra {string} Extra info
 */
export function deriveRekeyMaterialSync(
    kdf: IKDF,
    oldKey: Uint8Array,
    oldMac: Uint8Array,
    salt: Uint8Array,
    counter: number,
    infoExtra: string = "",
): Uint8Array {
    const ikm = QuarkDashUtils.concatBytes(oldKey, oldMac);
    const info = QuarkDashUtils.textToBytes(
        `quarkdash-rekey-v1:${counter}:${infoExtra}`,
    );
    const out = kdf.deriveSync(ikm, salt, info, 64);
    QuarkDashUtils.secureZero(ikm);
    return out;
}

/**
 * Build Key Rotation Payload
 * using small binary format to salt exchange [0x51 | counter LE32 | salt32]
 * @param salt
 * @param counter
 */
export function buildRekeyPayload(
    salt: Uint8Array,
    counter: number,
): Uint8Array {
    const payload = new Uint8Array(1 + 4 + salt.length);
    payload[0] = 0x51; // magic "Q" for QuarkDash
    payload[1] = counter & 0xff;
    payload[2] = (counter >> 8) & 0xff;
    payload[3] = (counter >> 16) & 0xff;
    payload[4] = (counter >> 24) & 0xff;
    payload.set(salt, 5);
    return payload;
}

/**
 * Parse Key Rotation Payload
 * @param payload {Uint8Array} Payload
 */
export function parseRekeyPayload(payload: Uint8Array): {
    salt: Uint8Array;
    counter: number;
} {
    if (payload.length < 5 || payload[0] !== 0x51)
        throw new Error("Invalid rekey payload");
    const counter =
        payload[1] | (payload[2] << 8) | (payload[3] << 16) | (payload[4] << 24);
    const salt = payload.slice(5);
    if (salt.length !== 32) throw new Error("Invalid rekey salt length");
    return {salt, counter};
}
