/**
 * QuarkDash Ciphers Implementation
 *
 * @git             https://github.com/devsdaddy/quarkdash
 * @version         1.1.0
 * @author          Elijah Rastorguev
 * @build           1002
 * @website         https://dev.to/devsdaddy
 * @updated         13.04.2026
 */
/* Import Required Modules */
import {ICipher} from "../core/types";
import {QuarkDashUtils} from "../core/utils";
import {QuarkDashChaCha} from "./chacha";
import {QuarkDashGimli} from "./gimli";

/**
 * Cipher Type
 */
export enum CipherType {
    ChaCha20 = 0,
    Gimli = 1
}

/**
 * Cipher Factory
 */
export class CipherFactory {
    /**
     * Create Cipher
     * @param algorithm {CipherType} Current cipher type
     * @param key {Uint8Array} Key buffer
     * @param nonce {Uint8Array} Nonce buffer
     * @returns {ICipher} Cipher class instance
     */
    static create(algorithm: CipherType, key: Uint8Array, nonce: Uint8Array): ICipher {
        switch(algorithm) {
            case CipherType.ChaCha20: return new QuarkDashChaCha(key, nonce);
            case CipherType.Gimli: return new QuarkDashGimli(key, nonce);
            default: throw new Error('Unsupported cipher type');
        }
    }
}