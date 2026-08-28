/**
 * QuarkDash Radical Ring-LWE Implementation
 *
 * @git             https://github.com/devsdaddy/quarkdash
 * @version         1.1.0
 * @author          Elijah Rastorguev
 * @build           1010
 * @website         https://dev.to/devsdaddy
 * @updated         28.08.2026
 */
/* Import required modules */
import {
    ICryptoEncapsulated,
    ICryptoKeyPair,
    IKeyExchange,
} from "../core/types";
import {QuarkDashUtils} from "../core/utils";
import {SHA256} from "../hash/sha";
import {BaseRingLWE} from "./baselwe";

/**
 * QuarkDash Radical Ring-LWE Implementation
 */
export class QuarkDashRRLWE extends BaseRingLWE implements IKeyExchange {
    // RRLWE Constants
    protected override readonly N = 256;
    protected override readonly Q = 12289n;
    protected override readonly ROOT = 8340n;
    protected override readonly INV_N = this.modInverse(BigInt(this.N), this.Q);
}
