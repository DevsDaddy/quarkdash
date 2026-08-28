/**
 * QuarkDash Ring-LWE Implementation
 *
 * @git             https://github.com/devsdaddy/quarkdash
 * @version         1.1.0
 * @author          Elijah Rastorguev
 * @build           1011
 * @website         https://dev.to/devsdaddy
 * @updated         28.08.2026
 */
/* Import Required Modules */
import {
    IKeyExchange,
} from "../core/types";
import {BaseRingLWE} from "./baselwe";

/**
 * Ring-LWE based key exchange implementation
 */
export class QuarkDashRLWE extends BaseRingLWE implements IKeyExchange {
    // Ring-LWE Constants
    protected override readonly N = 256;
    protected override readonly Q = 7681n;
    protected override readonly ROOT = 5685n;
    protected override readonly INV_N = this.modInverse(BigInt(this.N), this.Q);
}
