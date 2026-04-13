/**
 * QuarkDash Radical Ring-LWE Implementation
 *
 * @git             https://github.com/devsdaddy/quarkdash
 * @version         1.1.0
 * @author          Elijah Rastorguev
 * @build           1002
 * @website         https://dev.to/devsdaddy
 * @updated         13.04.2026
 */
/* Import required modules */
import {ICryptoEncapsulated, ICryptoKeyPair, IKeyExchange} from "../core/types";
import {QuarkDashUtils} from "../core/utils";
import {SHA256} from "../hash/sha";
import {BaseRingLWE} from "./baselwe";

/**
 * QuarkDash Radical Ring-LWE Implementation
 */
export class QuarkDashRRLWE extends BaseRingLWE implements IKeyExchange {
    // General Constants
    protected override readonly N = 256;
    protected override readonly Q = 12289n;
    protected override readonly ROOT = 7n;
    protected override readonly INV_N = this.modInverse(BigInt(this.N), this.Q);

    /**
     * Override small polynome for Radical Ring-lWE
     * @returns {bigint[]} Small polynome
     * @protected
     */
    protected override smallPoly(): bigint[] {
        const poly = new Array<bigint>(this.N);
        const bytesNeeded = Math.ceil(this.N * 2 / 8);
        const randomBytes = QuarkDashUtils.randomBytes(bytesNeeded);
        for (let i = 0; i < this.N; i++) {
            const byteIdx = Math.floor(i * 2 / 8);
            const bitShift = (i * 2) % 8;
            const val = (randomBytes[byteIdx] >> bitShift) & 0x03;
            if (val === 0) poly[i] = -1n;
            else if (val === 1) poly[i] = 0n;
            else poly[i] = 1n;
        }
        return poly;
    }
}