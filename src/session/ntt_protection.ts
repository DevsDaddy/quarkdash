/**
 * QuarkDash Protocol NTT Protection by time / errors
 *
 * NTT is a heart of Ring LWE. They can be listened by time
 * or broke by bug.
 *
 * When, I add more layers to protection:
 * - blinding - multiply first polynome by random r, second by r^{-1}, multiplication result doesn't change
 * - doubleChek - calculate two times and equal (catch fault-injection)
 * - validateInputs - check for length, range - and catch trash
 * - constantTime - single-length cycles without early exit
 *
 * @git             https://github.com/devsdaddy/quarkdash
 * @version         1.2.0
 * @author          Elijah Rastorguev
 * @build           1023
 * @website         https://dev.to/devsdaddy
 * @updated         22.08.2026
 */
/**
 * NTT Protection Options
 */
export interface NTTProtectionOptions {
    enabled: boolean;               // Enable protection
    blinding: boolean;              // random blinding factor
    doubleCheck: boolean;           // double check is enabled
    constantTime: boolean;          // constant-time cycles (TODO: make it as dynamic length)
    validateInputs: boolean;        // Validate polynomes
}

/**
 * Default NTT Protection Rules
 */
export const DEFAULT_NTT_PROTECTION: NTTProtectionOptions = {
    enabled: true,
    blinding: true,
    doubleCheck: true,
    constantTime: true,
    validateInputs: true,
};
