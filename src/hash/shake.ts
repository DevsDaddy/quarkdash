/**
 * QuarkDash Crypto SHAKE-256 Implementation
 *
 * @git             https://github.com/devsdaddy/quarkdash
 * @version         1.1.0
 * @author          Elijah Rastorguev
 * @build           1001
 * @website         https://dev.to/devsdaddy
 * @updated         13.04.2026
 */
/**
 * Shake-256 Hash
 */
export class Shake256 {
    /* Shake 256 Constants */
    private static KECCAK_ROUNDS = 24;
    private static RATE_BYTES = 136;
    private static ROTATIONS: number[] = [
        1,  3,  6,  10, 15, 21, 28, 36, 45, 55, 2,  14,
        27, 41, 56, 8,  25, 43, 62, 18, 39, 61, 20, 44
    ];
    private static RC: bigint[] = [
        0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an, 0x8000000080008000n,
        0x000000000000808bn, 0x0000000080000001n, 0x8000000080008081n, 0x8000000000008009n,
        0x000000000000008an, 0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
        0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n,
        0x8000000000008002n, 0x8000000000000080n, 0x000000000000800an, 0x800000008000000an,
        0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n
    ];

    /**
     * Shake-256 async
     * @param input {Uint8Array} Input buffer
     * @param outputLength {number} Output buffer length
     * @returns {Uint8Array} Output buffer
     */
    public static async hash(input: Uint8Array, outputLength: number): Promise<Uint8Array> {
        return this.process(input, outputLength);
    }

    /**
     * Shake-256 sync
     * @param input {Uint8Array} Input buffer
     * @param outputLength {number} Output buffer length
     * @returns {Uint8Array} Output buffer
     */
    public static hashSync(input: Uint8Array, outputLength: number): Uint8Array {
        return this.process(input, outputLength);
    }

    /**
     * Process SHAKE-256
     * @param input {Uint8Array} Input buffer
     * @param outputLength {number} Output length
     * @returns {Uint8Array} Output buffer
     * @private
     */
    private static process(input: Uint8Array, outputLength: number): Uint8Array {
        const state = new Array(25).fill(0n);
        // Absorb phase
        let offset = 0;
        let blockSize = this.RATE_BYTES;
        while (offset < input.length) {
            const block = input.subarray(offset, Math.min(offset + blockSize, input.length));
            for (let i = 0; i < block.length; i++) {
                const lane = i % 8;
                const bytePos = i - lane;
                const laneIdx = bytePos / 8;
                const shift = BigInt(lane * 8);
                const val = BigInt(block[i]) << shift;
                state[laneIdx] ^= val;
            }
            offset += block.length;
            if (block.length === blockSize || offset >= input.length) {
                // padding
                if (offset >= input.length) {
                    const lastByteIdx = block.length;
                    const padByte = 0x1F; // domain for SHAKE256
                    const laneIdx = Math.floor(lastByteIdx / 8);
                    const shift = BigInt((lastByteIdx % 8) * 8);
                    state[laneIdx] ^= (BigInt(padByte) << shift);
                    // final padding bit
                    const finalBytePos = lastByteIdx + 1;
                    const finalLane = Math.floor(finalBytePos / 8);
                    const finalShift = BigInt((finalBytePos % 8) * 8);
                    state[finalLane] ^= (0x80n << finalShift);
                }
                this.keccakF(state);
            }
        }

        // Squeeze phase
        const result = new Uint8Array(outputLength);
        let outOffset = 0;
        while (outOffset < outputLength) {
            for (let lane = 0; lane < 25 && outOffset < outputLength; lane++) {
                let val = state[lane];
                for (let byte = 0; byte < 8 && outOffset < outputLength; byte++) {
                    result[outOffset++] = Number(val & 0xFFn);
                    val >>= 8n;
                }
            }
            if (outOffset < outputLength) {
                this.keccakF(state);
            }
        }
        return result;
    }

    /**
     * Keccak Function
     * @param state {bigint[]} State array
     * @private
     */
    private static keccakF(state: bigint[]): void {
        for (let round = 0; round < this.KECCAK_ROUNDS; round++) {
            // Theta
            const C = new Array(5);
            for (let x = 0; x < 5; x++) {
                C[x] = state[x] ^ state[x+5] ^ state[x+10] ^ state[x+15] ^ state[x+20];
            }
            const D = new Array(5);
            for (let x = 0; x < 5; x++) {
                D[x] = C[(x+4)%5] ^ this.rot(C[(x+1)%5], 1n);
            }
            for (let x = 0; x < 5; x++) {
                for (let y = 0; y < 5; y++) {
                    state[x+5*y] ^= D[x];
                }
            }

            // Rho and Pi
            let current = state[1];
            for (let i = 0; i < 24; i++) {
                const nextIdx = (2 * ((i + 1) % 5) + 5*Math.floor((i+1)/5)) % 25;
                const temp = state[nextIdx];
                state[nextIdx] = this.rot(current, BigInt(this.ROTATIONS[i]));
                current = temp;
            }

            // Chi
            for (let y = 0; y < 5; y++) {
                const row = state.slice(y*5, y*5+5);
                for (let x = 0; x < 5; x++) {
                    state[y*5 + x] = row[x] ^ ((~row[(x+1)%5]) & row[(x+2)%5]);
                }
            }

            // Iota
            state[0] ^= this.RC[round];
        }
    }

    /**
     * Rotate function
     * @param x {number}
     * @param n {number}
     * @private
     */
    private static rot(x: bigint, n: bigint): bigint {
        const mask = (1n << 64n) - 1n;
        return ((x << n) | (x >> (64n - n))) & mask;
    }
}