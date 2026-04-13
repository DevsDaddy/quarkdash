/**
 * QuarkDash SHA Implementations
 *
 * @git             https://github.com/devsdaddy/quarkdash
 * @version         1.1.0
 * @author          Elijah Rastorguev
 * @build           1001
 * @website         https://dev.to/devsdaddy
 * @updated         13.04.2026
 */
/**
 * SHA-256 Implementation
 */
export class SHA256 {
    // Constants
    private static readonly K: number[] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ];

    /**
     * Right Rotate
     * @param value {number} Value to rotate
     * @param amount {number} Rotate amount
     * @private
     */
    private static rightRotate(value: number, amount: number): number {
        return (value >>> amount) | (value << (32 - amount));
    }

    /**
     * Get SHA256 Hash
     * @param data {string|Uint8Array} Raw string or bytes array
     * @param returnBytes {boolean} Returns HEX String or Uint8Array
     * @returns {string|Uint8Array} HEX String or Uint8Array
     */
    static hash(data: string | Uint8Array, returnBytes : boolean = false): string | Uint8Array {
        const msgBytes = typeof data === 'string' ? new TextEncoder().encode(data) : data;

        // Initial hash values
        let h0 = 0x6a09e667;
        let h1 = 0xbb67ae85;
        let h2 = 0x3c6ef372;
        let h3 = 0xa54ff53a;
        let h4 = 0x510e527f;
        let h5 = 0x9b05688c;
        let h6 = 0x1f83d9ab;
        let h7 = 0x5be0cd19;

        // Pre-processing: padding
        const ml = msgBytes.length * 8;
        const padded = new Uint8Array(((ml + 64 + 511) & ~511) / 8);
        padded.set(msgBytes);
        padded[msgBytes.length] = 0x80;

        // Append length
        const dv = new DataView(padded.buffer);
        dv.setUint32(padded.length - 8, 0, false);
        dv.setUint32(padded.length - 4, ml, false);

        // Process chunks
        for (let i = 0; i < padded.length; i += 64) {
            const w = new Array(64).fill(0);

            // Prepare message schedule
            for (let j = 0; j < 16; j++) {
                w[j] = dv.getUint32(i + j * 4, false);
            }

            for (let j = 16; j < 64; j++) {
                const s0 = this.rightRotate(w[j - 15], 7) ^ this.rightRotate(w[j - 15], 18) ^ (w[j - 15] >>> 3);
                const s1 = this.rightRotate(w[j - 2], 17) ^ this.rightRotate(w[j - 2], 19) ^ (w[j - 2] >>> 10);
                w[j] = (w[j - 16] + s0 + w[j - 7] + s1) >>> 0;
            }

            // Initialize working variables
            let a = h0;
            let b = h1;
            let c = h2;
            let d = h3;
            let e = h4;
            let f = h5;
            let g = h6;
            let h = h7;

            // Main loop
            for (let j = 0; j < 64; j++) {
                const S1 = this.rightRotate(e, 6) ^ this.rightRotate(e, 11) ^ this.rightRotate(e, 25);
                const ch = (e & f) ^ ((~e) & g);
                const temp1 = (h + S1 + ch + this.K[j] + w[j]) >>> 0;
                const S0 = this.rightRotate(a, 2) ^ this.rightRotate(a, 13) ^ this.rightRotate(a, 22);
                const maj = (a & b) ^ (a & c) ^ (b & c);
                const temp2 = (S0 + maj) >>> 0;

                h = g;
                g = f;
                f = e;
                e = (d + temp1) >>> 0;
                d = c;
                c = b;
                b = a;
                a = (temp1 + temp2) >>> 0;
            }

            // Update hash values
            h0 = (h0 + a) >>> 0;
            h1 = (h1 + b) >>> 0;
            h2 = (h2 + c) >>> 0;
            h3 = (h3 + d) >>> 0;
            h4 = (h4 + e) >>> 0;
            h5 = (h5 + f) >>> 0;
            h6 = (h6 + g) >>> 0;
            h7 = (h7 + h) >>> 0;
        }

        // Produce final hash
        const result = new Uint8Array(32);
        const resultView = new DataView(result.buffer);
        resultView.setUint32(0, h0, false);
        resultView.setUint32(4, h1, false);
        resultView.setUint32(8, h2, false);
        resultView.setUint32(12, h3, false);
        resultView.setUint32(16, h4, false);
        resultView.setUint32(20, h5, false);
        resultView.setUint32(24, h6, false);
        resultView.setUint32(28, h7, false);

        return (returnBytes) ? result as Uint8Array : Array.from(result).map(b => b.toString(16).padStart(2, '0')).join('') as string;
    }
}

/**
 * SHA-512 Implementation
 */
export class SHA512 {
    // Constants
    private static readonly K: bigint[] = [
        0x428a2f98d728ae22n, 0x7137449123ef65cdn, 0xb5c0fbcfec4d3b2fn, 0xe9b5dba58189dbbcn,
        0x3956c25bf348b538n, 0x59f111f1b605d019n, 0x923f82a4af194f9bn, 0xab1c5ed5da6d8118n,
        0xd807aa98a3030242n, 0x12835b0145706fben, 0x243185be4ee4b28cn, 0x550c7dc3d5ffb4e2n,
        0x72be5d74f27b896fn, 0x80deb1fe3b1696b1n, 0x9bdc06a725c71235n, 0xc19bf174cf692694n,
        0xe49b69c19ef14ad2n, 0xefbe4786384f25e3n, 0x0fc19dc68b8cd5b5n, 0x240ca1cc77ac9c65n,
        0x2de92c6f592b0275n, 0x4a7484aa6ea6e483n, 0x5cb0a9dcbd41fbd4n, 0x76f988da831153b5n,
        0x983e5152ee66dfabn, 0xa831c66d2db43210n, 0xb00327c898fb213fn, 0xbf597fc7beef0ee4n,
        0xc6e00bf33da88fc2n, 0xd5a79147930aa725n, 0x06ca6351e003826fn, 0x142929670a0e6e70n,
        0x27b70a8546d22ffcn, 0x2e1b21385c26c926n, 0x4d2c6dfc5ac42aedn, 0x53380d139d95b3dfn,
        0x650a73548baf63den, 0x766a0abb3c77b2a8n, 0x81c2c92e47edaee6n, 0x92722c851482353bn,
        0xa2bfe8a14cf10364n, 0xa81a664bbc423001n, 0xc24b8b70d0f89791n, 0xc76c51a30654be30n,
        0xd192e819d6ef5218n, 0xd69906245565a910n, 0xf40e35855771202an, 0x106aa07032bbd1b8n,
        0x19a4c116b8d2d0c8n, 0x1e376c085141ab53n, 0x2748774cdf8eeb99n, 0x34b0bcb5e19b48a8n,
        0x391c0cb3c5c95a63n, 0x4ed8aa4ae3418acbn, 0x5b9cca4f7763e373n, 0x682e6ff3d6b2b8a3n,
        0x748f82ee5defb2fcn, 0x78a5636f43172f60n, 0x84c87814a1f0ab72n, 0x8cc702081a6439ecn,
        0x90befffa23631e28n, 0xa4506cebde82bde9n, 0xbef9a3f7b2c67915n, 0xc67178f2e372532bn,
        0xca273eceea26619cn, 0xd186b8c721c0c207n, 0xeada7dd6cde0eb1en, 0xf57d4f7fee6ed178n,
        0x06f067aa72176fban, 0x0a637dc5a2c898a6n, 0x113f9804bef90daen, 0x1b710b35131c471bn,
        0x28db77f523047d84n, 0x32caab7b40c72493n, 0x3c9ebe0a15c9bebcn, 0x431d67c49c100d4cn,
        0x4cc5d4becb3e42b6n, 0x597f299cfc657e2an, 0x5fcb6fab3ad6faecn, 0x6c44198c4a475817n
    ];

    /**
     * Bitint right rotate
     * @param value {number} Value
     * @param amount {number} Rotate amount
     * @private
     */
    private static rightRotate(value: bigint, amount: number): bigint {
        return (value >> BigInt(amount)) | (value << (64n - BigInt(amount)));
    }

    /**
     * Get SHA512 Hash
     * @param data {string|Uint8Array} Raw string or bytes array
     * @param returnBytes {boolean} Returns HEX String or Uint8Array
     * @returns {string|Uint8Array} HEX String or Uint8Array
     */
    static hash(data: string | Uint8Array, returnBytes : boolean = false): string | Uint8Array {
        const msgBytes = typeof data === "string" ? new TextEncoder().encode(data) : data;

        // Initial hash values
        let h0 = 0x6a09e667f3bcc908n;
        let h1 = 0xbb67ae8584caa73bn;
        let h2 = 0x3c6ef372fe94f82bn;
        let h3 = 0xa54ff53a5f1d36f1n;
        let h4 = 0x510e527fade682d1n;
        let h5 = 0x9b05688c2b3e6c1fn;
        let h6 = 0x1f83d9abfb41bd6bn;
        let h7 = 0x5be0cd19137e2179n;

        const ml = BigInt(msgBytes.length * 8);
        const padded = new Uint8Array((((Number(ml) + 128 + 1023) & ~1023) / 8));
        padded.set(msgBytes);
        padded[msgBytes.length] = 0x80;

        const dv = new DataView(padded.buffer);
        dv.setBigUint64(padded.length - 8, ml, false);

        for (let i = 0; i < padded.length; i += 128) {
            const w = new Array(80).fill(0n);

            for (let j = 0; j < 16; j++) {
                w[j] = dv.getBigUint64(i + j * 8, false);
            }

            for (let j = 16; j < 80; j++) {
                const s0 = this.rightRotate(w[j - 15], 1) ^ this.rightRotate(w[j - 15], 8) ^ (w[j - 15] >> 7n);
                const s1 = this.rightRotate(w[j - 2], 19) ^ this.rightRotate(w[j - 2], 61) ^ (w[j - 2] >> 6n);
                w[j] = (w[j - 16] + s0 + w[j - 7] + s1) & 0xffffffffffffffffn;
            }

            let a = h0;
            let b = h1;
            let c = h2;
            let d = h3;
            let e = h4;
            let f = h5;
            let g = h6;
            let h = h7;

            for (let j = 0; j < 80; j++) {
                const S1 = this.rightRotate(e, 14) ^ this.rightRotate(e, 18) ^ this.rightRotate(e, 41);
                const ch = (e & f) ^ ((~e) & g);
                const temp1 = (h + S1 + ch + this.K[j] + w[j]) & 0xffffffffffffffffn;
                const S0 = this.rightRotate(a, 28) ^ this.rightRotate(a, 34) ^ this.rightRotate(a, 39);
                const maj = (a & b) ^ (a & c) ^ (b & c);
                const temp2 = (S0 + maj) & 0xffffffffffffffffn;

                h = g;
                g = f;
                f = e;
                e = (d + temp1) & 0xffffffffffffffffn;
                d = c;
                c = b;
                b = a;
                a = (temp1 + temp2) & 0xffffffffffffffffn;
            }

            h0 = (h0 + a) & 0xffffffffffffffffn;
            h1 = (h1 + b) & 0xffffffffffffffffn;
            h2 = (h2 + c) & 0xffffffffffffffffn;
            h3 = (h3 + d) & 0xffffffffffffffffn;
            h4 = (h4 + e) & 0xffffffffffffffffn;
            h5 = (h5 + f) & 0xffffffffffffffffn;
            h6 = (h6 + g) & 0xffffffffffffffffn;
            h7 = (h7 + h) & 0xffffffffffffffffn;
        }

        const result = new Uint8Array(64);
        const resultView = new DataView(result.buffer);
        resultView.setBigUint64(0, h0, false);
        resultView.setBigUint64(8, h1, false);
        resultView.setBigUint64(16, h2, false);
        resultView.setBigUint64(24, h3, false);
        resultView.setBigUint64(32, h4, false);
        resultView.setBigUint64(40, h5, false);
        resultView.setBigUint64(48, h6, false);
        resultView.setBigUint64(56, h7, false);

        return (returnBytes) ? result as Uint8Array : Array.from(result).map(b => b.toString(16).padStart(2, '0')).join('') as string;
    }
}