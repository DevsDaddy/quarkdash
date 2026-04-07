/**
 * QuarkDash Crypto Utils
 *
 * @git             https://github.com/devsdaddy/quarkdash
 * @version         1.0.0
 * @author          Elijah Rastorguev
 * @build           1000
 * @website         https://dev.to/devsdaddy
 */
import crypto from "crypto";
import {Shake256} from "./shake";

/**
 * Crypto Utils Class
 */
export class QuarkDashUtils {
    // Protected Constants
    private static HEXChars : string = '0123456789abcdef';

    /**
     * Get Shake-256 result async
     * @param data {Uint8Array} Bytes buffer
     * @param len {number} Buffer length
     * @return {Promise<Uint8Array>} Result buffer
     */
    public static async shake256(data: Uint8Array, len: number): Promise<Uint8Array> {
        return await Shake256.hash(data, len);
    }

    /**
     * Get Shake-256 result sync
     * @param data {Uint8Array} Bytes buffer
     * @param len {number} Buffer length
     * @return {Uint8Array} Result buffer
     */
    public static shake256Sync(data: Uint8Array, len: number): Uint8Array {
        return Shake256.hashSync(data, len);
    }

    /**
     * Concat bytes
     * @param arrays {Uint8Array|null|undefined} Input arrays for concat
     * @returns {Uint8Array} Result buffer
     */
    public static concatBytes(...arrays: (Uint8Array|null|undefined)[]): Uint8Array {
        const valid = arrays.filter(a => a != null) as Uint8Array[];
        const total = valid.reduce((s, a) => s + a.length, 0);
        const res = new Uint8Array(total);
        let pos = 0;
        for (const a of valid) {
            res.set(a, pos);
            pos += a.length;
        }
        return res;
    }

    /**
     * Coerce Array
     * @param arg {any} Argument
     * @param copy {any} Copy
     * @protected
     */
    public static coerceArray(arg : any, copy ? : any) : any {
        let self = this

        // ArrayBuffer view
        if (arg.buffer && arg.name === 'Uint8Array') {
            if (copy) {
                if (arg.slice) {
                    arg = arg.slice()
                } else {
                    arg = Array.prototype.slice.call(arg)
                }
            }

            return arg
        }

        // It's an array; check it is a valid representation of a byte
        if (Array.isArray(arg)) {
            if (!self.checkInts(arg)) {
                throw new Error('Array contains invalid value: ' + arg)
            }

            return new Uint8Array(arg)
        }

        // Something else, but behaves like an array (maybe a Buffer? Arguments?)
        if (self.checkInt(arg.length) && self.checkInts(arg)) {
            return new Uint8Array(arg)
        }

        throw new Error('unsupported array-like object')
    }

    /**
     * Check if value is int
     * @param value {any} Value
     * @returns {boolean}
     * @protected
     */
    public static checkInt(value: any) : boolean {
        return parseInt(value) === value
    }

    /**
     * Check Ints inside array
     * @param arrayish {any} Array
     * @returns {boolean} Any value is integer and between 0 and 255
     * @protected
     */
    public static checkInts(arrayish : any) : boolean {
        let self = this
        if (!self.checkInt(arrayish.length)) {
            return false
        }

        for (let i = 0; i < arrayish.length; i++) {
            if (!self.checkInt(arrayish[i]) || arrayish[i] < 0 || arrayish[i] > 255) {
                return false
            }
        }

        return true
    }

    /**
     * Get random bytes
     * @param len {number} buffer length
     * @returns {Uint8Array} Random bytes buffer
     */
    public static randomBytes(len: number): Uint8Array {
        return crypto.getRandomValues(new Uint8Array(len));
    }

    /**
     * Convert raw text to bytes array
     * @param text {string} raw string
     * @returns {any} bytes array
     */
    public static textToBytes(text : string) : any {
        let self = this
        let result = [],
            i = 0
        text = encodeURI(text)
        while (i < text.length) {
            let c = text.charCodeAt(i++)

            // if it is a % sign, encode the following 2 bytes as a hex value
            if (c === 37) {
                result.push(parseInt(text.substr(i, 2), 16))
                i += 2

                // otherwise, just the actual byte
            } else {
                result.push(c)
            }
        }

        return self.coerceArray(result)
    }

    /**
     * Convert bytes array to raw string
     * @param bytes {number[]|Uint8Array} Bytes array
     * @returns {string} raw string
     */
    public static bytesToText(bytes : number[] | Uint8Array) : string {
        return new TextDecoder().decode(bytes as Uint8Array);

        let result = [],
            i = 0

        while (i < bytes.length) {
            let c = bytes[i]

            if (c < 128) {
                result.push(String.fromCharCode(c))
                i++
            } else if (c > 191 && c < 224) {
                result.push(String.fromCharCode(((c & 0x1f) << 6) | (bytes[i + 1] & 0x3f)))
                i += 2
            } else {
                result.push(
                    String.fromCharCode(
                        ((c & 0x0f) << 12) | ((bytes[i + 1] & 0x3f) << 6) | (bytes[i + 2] & 0x3f),
                    ),
                )
                i += 3
            }
        }

        return result.join('')
    }

    /**
     * Convert HEX string to bytes array
     * @param text {string} HEX string
     * @returns {number[]} bytes array
     * @constructor
     */
    public static HEXToBytes(text : string) : number[] {
        let result = []
        for (let i = 0; i < text.length; i += 2) {
            result.push(parseInt(text.substr(i, 2), 16))
        }

        return result
    }

    /**
     * Convert bytes array to HEX string
     * @param bytes {number[]|Uint8Array} Bytes array
     * @returns {string} HEX String
     */
    public static bytesToHEX(bytes : number[] | Uint8Array) : string {
        let self = this
        let result = []
        for (let i = 0; i < bytes.length; i++) {
            let v = bytes[i]
            result.push(self.HEXChars[(v & 0xf0) >> 4] + self.HEXChars[v & 0x0f])
        }
        return result.join('')
    }

    /**
     * Constant time equal
     * @param a {Uint8Array} first buffer
     * @param b {Uint8Array} second buffer
     * @returns {boolean} Equal or not
     */
    public static constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
        if (a.length !== b.length) return false;
        let diff = 0;
        for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
        return diff === 0;
    }

    /**
     * Secure zero
     * @param bytes {Uint8Array} bytes buffer
     */
    public static secureZero(bytes: Uint8Array): void {
        for (let i = 0; i < bytes.length; i++) bytes[i] = 0;
    }

    /**
     * Read U32 from buffer
     * @param arr {Uint8Array} buffer
     * @param off {number} Offset
     * @returns {number} U32
     * @private
     */
    public static readU32(arr:Uint8Array, off:number): number {
        return (arr[off]|(arr[off+1]<<8)|(arr[off+2]<<16)|(arr[off+3]<<24))>>>0;
    }

    /**
     * Write U32 to buffer
     * @param v {number} U32
     * @param arr {Uint8Array} Target buffer
     * @param off {number} Offset
     * @private
     */
    public static writeU32(v:number, arr:Uint8Array, off:number){
        arr[off]=v&0xFF; arr[off+1]=(v>>8)&0xFF; arr[off+2]=(v>>16)&0xFF; arr[off+3]=(v>>24)&0xFF;
    }

    /**
     * Read Uint32 Value
     * @param arr {Uint8Array} Bytes buffer
     * @param off {number} Offset
     * @returns {number} Uint32 Value
     */
    public static readUint32(arr: Uint8Array, off: number): number {
        return (arr[off] | (arr[off+1]<<8) | (arr[off+2]<<16) | (arr[off+3]<<24)) >>> 0;
    }

    /**
     * Read Uint64 Value
     * @param arr {Uint8Array} Bytes buffer
     * @param off {number} offset
     * @returns {bigint} Bigint
     */
    public static readUint64(arr: Uint8Array, off: number): bigint {
        let v = 0n;
        for (let i = 0; i < 8; i++) v |= BigInt(arr[off+i]) << BigInt(i*8);
        return v;
    }
}