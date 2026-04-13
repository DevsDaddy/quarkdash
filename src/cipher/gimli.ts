/**
 * QuarkDash Gimli Implementation
 *
 * @git             https://github.com/devsdaddy/quarkdash
 * @version         1.1.0
 * @author          Elijah Rastorguev
 * @build           1002
 * @website         https://dev.to/devsdaddy
 * @updated         13.04.2026
 */
import {QuarkDashUtils} from "../core/utils";
import {ICipher} from "../core/types";

/**
 * Gimli Cipher
 */
export class QuarkDashGimli implements ICipher {
    // Key and Nonce
    private readonly key: Uint8Array;
    private readonly nonce: Uint8Array;

    /**
     * Create Gimli Cipher
     * @param key {Uint8Array} Key buffer
     * @param nonce {Uint8Array} Nonce buffer
     */
    constructor(key: Uint8Array, nonce: Uint8Array) {
        if (key.length !== 32) throw new Error('Key must be 32 bytes');
        if (nonce.length !== 12) throw new Error('Nonce must be 12 bytes');
        this.key = key;
        this.nonce = nonce;
    }

    /**
     * Encrypt data async using Gimli
     * @param data {Uint8Array} Raw data buffer
     * @returns {Promise<Uint8Array>} Result buffer
     * TODO: GPU Calculations
     */
    public async encrypt(data: Uint8Array): Promise<Uint8Array> { return this.process(data); }

    /**
     * Decrypt data async using Gimli
     * @param data {Uint8Array} Encrypted raw data buffer
     * @returns {Promise<Uint8Array>} Result buffer
     * TODO: GPU Calculations
     */
    public async decrypt(data: Uint8Array): Promise<Uint8Array> { return this.process(data); }

    /**
     * Encrypt data sync using Gimli
     * @param data {Uint8Array} Raw data buffer
     * @returns {Uint8Array} Result buffer
     */
    public encryptSync(data: Uint8Array): Uint8Array { return this.process(data); }

    /**
     * Decrypt data sync using Gimli
     * @param data {Uint8Array} Encrypted raw data buffer
     * @returns {Uint8Array} Result buffer
     */
    public decryptSync(data: Uint8Array): Uint8Array { return this.process(data); }

    /**
     * Process Gimli Cipher
     * @param data {Uint8Array} Input buffer
     * @returns {Uint8Array} Output buffer
     * @private
     */
    private process(data: Uint8Array): Uint8Array {
        const out = new Uint8Array(data.length);
        let block = 0;
        let pos = 0;
        while (pos < data.length) {
            const ks = this.keystreamBlock(block);
            const len = Math.min(48, data.length - pos);
            for (let i = 0; i < len; i++) out[pos+i] = data[pos+i] ^ ks[i];
            pos += len;
            block++;
        }
        return out;
    }

    /**
     * Get keystream block
     * @param counter {number} Counter
     * @returns {Uint8Array} Result buffer
     * @private
     */
    private keystreamBlock(counter: number): Uint8Array {
        const state = new Uint32Array(12);
        for (let i=0;i<8;i++) state[i] = QuarkDashUtils.readU32(this.key, i*4);
        state[8] = QuarkDashUtils.readU32(this.nonce,0);
        state[9] = QuarkDashUtils.readU32(this.nonce,4);
        state[10] = QuarkDashUtils.readU32(this.nonce,8);
        state[11] = counter;
        for (let r=0;r<24;r++) this.gimliRound(state, r);
        const out = new Uint8Array(48);
        for(let i=0;i<12;i++) QuarkDashUtils.writeU32(state[i], out, i*4);
        return out;
    }

    /**
     * Gimli Round
     * @param state {Uint32Array} State buffer
     * @param round {number} Round number
     * @private
     */
    private gimliRound(state:Uint32Array, round:number){
        for(let i=0;i<4;i++){
            const x=state[i], y=state[i+4], z=state[i+8];
            const newX = x ^ (z<<1) ^ ((y&z)<<2);
            const newY = y ^ x ^ ((x|z)<<1);
            const newZ = z ^ y ^ ((x&y)<<3);
            state[i]=newX; state[i+4]=newY; state[i+8]=newZ;
        }
        const t=state[1]; state[1]=state[2]; state[2]=state[3]; state[3]=t;
        if((round&3)===0) state[0] ^= (0x9e377900 | round);
    }
}