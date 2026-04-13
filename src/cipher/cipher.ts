/**
 * QuarkDash Ciphers Implementation
 *
 * @git             https://github.com/devsdaddy/quarkdash
 * @version         1.1.0
 * @author          Elijah Rastorguev
 * @build           1001
 * @website         https://dev.to/devsdaddy
 * @updated         13.04.2026
 */
/* Import Required Modules */
import {ICipher} from "../core/types";
import {QuarkDashUtils} from "../core/utils";

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

/**
 * ChaCha20 Based Cipher Implementation
 */
export class QuarkDashChaCha implements ICipher {
    // Key and Nonce
    private readonly key: Uint8Array;
    private readonly nonce: Uint8Array;

    /**
     * Create ChaCha20 Cipher
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
     * Encrypt data async using ChaCha20
     * @param data {Uint8Array} Raw data buffer
     * @returns {Promise<Uint8Array>} Result buffer
     * TODO: GPU Calculations
     */
    public async encrypt(data: Uint8Array): Promise<Uint8Array> { return this.process(data); }

    /**
     * Decrypt data async using ChaCha20
     * @param data {Uint8Array} Encrypted raw data buffer
     * @returns {Promise<Uint8Array>} Result buffer
     * TODO: GPU Calculations
     */
    public async decrypt(data: Uint8Array): Promise<Uint8Array> { return this.process(data); }

    /**
     * Encrypt data sync using ChaCha20
     * @param data {Uint8Array} Raw data buffer
     * @returns {Uint8Array} Result buffer
     */
    public encryptSync(data: Uint8Array): Uint8Array { return this.process(data); }

    /**
     * Decrypt data sync using ChaCha20
     * @param data {Uint8Array} Encrypted raw data buffer
     * @returns {Uint8Array} Result buffer
     */
    public decryptSync(data: Uint8Array): Uint8Array { return this.process(data); }

    /**
     * Process ChaCha20 Cipher
     * @param data {Uint8Array} Data for processing
     * @returns {Uint8Array} Processing result
     * @private
     */
    private process(data: Uint8Array): Uint8Array {
        const out = new Uint8Array(data.length);
        let block = 0;
        let pos = 0;
        while (pos < data.length) {
            const ks = this.keystreamBlock(block);
            const len = Math.min(64, data.length - pos);
            for (let i = 0; i < len; i++) out[pos+i] = data[pos+i] ^ ks[i];
            pos += len;
            block++;
        }
        return out;
    }

    /**
     * Get keystream block
     * @param counter {number} counter
     * @returns {Uint8Array} result buffer
     * @private
     */
    private keystreamBlock(counter: number): Uint8Array {
        const state = new Uint32Array(16);
        state[0]=0x61707865; state[1]=0x3320646e; state[2]=0x79622d32; state[3]=0x6b206574;
        for (let i=0;i<8;i++) state[4+i] = QuarkDashUtils.readU32(this.key, i*4);
        state[12] = counter;
        for (let i=0;i<3;i++) state[13+i] = QuarkDashUtils.readU32(this.nonce, i*4);
        const working = new Uint32Array(state);
        for (let r=0;r<10;r++) {
            this.quarterRound(working,0,4,8,12); this.quarterRound(working,1,5,9,13);
            this.quarterRound(working,2,6,10,14); this.quarterRound(working,3,7,11,15);
            this.quarterRound(working,0,5,10,15); this.quarterRound(working,1,6,11,12);
            this.quarterRound(working,2,7,8,13); this.quarterRound(working,3,4,9,14);
        }
        for(let i=0;i<16;i++) working[i] += state[i];
        const out = new Uint8Array(64);
        for(let i=0;i<16;i++) QuarkDashUtils.writeU32(working[i], out, i*4);
        return out;
    }

    /**
     * Quarter Round
     * @param s {Uint8Array} Buffer
     * @param a {number}
     * @param b {number}
     * @param c {number}
     * @param d {number}
     * @private
     */
    private quarterRound(s:Uint32Array, a:number,b:number,c:number,d:number){
        s[a] += s[b]; s[d] ^= s[a]; s[d] = (s[d]<<16)|(s[d]>>>16);
        s[c] += s[d]; s[b] ^= s[c]; s[b] = (s[b]<<12)|(s[b]>>>20);
        s[a] += s[b]; s[d] ^= s[a]; s[d] = (s[d]<<8)|(s[d]>>>24);
        s[c] += s[d]; s[b] ^= s[c]; s[b] = (s[b]<<7)|(s[b]>>>25);
    }
}

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