/**
 * QuarkDash Crypto Algorithm Implementation
 *
 * @git             https://github.com/devsdaddy/quarkdash
 * @version         1.0.0
 * @author          Elijah Rastorguev
 * @build           1105
 * @website         https://dev.to/devsdaddy
 * @updated         14.04.2026
 */
/* Import Required Modules */
import {CipherFactory, CipherType} from "./cipher/cipher";
import {ICipher, ICryptoMethodAsync, ICryptoMethodSync, IKDF, IKeyExchange, IMAC} from "./core/types";
import {QuarkDashKDF} from "./core/kdf";
import {QuarkDashMAC} from "./core/mac";
import {QuarkDashUtils} from "./core/utils";
import {QuarkDashRRLWE} from "./session/rringlwe";
import {isWasmShake, Shake256Wasm} from "./hash/shake";

/**
 * Quark Dash parsed encrypted packet
 */
export interface QDEncryptedPacket {
    metadata: Uint8Array;
    encrypted: Uint8Array;
    mac: Uint8Array;
}

/**
 * QuarkDash options
 */
export interface QuarkDashOptions {
    cipher: CipherType;
    kdf: IKDF;
    mac: IMAC;
    keyExchange: IKeyExchange;
    maxPacketWindow: number;
    timestampToleranceMs: number;
    WASM : {
        isEnabled: boolean;
        shakePath: string;
    }
}

/**
 * Default QuarkDash options
 */
const DEFAULT_OPTIONS : QuarkDashOptions = {
    cipher: CipherType.ChaCha20,
    kdf: new QuarkDashKDF(),
    mac: new QuarkDashMAC(),
    keyExchange: new QuarkDashRRLWE(),
    maxPacketWindow: 1000,
    timestampToleranceMs: 300000,
    WASM: {
        isEnabled: true,
        shakePath: "./wasm/shake.wasm",
    }
}

/**
 * QuarkDash Crypto Algorithm Implementation
 */
export class QuarkDash implements ICryptoMethodAsync, ICryptoMethodSync {
    private config: QuarkDashOptions;
    private sessionKey: Uint8Array | null = null;
    private cipher: ICipher | null = null;
    private macKey: Uint8Array | null = null;
    private sendSeq = 0;
    private receivedPackets = new Set<number>();
    private myKeyPair?: { publicKey: Uint8Array; privateKey: Uint8Array };
    private peerPublicKey?: Uint8Array;

    /**
     * Create QuarkDash Crypto
     * @param config {QuarkDashOptions} Crypto Options
     */
    constructor(config?: Partial<QuarkDashOptions>) {
        this.config = { ...DEFAULT_OPTIONS, ...config };
    }

    /**
     * Generate key pair async
     * @returns {Promise<Uint8Array>} Key pair buffer
     * TODO: GPU Computing
     */
    public async generateKeyPair(): Promise<Uint8Array> {
        // Initialize WASM Modules at first time
        if(this.config.WASM.isEnabled && !isWasmShake()) await Shake256Wasm.initWasm(this.config.WASM.shakePath);

        // Generate key pair
        this.myKeyPair = await this.config.keyExchange.generateKeyPair();
        return this.myKeyPair.publicKey;
    }

    /**
     * Generate key pair sync
     * @returns {Uint8Array} Key pair buffer
     */
    public generateKeyPairSync(): Uint8Array {
        this.myKeyPair = this.config.keyExchange.generateKeyPairSync();
        return this.myKeyPair.publicKey;
    }

    /**
     * Initialize session async
     * @param peerPublicKey {Uint8Array} Peer public key buffer
     * @param isInitiator {boolean} Is session initiator
     * @returns {Promise<Uint8Array|number>} Returns derived session key or null
     * TODO: GPU Computing
     */
    public async initializeSession(peerPublicKey: Uint8Array, isInitiator: boolean): Promise<Uint8Array | null> {
        this.peerPublicKey = peerPublicKey;
        if (!this.myKeyPair) await this.generateKeyPair();
        if (isInitiator) {
            const { ciphertext, sharedSecret } = await this.config.keyExchange.encapsulate(peerPublicKey);
            await this.deriveSessionKeys(sharedSecret);
            return ciphertext;
        } else {
            return null;
        }
    }

    /**
     * Initialize session sync
     * @param peerPublicKey {Uint8Array} Peer public key buffer
     * @param isInitiator {boolean} Is session initiator
     * @returns {Uint8Array|number} Returns derived session key or null
     */
    public initializeSessionSync(peerPublicKey: Uint8Array, isInitiator: boolean): Uint8Array | null {
        this.peerPublicKey = peerPublicKey;
        if (!this.myKeyPair) this.generateKeyPairSync();
        if (isInitiator) {
            const { ciphertext, sharedSecret } = this.config.keyExchange.encapsulateSync(peerPublicKey);
            this.deriveSessionKeysSync(sharedSecret);
            return ciphertext;
        } else {
            return null;
        }
    }

    /**
     * Finalize session async
     * @param ciphertext {Uint8Array} Cipher text buffer
     * TODO: GPU Computing
     */
    public async finalizeSession(ciphertext: Uint8Array): Promise<void> {
        if (!this.myKeyPair || !this.peerPublicKey) throw new Error('Session not initialized');
        const sharedSecret = await this.config.keyExchange.decapsulate(this.myKeyPair.privateKey, this.peerPublicKey, ciphertext);
        await this.deriveSessionKeys(sharedSecret);
    }

    /**
     * Finalize session sync
     * @param ciphertext {Uint8Array} Cipher text buffer
     */
    public finalizeSessionSync(ciphertext: Uint8Array): void {
        if (!this.myKeyPair || !this.peerPublicKey) throw new Error('Session not initialized');
        const sharedSecret = this.config.keyExchange.decapsulateSync(this.myKeyPair.privateKey, this.peerPublicKey, ciphertext);
        this.deriveSessionKeysSync(sharedSecret);
    }

    /**
     * Derive session keys async
     * @param sharedSecret {Uint8Array} Shared secret buffer
     * @private
     * TODO: GPU Computing
     */
    private async deriveSessionKeys(sharedSecret: Uint8Array): Promise<void> {
        const salt = QuarkDashUtils.randomBytes(32);
        const info = QuarkDashUtils.textToBytes('session-key');
        const keyMaterial = await this.config.kdf.derive(sharedSecret, salt, info, 64);
        this.processDeriveSessionKeys(keyMaterial, sharedSecret);
    }

    /**
     * Derive session keys sync
     * @param sharedSecret {Uint8Array} Shared secret buffer
     * @private
     */
    private deriveSessionKeysSync(sharedSecret: Uint8Array): void {
        const salt = QuarkDashUtils.randomBytes(32);
        const info = QuarkDashUtils.textToBytes('session-key');
        const keyMaterial = this.config.kdf.deriveSync(sharedSecret, salt, info, 64);
        this.processDeriveSessionKeys(keyMaterial, sharedSecret);
    }

    /**
     * Process derive session keys
     * @param keyMaterial {Uint8Array} Key material buffer
     * @param sharedSecret {Uint8Array} Shared secret buffer
     * @private
     */
    private processDeriveSessionKeys(keyMaterial : Uint8Array, sharedSecret: Uint8Array){
        this.sessionKey = keyMaterial.slice(0, 32);
        this.macKey = keyMaterial.slice(32, 64);
        const nonce = new Uint8Array(12);
        this.cipher = CipherFactory.create(this.config.cipher, this.sessionKey, nonce);
        QuarkDashUtils.secureZero(sharedSecret);
        QuarkDashUtils.secureZero(keyMaterial);
    }

    /**
     * Encrypt sync
     * @param decryptedData {Uint8Array} Decrypted buffer
     * @returns {Promise<Uint8Array>} Encrypted buffer
     * TODO: GPU Computing
     */
    public async encrypt(decryptedData: Uint8Array): Promise<Uint8Array> {
        if (!this.cipher || !this.macKey) throw new Error('Session not established');
        const metadata = this.buildMetadata();
        const encrypted = await this.cipher.encrypt(decryptedData);
        let s1 = performance.now();
        const mac = await this.config.mac.signTwo(metadata, encrypted, this.macKey);
        const result = new Uint8Array(metadata.length + encrypted.length + mac.length);
        result.set(metadata, 0);
        result.set(encrypted, metadata.length);
        result.set(mac, metadata.length + encrypted.length);
        return result;
    }

    /**
     * Encrypt sync
     * @param decryptedData {Uint8Array} Decrypted buffer
     * @returns {Uint8Array} Encrypted buffer
     */
    public encryptSync(decryptedData: Uint8Array): Uint8Array {
        if (!this.cipher || !this.macKey) throw new Error('Session not established');
        const metadata = this.buildMetadata();
        const encrypted = this.cipher.encryptSync(decryptedData);
        const mac = this.config.mac.signSync(QuarkDashUtils.concatBytes(metadata, encrypted), this.macKey);
        return QuarkDashUtils.concatBytes(metadata, encrypted, mac);
    }

    /**
     * Decrypt async
     * @param encryptedData {Uint8Array} Encrypted buffer
     * @returns {Promise<Uint8Array>} Decrypted buffer
     * TODO: GPU Computing
     */
    public async decrypt(encryptedData: Uint8Array): Promise<Uint8Array> {
        if (!this.cipher || !this.macKey) throw new Error('Session not established');
        const packet = this.processDecrypt(encryptedData);
        const valid = await this.config.mac.verify(QuarkDashUtils.concatBytes(packet.metadata, packet.encrypted), this.macKey, packet.mac);
        if (!valid) throw new Error('MAC verification failed');
        this.checkMetadata(packet.metadata);
        return await this.cipher.decrypt(packet.encrypted);
    }

    /**
     * Decrypt sync
     * @param encryptedData {Uint8Array} Encrypted buffer
     * @returns {Uint8Array} Decrypted buffer
     */
    public decryptSync(encryptedData: Uint8Array): Uint8Array {
        if (!this.cipher || !this.macKey) throw new Error('Session not established');
        const packet = this.processDecrypt(encryptedData);
        const valid = this.config.mac.verifySync(QuarkDashUtils.concatBytes(packet.metadata, packet.encrypted), this.macKey, packet.mac);
        if (!valid) throw new Error('MAC verification failed');
        this.checkMetadata(packet.metadata);
        return this.cipher.decryptSync(packet.encrypted);
    }

    /**
     * Process decrypt
     * @param encryptedData {Uint8Array} encrypted buffer
     * @returns {QDEncryptedPacket} Parsed encrypted packet
     * @private
     */
    private processDecrypt(encryptedData: Uint8Array) : QDEncryptedPacket {
        if (encryptedData.length < 44) throw new Error('Invalid ciphertext');
        return {
            metadata: encryptedData.slice(0, 12),
            encrypted: encryptedData.slice(12, encryptedData.length - 32),
            mac: encryptedData.slice(encryptedData.length - 32)
        }
    }

    /**
     * Build meta-data
     * @returns {Uint8Array} Meta-data buffer
     * @private
     */
    private buildMetadata(): Uint8Array {
        const metadata = new Uint8Array(12);
        const timestamp = BigInt(Date.now());
        for (let i = 0; i < 8; i++) {
            metadata[i] = Number((timestamp >> BigInt(i * 8)) & 0xFFn);
        }
        const seq = this.sendSeq++;
        metadata[8] = seq & 0xFF;
        metadata[9] = (seq >> 8) & 0xFF;
        metadata[10] = (seq >> 16) & 0xFF;
        metadata[11] = (seq >> 24) & 0xFF;
        return metadata;
    }

    /**
     * Check Meta-Data
     * @param metadata {Uint8Array} Meta-data buffer
     * @private
     */
    private checkMetadata(metadata: Uint8Array): void {
        const timestamp = QuarkDashUtils.readUint64(metadata, 0);
        const now = Date.now();
        if (Math.abs(now - Number(timestamp)) > this.config.timestampToleranceMs) {
            throw new Error('Timestamp out of window');
        }
        const seq = QuarkDashUtils.readUint32(metadata, 8);
        if (this.receivedPackets.has(seq)) throw new Error('Replay detected');
        this.receivedPackets.add(seq);
        if (this.receivedPackets.size > this.config.maxPacketWindow) {
            const oldest = Math.min(...this.receivedPackets);
            this.receivedPackets.delete(oldest);
        }
    }

    /**
     * Dispose QuarkDash Crypto
     */
    public dispose() : void {
        if (this.sessionKey) QuarkDashUtils.secureZero(this.sessionKey);
        if (this.macKey) QuarkDashUtils.secureZero(this.macKey);
        this.sessionKey = null;
        this.macKey = null;
        this.cipher = null;
        this.receivedPackets.clear();
    }
}