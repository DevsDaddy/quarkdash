/**
 * QuarkDash General Protocol Class
 *
 * @git             https://github.com/devsdaddy/quarkdash
 * @version         1.2.0
 * @author          Elijah Rastorguev
 * @build           1030
 * @website         https://dev.to/devsdaddy
 * @updated         28.08.2026
 */
/* Import required modules */
import {CipherFactory, CipherType} from "./cipher/cipher";
import {
    ICipher,
    ICryptoMethodAsync,
    ICryptoMethodSync,
    IKDF,
    IKeyExchange,
    IMAC,
} from "./core/types";
import {QuarkDashKDF} from "./core/kdf";
import {QuarkDashMAC} from "./core/mac";
import {QuarkDashUtils} from "./core/utils";
import {QuarkDashRRLWE} from "./session/rringlwe";
import {isWasmShake, Shake256Wasm} from "./hash/shake";
import {
    DEFAULT_REKEY_POLICY,
    RekeyPolicy,
    deriveRekeyMaterial,
    deriveRekeyMaterialSync,
    buildRekeyPayload,
    parseRekeyPayload,
} from "./session/rekey";

/**
 * Encrypted packet
 */
export interface QDEncryptedPacket {
    metadata: Uint8Array;
    encrypted: Uint8Array;
    mac: Uint8Array;
}

/**
 * Key Ring (Rekey) Options
 */
export interface QuarkDashRekeyOptions {
    policy: Partial<RekeyPolicy>;
    autoRekey: boolean;
    onRekey?: (counter: number) => void; // On key changed
}

/**
 * General Options
 */
export interface QuarkDashOptions {
    cipher: CipherType;
    kdf: IKDF;
    mac: IMAC;
    keyExchange: IKeyExchange;
    maxPacketWindow: number;
    timestampToleranceMs: number;
    rekey: QuarkDashRekeyOptions;
    usePerMessageNonce: boolean;
    WASM: { isEnabled: boolean; shakePath: string };
}

/**
 * Default QuarkDash Options
 */
const DEFAULT_OPTIONS: QuarkDashOptions = {
    cipher: CipherType.ChaCha20,
    kdf: new QuarkDashKDF(),
    mac: new QuarkDashMAC(),
    keyExchange: new QuarkDashRRLWE(),
    maxPacketWindow: 1000,
    timestampToleranceMs: 300000,
    rekey: {policy: {...DEFAULT_REKEY_POLICY}, autoRekey: false},
    usePerMessageNonce: true,
    WASM: {isEnabled: true, shakePath: "./wasm/shake.wasm"},
};

/**
 * QuarkDash
 */
export class QuarkDash implements ICryptoMethodAsync, ICryptoMethodSync {
    // General configs
    private config: QuarkDashOptions;

    // Session key: 32 bytes each, live in memory
    private sessionKey: Uint8Array | null = null;
    private macKey: Uint8Array | null = null;
    private cipher: ICipher | null = null;                              // for static nonce mode

    // replay encryption variables
    private sendSeq = 0;
    private receivedPackets = new Set<number>();

    // long-term keys
    private myKeyPair?: { publicKey: Uint8Array; privateKey: Uint8Array };
    private peerPublicKey?: Uint8Array;

    // key rotation mechanism variables
    private rekeyCounter = 0;
    private bytesEncrypted = 0;
    private messagesEncrypted = 0;
    private lastRekeyTime = Date.now();
    private rekeyPolicy: RekeyPolicy;

    /**
     * Create new QuarkDash Instance
     * @param config {Partial<QuarkDashOptions>} QuarkDash Options
     */
    constructor(config?: Partial<QuarkDashOptions>) {
        this.config = {
            ...DEFAULT_OPTIONS,
            ...config,
            rekey: {
                ...DEFAULT_OPTIONS.rekey,
                ...(config?.rekey || {}),
                policy: {...DEFAULT_REKEY_POLICY, ...(config?.rekey?.policy || {})},
            },
        } as QuarkDashOptions;
        this.rekeyPolicy = {
            ...DEFAULT_REKEY_POLICY,
            ...(config?.rekey?.policy || {}),
        };
        if (config?.WASM)
            this.config.WASM = {...DEFAULT_OPTIONS.WASM, ...config.WASM};
    }

    /* HANDSHAKE METHODS */
    /**
     * Generate key pair
     */
    public async generateKeyPair(): Promise<Uint8Array> {
        // Load WASM in lazy mode only if required
        if (this.config.WASM.isEnabled && !isWasmShake())
            await Shake256Wasm.initWasm(this.config.WASM.shakePath);
        this.myKeyPair = await this.config.keyExchange.generateKeyPair();
        return this.myKeyPair.publicKey;
    }

    /**
     * Generate key pair in sync mode
     */
    public generateKeyPairSync(): Uint8Array {
        this.myKeyPair = this.config.keyExchange.generateKeyPairSync();
        return this.myKeyPair.publicKey;
    }

    /**
     * Initialize session
     * @param peerPublicKey {Uint8Array} Public Key
     * @param isInitiator {boolean} Is initiator
     */
    public async initializeSession(
        peerPublicKey: Uint8Array,
        isInitiator: boolean,
    ): Promise<Uint8Array | null> {
        this.peerPublicKey = peerPublicKey;
        if (!this.myKeyPair) await this.generateKeyPair();
        if (isInitiator) {
            const {ciphertext, sharedSecret} =
                await this.config.keyExchange.encapsulate(peerPublicKey);
            await this.deriveSessionKeys(sharedSecret);
            return ciphertext;
        }
        return null;
    }

    /**
     * Initialize session in sync mode
     * @param peerPublicKey {Uint8Array} Public key
     * @param isInitiator {boolean} Initiator
     */
    public initializeSessionSync(
        peerPublicKey: Uint8Array,
        isInitiator: boolean,
    ): Uint8Array | null {
        this.peerPublicKey = peerPublicKey;
        if (!this.myKeyPair) this.generateKeyPairSync();
        if (isInitiator) {
            const {ciphertext, sharedSecret} =
                this.config.keyExchange.encapsulateSync(peerPublicKey);
            this.deriveSessionKeysSync(sharedSecret);
            return ciphertext;
        }
        return null;
    }

    /**
     * Finalize session
     * @param ciphertext {Uint8Array} Ciphertext to finalize session
     */
    public async finalizeSession(ciphertext: Uint8Array): Promise<void> {
        if (!this.myKeyPair || !this.peerPublicKey)
            throw new Error("Session not initialized");
        const sharedSecret = await this.config.keyExchange.decapsulate(
            this.myKeyPair.privateKey,
            this.myKeyPair.publicKey,
            ciphertext,
        );
        await this.deriveSessionKeys(sharedSecret);
    }

    /**
     * Finalize session in sync mode
     * @param ciphertext {Uint8Array} Ciphertext to finalize session
     */
    public finalizeSessionSync(ciphertext: Uint8Array): void {
        if (!this.myKeyPair || !this.peerPublicKey)
            throw new Error("Session not initialized");
        const sharedSecret = this.config.keyExchange.decapsulateSync(
            this.myKeyPair.privateKey,
            this.myKeyPair.publicKey,
            ciphertext,
        );
        this.deriveSessionKeysSync(sharedSecret);
    }

    /* KEYS ROTATION METHODS */
    /**
     * Check if need key rotation by bytes / messages / time
     */
    public needsRekey(): boolean {
        if (!this.sessionKey) return false;
        if (
            this.rekeyPolicy.afterMessages > 0 &&
            this.messagesEncrypted >= this.rekeyPolicy.afterMessages
        )
            return true;
        if (
            this.rekeyPolicy.afterBytes > 0 &&
            this.bytesEncrypted >= this.rekeyPolicy.afterBytes
        )
            return true;
        if (
            this.rekeyPolicy.intervalMs > 0 &&
            Date.now() - this.lastRekeyTime >= this.rekeyPolicy.intervalMs
        )
            return true;
        return false;
    }

    /**
     * Get key rotation stats
     */
    public getRekeyStats() {
        return {
            counter: this.rekeyCounter,
            bytesEncrypted: this.bytesEncrypted,
            messagesEncrypted: this.messagesEncrypted,
            lastRekeyTime: this.lastRekeyTime,
            policy: {...this.rekeyPolicy},
        };
    }

    /**
     * Set new key rotation policy
     * @param policy {Partial<RekeyPolicy>} New policy
     */
    public setRekeyPolicy(policy: Partial<RekeyPolicy>): void {
        this.rekeyPolicy = {...this.rekeyPolicy, ...policy};
    }

    /**
     * Get key rotation counter
     */
    public getRekeyCounter(): number {
        return this.rekeyCounter;
    }

    /**
     * Run key rotation
     */
    public async rekey(): Promise<Uint8Array> {
        const salt = QuarkDashUtils.randomBytes(32);
        const payload = buildRekeyPayload(salt, this.rekeyCounter);
        const token = await this.encrypt(payload);
        await this.doRekeyDerive(salt);
        return token;
    }

    /**
     * Run key rotation in sync mode
     */
    public rekeySync(): Uint8Array {
        const salt = QuarkDashUtils.randomBytes(32);
        const payload = buildRekeyPayload(salt, this.rekeyCounter);
        const token = this.encryptSync(payload);
        this.doRekeyDeriveSync(salt);
        return token;
    }

    /**
     * Apply key rotation
     * @param token {Uint8Array} Token
     */
    public async applyRekey(token: Uint8Array): Promise<void> {
        const plain = await this.decrypt(token);
        const {salt, counter} = parseRekeyPayload(plain);
        if (counter !== this.rekeyCounter)
            throw new Error(
                `Rekey counter mismatch: expected ${this.rekeyCounter} got ${counter}`,
            );
        await this.doRekeyDerive(salt);
        QuarkDashUtils.secureZero(plain);
    }

    /**
     * Apply key rotation in sync mode
     * @param token {Uint8Array} Token
     */
    public applyRekeySync(token: Uint8Array): void {
        const plain = this.decryptSync(token);
        const {salt, counter} = parseRekeyPayload(plain);
        if (counter !== this.rekeyCounter)
            throw new Error(
                `Rekey counter mismatch: expected ${this.rekeyCounter} got ${counter}`,
            );
        this.doRekeyDeriveSync(salt);
        QuarkDashUtils.secureZero(plain);
    }

    /* ENCRYPTION METHODS */
    /**
     * Encrypt
     * @param decryptedData {Uint8Array} Decrypted data
     */
    public async encrypt(decryptedData: Uint8Array): Promise<Uint8Array> {
        if (!this.macKey || !this.sessionKey)
            throw new Error("Session not established");

        const metadata = this.buildMetadata();                  // 8B time + 4B seq
        const cipher = this.getCipherForNonce(metadata);                        // per-message nonce = metadata (no reuse)
        const encrypted = await cipher.encrypt(decryptedData);
        const mac = await this.config.mac.signTwo(metadata, encrypted, this.macKey);

        const result = new Uint8Array(
            metadata.length + encrypted.length + mac.length,
        );
        result.set(metadata, 0);
        result.set(encrypted, metadata.length);
        result.set(mac, metadata.length + encrypted.length);

        this.bytesEncrypted += decryptedData.length;
        this.messagesEncrypted++;
        return result;
    }

    /**
     * Encrypt in sync mode
     * @param decryptedData {Uint8Array} Decrypted data
     */
    public encryptSync(decryptedData: Uint8Array): Uint8Array {
        if (!this.macKey || !this.sessionKey)
            throw new Error("Session not established");
        const metadata = this.buildMetadata();
        const cipher = this.getCipherForNonce(metadata);
        const encrypted = cipher.encryptSync(decryptedData);
        const mac = this.config.mac.signSync(
            QuarkDashUtils.concatBytes(metadata, encrypted),
            this.macKey,
        );
        this.bytesEncrypted += decryptedData.length;
        this.messagesEncrypted++;
        return QuarkDashUtils.concatBytes(metadata, encrypted, mac);
    }

    /**
     * Decrypt
     * @param encryptedData {Uint8Array} Encrypted data
     */
    public async decrypt(encryptedData: Uint8Array): Promise<Uint8Array> {
        if (!this.macKey || !this.sessionKey)
            throw new Error("Session not established");
        const packet = this.processDecrypt(encryptedData);
        const valid = await this.config.mac.verify(
            QuarkDashUtils.concatBytes(packet.metadata, packet.encrypted),
            this.macKey,
            packet.mac,
        );
        if (!valid) throw new Error("MAC verification failed");
        this.checkMetadata(packet.metadata);
        return this.getCipherForNonce(packet.metadata).decrypt(packet.encrypted);
    }

    /**
     * Decrypt in sync mode
     * @param encryptedData {Uint8Array} Encrypted data
     */
    public decryptSync(encryptedData: Uint8Array): Uint8Array {
        if (!this.macKey || !this.sessionKey)
            throw new Error("Session not established");
        const packet = this.processDecrypt(encryptedData);
        const valid = this.config.mac.verifySync(
            QuarkDashUtils.concatBytes(packet.metadata, packet.encrypted),
            this.macKey,
            packet.mac,
        );
        if (!valid) throw new Error("MAC verification failed");
        this.checkMetadata(packet.metadata);
        return this.getCipherForNonce(packet.metadata).decryptSync(
            packet.encrypted,
        );
    }

    /**
     * Dispose QuarkDash Instance
     */
    public dispose(): void {
        if (this.sessionKey) QuarkDashUtils.secureZero(this.sessionKey);
        if (this.macKey) QuarkDashUtils.secureZero(this.macKey);
        this.sessionKey = null;
        this.macKey = null;
        this.cipher = null;
        this.receivedPackets.clear();
    }

    private async deriveSessionKeys(sharedSecret: Uint8Array): Promise<void> {
        const salt = new Uint8Array(32);
        const info = QuarkDashUtils.textToBytes("session-key");
        const keyMaterial = await this.config.kdf.derive(
            sharedSecret,
            salt,
            info,
            64,
        );
        this.processDeriveSessionKeys(keyMaterial, sharedSecret);
    }

    private deriveSessionKeysSync(sharedSecret: Uint8Array): void {
        const salt = new Uint8Array(32);
        const info = QuarkDashUtils.textToBytes("session-key");
        const keyMaterial = this.config.kdf.deriveSync(
            sharedSecret,
            salt,
            info,
            64,
        );
        this.processDeriveSessionKeys(keyMaterial, sharedSecret);
    }

    // Process derive session keys
    private processDeriveSessionKeys(
        keyMaterial: Uint8Array,
        sharedSecret: Uint8Array,
    ) {
        this.sessionKey = keyMaterial.slice(0, 32);
        this.macKey = keyMaterial.slice(32, 64);

        // One cipher for static-nonce mode.
        // For per-message mode - create new cipher every time
        this.cipher = CipherFactory.create(
            this.config.cipher,
            this.sessionKey,
            new Uint8Array(12),
        );

        // Reset rekey counters for new session
        this.rekeyCounter = 0;
        this.bytesEncrypted = 0;
        this.messagesEncrypted = 0;
        this.lastRekeyTime = Date.now();

        // Clear secrets from memory
        QuarkDashUtils.secureZero(sharedSecret);
        QuarkDashUtils.secureZero(keyMaterial);
    }

    // Choose a cipher for session / message (nonce = metadata)
    private getCipherForNonce(nonce: Uint8Array): ICipher {
        if (!this.sessionKey) throw new Error("Session not established");
        if (!this.config.usePerMessageNonce) return this.cipher!;
        if (nonce.length !== 12) throw new Error("Nonce must be 12 bytes");
        return CipherFactory.create(this.config.cipher, this.sessionKey, nonce);
    }

    // Internal method for new keys
    private async doRekeyDerive(salt: Uint8Array): Promise<void> {
        if (!this.sessionKey || !this.macKey)
            throw new Error("Session not established");
        const mat = await deriveRekeyMaterial(
            this.config.kdf,
            this.sessionKey,
            this.macKey,
            salt,
            this.rekeyCounter,
        );
        this.reinitSession(mat);
    }

    private doRekeyDeriveSync(salt: Uint8Array): void {
        if (!this.sessionKey || !this.macKey)
            throw new Error("Session not established");
        const mat = deriveRekeyMaterialSync(
            this.config.kdf,
            this.sessionKey,
            this.macKey,
            salt,
            this.rekeyCounter,
        );
        this.reinitSession(mat);
    }

    private reinitSession(mat: Uint8Array<ArrayBufferLike>) {
        if (!this.sessionKey || !this.macKey)
            throw new Error("Session not established");

        const newSession = mat.slice(0, 32),
            newMac = mat.slice(32, 64);

        QuarkDashUtils.secureZero(this.sessionKey);
        QuarkDashUtils.secureZero(this.macKey);
        this.sessionKey = newSession;
        this.macKey = newMac;
        this.cipher = CipherFactory.create(
            this.config.cipher,
            this.sessionKey,
            new Uint8Array(12),
        );

        this.rekeyCounter++;
        this.bytesEncrypted = 0;
        this.messagesEncrypted = 0;
        this.lastRekeyTime = Date.now();
        QuarkDashUtils.secureZero(mat);
        if (this.config.rekey.onRekey) this.config.rekey.onRekey(this.rekeyCounter);
    }

    // Process decrypt
    private processDecrypt(encryptedData: Uint8Array): QDEncryptedPacket {
        if (encryptedData.length < 44) throw new Error("Invalid ciphertext"); // 12 + 0 + 32 is minimum
        return {
            metadata: encryptedData.slice(0, 12),
            encrypted: encryptedData.slice(12, encryptedData.length - 32),
            mac: encryptedData.slice(encryptedData.length - 32),
        };
    }

    // 12B: 8B little-endian timestamp + 4B seq for metadata
    private buildMetadata(): Uint8Array {
        const metadata = new Uint8Array(12);
        const timestamp = BigInt(Date.now());
        for (let i = 0; i < 8; i++)
            metadata[i] = Number((timestamp >> BigInt(i * 8)) & 0xffn);
        const seq = this.sendSeq++;
        metadata[8] = seq & 0xff;
        metadata[9] = (seq >> 8) & 0xff;
        metadata[10] = (seq >> 16) & 0xff;
        metadata[11] = (seq >> 24) & 0xff;
        return metadata;
    }

    // check metadata
    private checkMetadata(metadata: Uint8Array): void {
        const timestamp = QuarkDashUtils.readUint64(metadata, 0);
        if (
            Math.abs(Date.now() - Number(timestamp)) >
            this.config.timestampToleranceMs
        )
            throw new Error("Timestamp out of window");

        const seq = QuarkDashUtils.readUint32(metadata, 8);
        if (this.receivedPackets.has(seq)) throw new Error("Replay detected");

        this.receivedPackets.add(seq);
        // sliding window. Do not allow infinite scaling
        if (this.receivedPackets.size > this.config.maxPacketWindow) {
            const oldest = Math.min(...this.receivedPackets);
            this.receivedPackets.delete(oldest);
        }
    }
}
