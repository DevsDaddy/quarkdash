/**
 * QuarkDash Crypto Types
 *
 * @git             https://github.com/devsdaddy/quarkdash
 * @version         1.1.0
 * @author          Elijah Rastorguev
 * @build           1001
 * @website         https://dev.to/devsdaddy
 * @updated         13.04.2026
 */
/**
 * Crypto methods async interface
 */
export interface ICryptoMethodAsync {
    encrypt(decryptedData: Uint8Array): Promise<Uint8Array>;
    decrypt(encryptedData: Uint8Array): Promise<Uint8Array>;
}

/**
 * Crypto methods sync interface
 */
export interface ICryptoMethodSync {
    encryptSync(decryptedData: Uint8Array): Uint8Array;
    decryptSync(encryptedData: Uint8Array): Uint8Array;
}

/**
 * Cipher interface
 */
export interface ICipher extends ICryptoMethodAsync, ICryptoMethodSync{}

/**
 * KDF interface
 */
export interface IKDF {
    derive(ikm: Uint8Array, salt: Uint8Array, info: Uint8Array, length: number): Promise<Uint8Array>;
    deriveSync(ikm: Uint8Array, salt: Uint8Array, info: Uint8Array, length: number): Uint8Array;
}

/**
 * MAC interface
 */
export interface IMAC {
    sign(data: Uint8Array, key: Uint8Array): Promise<Uint8Array>;
    verify(data: Uint8Array, key: Uint8Array, tag: Uint8Array): Promise<boolean>;
    signSync(data: Uint8Array, key: Uint8Array): Uint8Array;
    verifySync(data: Uint8Array, key: Uint8Array, tag: Uint8Array): boolean;
}

/**
 * Key exchange interface
 */
export interface IKeyExchange {
    generateKeyPair(): Promise<ICryptoKeyPair>;
    generateKeyPairSync(): ICryptoKeyPair;
    encapsulate(publicKey: Uint8Array): Promise<ICryptoEncapsulated>;
    encapsulateSync(publicKey: Uint8Array): ICryptoEncapsulated;
    decapsulate(privateKey: Uint8Array, peerPublicKey: Uint8Array, ciphertext: Uint8Array): Promise<Uint8Array>;
    decapsulateSync(privateKey: Uint8Array, peerPublicKey: Uint8Array, ciphertext: Uint8Array): Uint8Array;
}

/**
 * Crypto key pair
 */
export interface ICryptoKeyPair {
    publicKey : Uint8Array;
    privateKey : Uint8Array;
}

/**
 * Crypto encapsulated
 */
export interface ICryptoEncapsulated {
    ciphertext: Uint8Array;
    sharedSecret: Uint8Array;
}