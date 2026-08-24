/**
 * QuarkDash Protocol gRPC Wrapper
 * This module allow to wrap gRPC protocol.
 * gRPC is already binary, so we need only apply as
 * proxy-wrapper
 *
 * @git             https://github.com/devsdaddy/quarkdash
 * @version         1.2.0
 * @author          Elijah Rastorguev
 * @build           1023
 * @website         https://dev.to/devsdaddy
 * @updated         22.08.2026
 */
/* Import required modules */
import {QuarkDash} from "../crypto";
import {QuarkDashUtils} from "../core/utils";

// GRPC Metadata
export type GrpcMetadata = Map<string, string> | Record<string, string> | any;
export type GrpcCall = { metadata?: GrpcMetadata; request?: Uint8Array | any };

/**
 * QuarkDash gRPC Options
 */
export interface QDGrpcOptions {
    metadataKey?: string;                 // Where to store encryption marker
    encryptMetadata?: boolean;
}

/**
 * QuarkDash gRPC Wrapper
 */
export class QuarkDashGRPC {
    /**
     * Create QuarkDash gRPC Wrapper
     * @param qd
     * @param opts
     */
    constructor(
        private qd: QuarkDash,
        private opts: QDGrpcOptions = {},
    ) {
        this.opts.metadataKey = this.opts.metadataKey ?? "qd-encrypted-bin";
    }

    /**
     * Encrypt message
     * @param msg {Uint8Array | string | object} Message to encrypt
     */
    public async encryptMessage(msg: Uint8Array | string | object): Promise<Uint8Array> {
        let bytes: Uint8Array;
        if (msg instanceof Uint8Array) bytes = msg;
        else if (typeof msg === "string") bytes = QuarkDashUtils.textToBytes(msg);
        else bytes = QuarkDashUtils.textToBytes(JSON.stringify(msg));
        return this.qd.encrypt(bytes);
    }

    /**
     * Encrypt message in sync mode
     * @param msg {Uint8Array | string | object} Message to encrypt
     */
    public encryptMessageSync(msg: Uint8Array | string | object): Uint8Array {
        let bytes: Uint8Array;
        if (msg instanceof Uint8Array) bytes = msg;
        else if (typeof msg === "string") bytes = QuarkDashUtils.textToBytes(msg);
        else bytes = QuarkDashUtils.textToBytes(JSON.stringify(msg));
        return this.qd.encryptSync(bytes);
    }

    /**
     * Decrypt message
     * @param data {Uint8Array} Encrypted data
     */
    public async decryptMessage(data: Uint8Array): Promise<Uint8Array> {
        return this.qd.decrypt(data);
    }

    /**
     * Decrypt data in sync mode
     * @param data {Uint8Array} Encrypted data
     */
    public decryptMessageSync(data: Uint8Array): Uint8Array {
        return this.qd.decryptSync(data);
    }

    /* USE INTERCEPTORS FOR NATIVE gRPC API */
    /**
     * Client Interceptor
     */
    public clientInterceptor() {
        const self = this;
        return (options: any, nextCall: any) => {
            return new Proxy(nextCall(options), {
                get(target, prop) {
                    if (prop === "sendMessage") {
                        return async (msg: any) => {
                            const bytes =
                                msg instanceof Uint8Array
                                    ? msg
                                    : QuarkDashUtils.textToBytes(JSON.stringify(msg));
                            const enc = await self.encryptMessage(bytes);
                            return target.sendMessage(enc);
                        };
                    }
                    return target[prop];
                },
            });
        };
    }

    /**
     * Server Interceptor
     */
    public serverInterceptor() {
        const self = this;
        return async (call: GrpcCall, next: (call: GrpcCall) => any) => {
            if (call.request instanceof Uint8Array) {
                try {
                    call.request = await self.decryptMessage(call.request);
                } catch {
                }
            }
            const result = await next(call);
            if (result instanceof Uint8Array) return self.encryptMessage(result);
            if (result && typeof result === "object")
                return self.encryptMessage(
                    QuarkDashUtils.textToBytes(JSON.stringify(result)),
                );
            return result;
        };
    }

    /**
     * gRPC Proxy Client
     * May be used without .proto changes
     * @param client {any} Client
     */
    public wrapClient<T extends object>(client: T): T {
        const self = this;
        return new Proxy(client as any, {
            get(target, prop) {
                const orig = target[prop];
                if (typeof orig === "function") {
                    return async (...args: any[]) => {
                        // Payload as first argument
                        if (args[0] instanceof Uint8Array || typeof args[0] === "object") {
                            try {
                                args[0] = await self.encryptMessage(
                                    args[0] instanceof Uint8Array
                                        ? args[0]
                                        : QuarkDashUtils.textToBytes(JSON.stringify(args[0])),
                                );
                            } catch {
                            }
                        }
                        const res = await orig.apply(target, args);
                        if (res instanceof Uint8Array) {
                            try {
                                return await self.decryptMessage(res);
                            } catch {
                                return res;
                            }
                        }
                        return res;
                    };
                }
                return orig;
            },
        });
    }

    /**
     * Convert to bytes
     * @param data {any} Data to bytes
     */
    public static toBytes(data: any): Uint8Array {
        if (data instanceof Uint8Array) return data;
        if (typeof data === "string") return QuarkDashUtils.textToBytes(data);
        return QuarkDashUtils.textToBytes(JSON.stringify(data));
    }
}
