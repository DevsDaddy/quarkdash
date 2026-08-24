/**
 * QuarkDash Protocol HTTP Wrapper
 * Can be used with Express, Fastify and other clients
 * with minimal changes.
 *
 * Encrypt request/response body with
 * `x-qd-encrypted: 1` headers. Other - default HTTP
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

/**
 * QuarkDash HTTP Wrapper Options
 */
export interface QDHttpOptions {
    headerName?: string;                  // Encryption header. By default x-qd-encrypted
    encryptHeader?: boolean;
}

/**
 * QuarkDash HTTP Wrapper
 */
export class QuarkDashHTTP {
    /**
     * Create QuarkDash HTTP Wrapper
     * @param qd {QuarkDash} QuarkDash Instance
     * @param opts {QDHttpOptions} QuarkDash HTTP Wrapper Options
     */
    constructor(
        private qd: QuarkDash,
        private opts: QDHttpOptions = {},
    ) {
        this.opts.headerName = this.opts.headerName ?? "x-qd-encrypted";
    }

    /* LOW-LEVEL BODY ENCRYPTION */
    /**
     * Encrypt body
     * @param body {Uint8Array | string | object} Body data
     */
    public async encryptBody(
        body: Uint8Array | string | object,
    ): Promise<{ body: Uint8Array; headers: Record<string, string> }> {
        let bytes: Uint8Array;
        if (body instanceof Uint8Array) bytes = body;
        else if (typeof body === "string") bytes = QuarkDashUtils.textToBytes(body);
        else bytes = QuarkDashUtils.textToBytes(JSON.stringify(body));

        const enc = await this.qd.encrypt(bytes);
        return {
            body: enc,
            headers: {
                [this.opts.headerName!]: "1",
                "Content-Type": "application/octet-stream",
            },
        };
    }

    /**
     * Encrypt body in sync mode
     * @param body {Uint8Array | string | object} Body data
     */
    public encryptBodySync(body: Uint8Array | string | object): {
        body: Uint8Array;
        headers: Record<string, string>;
    } {
        let bytes: Uint8Array;
        if (body instanceof Uint8Array) bytes = body;
        else if (typeof body === "string") bytes = QuarkDashUtils.textToBytes(body);
        else bytes = QuarkDashUtils.textToBytes(JSON.stringify(body));

        const enc = this.qd.encryptSync(bytes);
        return {
            body: enc,
            headers: {
                [this.opts.headerName!]: "1",
                "Content-Type": "application/octet-stream",
            },
        };
    }

    /**
     * Decrypt body
     * @param data {Uint8Array} Encrypted body
     */
    public async decryptBody(data: Uint8Array): Promise<Uint8Array> {
        return this.qd.decrypt(data);
    }

    /**
     * Decrypt body in sync mode
     * @param data {Uint8Array} Encrypted body
     */
    public decryptBodySync(data: Uint8Array): Uint8Array {
        return this.qd.decryptSync(data);
    }

    /**
     * Decrypt data to string
     * @param data {Uint8Array} Encrypted data
     */
    public async decryptToString(data: Uint8Array): Promise<string> {
        return QuarkDashUtils.bytesToText(await this.decryptBody(data));
    }

    /**
     * Decrypt data to JSON
     * @param data {Uint8Array} Encrypted data
     */
    public async decryptToJSON<T = any>(data: Uint8Array): Promise<T> {
        return JSON.parse(await this.decryptToString(data));
    }

    /**
     * Get express middleware
     * Single app.use() - encrypt everything
     */
    public expressMiddleware() {
        const self = this;
        return async (req: any, res: any, next: any) => {
            try {
                // Incoming request check header and decrypt
                if (req.headers[self.opts.headerName!.toLowerCase()]) {
                    const chunks: Uint8Array[] = [];
                    req.on("data", (c: any) =>
                        chunks.push(c instanceof Uint8Array ? c : new Uint8Array(c)),
                    );
                    await new Promise<void>((resolve) => req.on("end", resolve));

                    const raw = QuarkDashUtils.concatBytes(...chunks);
                    const dec = await self.decryptBody(raw);

                    (req as any).qdDecryptedBody = dec;
                    try {
                        (req as any).body = JSON.parse(QuarkDashUtils.bytesToText(dec));
                    } catch {
                        (req as any).body = dec;
                    }
                }

                // Encrypt res.send
                const origSend = res.send.bind(res);
                res.send = async (body: any) => {
                    if (
                        body instanceof Uint8Array ||
                        typeof body === "string" ||
                        typeof body === "object"
                    ) {
                        const {body: enc} = await self.encryptBody(
                            body instanceof Uint8Array ? body : body,
                        );
                        res.setHeader(self.opts.headerName!, "1");
                        res.setHeader("Content-Type", "application/octet-stream");
                        return origSend(enc);
                    }
                    return origSend(body);
                };

                next();
            } catch (e) {
                next(e);
            }
        };
    }

    /**
     * Create fetch wrapper
     * @param fetchFn {fetchFn} Fetch function
     */
    public createFetchWrapper(fetchFn: typeof fetch = fetch): typeof fetch {
        const self = this;
        return (async (input: any, init?: any) => {
            // ecrypt body before send
            if (init?.body) {
                const bytes =
                    init.body instanceof Uint8Array
                        ? init.body
                        : QuarkDashUtils.textToBytes(
                            typeof init.body === "string"
                                ? init.body
                                : JSON.stringify(init.body),
                        );
                const enc = await self.qd.encrypt(bytes);
                init = {
                    ...init,
                    body: enc,
                    headers: {
                        ...(init.headers || {}),
                        [self.opts.headerName!]: "1",
                        "Content-Type": "application/octet-stream",
                    },
                };
            }

            const res: any = await fetchFn(input, init);

            // if server response is encrypted
            const hdr = res.headers?.get?.(self.opts.headerName!);
            if (hdr) {
                const buf = new Uint8Array(await res.arrayBuffer());
                const dec = await self.decryptBody(buf);
                return new Response(dec as any, {
                    status: res.status,
                    headers: res.headers,
                });
            }
            return res;
        }) as any;
    }
}
