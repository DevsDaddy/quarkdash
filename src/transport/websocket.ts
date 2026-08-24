/**
 * QuarkDash Protocol WebSocket Wrapper
 * Can be used with any websocket (node / browser)
 *
 * Wrap any socket using `wrap()` method and get your
 * encrypted channel by few lines of code.
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
 * WSLike Type
 * For browser and Node
 */
export type WSLike = {
    send(data: Uint8Array | string): void;
    on?(event: string, handler: (...args: any[]) => void): void;
    addEventListener?(type: string, handler: (ev: any) => void): void;
    close?(): void;
};

/**
 * QuarkDash WebSocket Options
 */
export interface QuarkDashWSOptions {
    binaryType?: "arraybuffer" | "nodebuffer";        // Binary type
    autoEncrypt?: boolean;
}

/**
 * QuarkDash WebSocket Wrapper
 */
export class QuarkDashWebSocket {
    /**
     * Create QuarkDash WebSocket Wrapper
     * @param qd {QuarkDash} QuarkDash Instance
     * @param ws {WSLike} WebSocket Instance
     * @param opts {QuarkDashWSOptions} QuarkDash WebSocket Options
     */
    constructor(
        private qd: QuarkDash,
        private ws: WSLike,
        private opts: QuarkDashWSOptions = {},
    ) {
    }

    /**
     * Wrap socket
     * @param qd {QuarkDash} QuarkDash Instance
     * @param ws {WSLike} WebSocket
     * @param opts {QuarkDashWSOptions} QuarkDash WebSocket Options
     */
    public static wrap(
        qd: QuarkDash,
        ws: WSLike,
        opts: QuarkDashWSOptions = {},
    ): QuarkDashWebSocket {
        const inst = new QuarkDashWebSocket(qd, ws, opts);
        inst.attach();
        return inst;
    }

    /**
     * Convert any data to Uint8Array
     * @param data {any} Any data from socket
     */
    public static toUint8Array(data: any): Uint8Array {
        if (data instanceof Uint8Array) return data;
        if (data instanceof ArrayBuffer) return new Uint8Array(data);
        if (typeof Buffer !== "undefined" && Buffer.isBuffer(data))
            return new Uint8Array(data);
        if (typeof data === "string") return QuarkDashUtils.textToBytes(data);
        if (data?.data) return QuarkDashWebSocket.toUint8Array(data.data);
        return new Uint8Array(data);
    }

    /**
     * Create server wrapper (factory method)
     * @param qdFactory {QuarkDash | Promise<QuarkDash>} QuarkDash Factory
     */
    public static createServerWrapper(qdFactory: () => QuarkDash | Promise<QuarkDash>) {
        return async (ws: WSLike) => {
            const qd = await qdFactory();
            return QuarkDashWebSocket.wrap(qd, ws);
        };
    }

    /**
     * Send binary data
     * @param data {Uint8Array | string} Data to send
     */
    public async send(data: Uint8Array | string): Promise<void> {
        const bytes =
            typeof data === "string" ? QuarkDashUtils.textToBytes(data) : data;
        const enc = await this.qd.encrypt(bytes);
        this.ws.send(enc as any);
    }

    /**
     * Send binary data in sync mode
     * @param data {Uint8Array | string} Data to send
     */
    public sendSync(data: Uint8Array | string): void {
        const bytes =
            typeof data === "string" ? QuarkDashUtils.textToBytes(data) : data;
        const enc = this.qd.encryptSync(bytes);
        this.ws.send(enc as any);
    }

    /**
     * Send as JSON
     * @param obj {any} Object to send
     */
    public async sendJSON(obj: any): Promise<void> {
        await this.send(QuarkDashUtils.textToBytes(JSON.stringify(obj)));
    }

    /**
     * Subscribe to decrypted messages
     * @param handler Message handler
     */
    public onDecrypted(handler: (data: Uint8Array) => void): void {
        (this.ws as any).__qd_onMessage = handler;
    }

    // Attach handlers
    private attach(): void {
        const handler = async (data: any) => {
            const buf = QuarkDashWebSocket.toUint8Array(data);
            try {
                const dec = await this.qd.decrypt(buf);
                // внешний код подписывается через onDecrypted()
                (this.ws as any).__qd_onMessage?.(dec);
            } catch {
                // если не смогли расшифровать — просто игнорируем, не ломаем сокет
            }
        };

        if (this.ws.on) this.ws.on("message", handler);
        else if (this.ws.addEventListener)
            this.ws.addEventListener("message", (ev: any) => handler(ev.data));
    }
}

declare const Buffer: any;
