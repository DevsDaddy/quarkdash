/**
 * QuarkDash Crypto WebAssembly Loader
 *
 * @git             https://github.com/devsdaddy/quarkdash
 * @version         1.1.0
 * @author          Elijah Rastorguev
 * @build           1017
 * @website         https://dev.to/devsdaddy
 * @updated         05.09.2026
 */
// WASM Cache and Lazy Loading
let wasmCacheMap = new Map<string, WebAssembly.Module>();
let wasmPromiseMap = new Map<string, Promise<WebAssembly.Module>>();

/**
 * Clear WASM Cache
 */
export function clearWasmCache(): void {
    wasmCacheMap.clear();
    wasmPromiseMap.clear();
}

/**
 * Load WASM Module
 * @param wasmUrl {string} WASM Url
 */
export async function loadWasmModule(
    wasmUrl: string,
): Promise<WebAssembly.Module> {
    // Check cache and lazy load
    const cached = wasmCacheMap.get(wasmUrl);
    if (cached) return cached;
    const pending = wasmPromiseMap.get(wasmUrl);
    if (pending) return pending;

    // Load WASM
    const promise = (async () => {
        let bytes: ArrayBuffer;

        // For Node js
        if (
            typeof process !== "undefined" &&
            process.versions &&
            process.versions.node
        ) {
            try {
                const {readFileSync} = await import("fs");
                const {resolve} = await import("path");
                const possiblePaths = [
                    resolve(process.cwd(), wasmUrl),
                    resolve(__dirname, wasmUrl),
                ];
                for (const path of possiblePaths) {
                    try {
                        const buffer = readFileSync(path);
                        bytes = buffer.buffer.slice(
                            buffer.byteOffset,
                            buffer.byteOffset + buffer.byteLength,
                        );
                        return await WebAssembly.compile(bytes);
                    } catch (e) {
                        /* continue */
                    }
                }
                throw new Error("WASM file not found in Node.js filesystem");
            } catch (err) {
                console.error("Node.js filesystem read failed:", err);
            }
        }

        // Browser support
        try {
            const response = await fetch(wasmUrl);
            if (!response.ok) throw new Error(`HTTP ${response.status}`);
            bytes = await response.arrayBuffer();
            return await WebAssembly.compile(bytes);
        } catch (err) {
            console.error(`Failed to fetch WASM from ${wasmUrl}:`, err);
        }

        throw new Error(
            "Unable to load WASM module. Please provide a valid URL or install the .wasm file.",
        );
    })();
    wasmPromiseMap.set(wasmUrl, promise);
    const mod = await promise;
    wasmCacheMap.set(wasmUrl, mod);
    return mod;
}

/**
 * Check SIMD Support
 */
export function isSimdSupported(): boolean {
    try {
        return typeof WebAssembly !== "undefined" && typeof (WebAssembly as any).validate === "function" && (WebAssembly as any).validate(new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0, 2, 6, 1, 5, 1, 121, 0, 2, 10, 1, 11, 0, 1, 0, 2, 3, 1, 0, 13, 1, 11]));
    } catch {
        return false;
    }
}

/**
 * Check BULK Memory Support
 */
export function isBulkMemorySupported(): boolean {
    try {
        return typeof WebAssembly !== "undefined" && typeof (WebAssembly as any).validate === "function" && (WebAssembly as any).validate(new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0, 1, 4, 1, 96, 0, 0, 2, 6, 1, 5, 1, 1, 0, 3, 2, 1, 0, 5, 3, 1, 0, 1, 10, 9, 1, 7, 0, 65, 0, 65, 0, 65, 0, 252, 10, 0, 0, 11]));
    } catch {
        return false;
    }
}

/**
 * Check WASM Support
 */
export function isWasmSupported(): boolean {
    try {
        return typeof WebAssembly !== "undefined" && typeof WebAssembly.compile === "function";
    } catch {
        return false;
    }
}
