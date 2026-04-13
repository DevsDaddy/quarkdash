/**
 * QuarkDash Crypto WebAssembly Loader
 *
 * @git             https://github.com/devsdaddy/quarkdash
 * @version         1.1.0
 * @author          Elijah Rastorguev
 * @build           1010
 * @website         https://dev.to/devsdaddy
 * @updated         14.04.2026
 */
// WASM Variables
let wasmPromise: Promise<WebAssembly.Module> | null = null;
let wasmCache: WebAssembly.Module | null = null;

/**
 * Load WASM Module
 * @param wasmUrl
 */
export async function loadWasmModule(wasmUrl: string): Promise<WebAssembly.Module> {
    if (wasmCache) return wasmCache;
    if (wasmPromise) return wasmPromise;

    wasmPromise = (async () => {
        let bytes: ArrayBuffer;

        // For Node js
        if (typeof process !== 'undefined' && process.versions && process.versions.node) {
            try {
                const { readFileSync } = await import('fs');
                const { resolve } = await import('path');
                const possiblePaths = [
                    resolve(process.cwd(), wasmUrl),
                    resolve(__dirname, wasmUrl)
                ];
                for (const path of possiblePaths) {
                    try {
                        const buffer = readFileSync(path);
                        bytes = buffer.buffer.slice(buffer.byteOffset, buffer.byteOffset + buffer.byteLength);
                        return await WebAssembly.compile(bytes);
                    } catch (e) { /* continue */ }
                }
                throw new Error('WASM file not found in Node.js filesystem');
            } catch (err) {
                console.error('Node.js filesystem read failed:', err);
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

        throw new Error('Unable to load WASM module. Please provide a valid URL or install the .wasm file.');
    })();

    wasmCache = await wasmPromise;
    return wasmCache;
}