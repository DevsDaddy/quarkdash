/**
 * QuarkDash Lazy Keystream
 * Instead of generate a megabytes of keystream, we build a lazy generator.
 * Compute only requested block and cache last 64.
 *
 * @git             https://github.com/devsdaddy/quarkdash
 * @version         1.2.0
 * @author          Elijah Rastorguev
 * @build           1027
 * @website         https://dev.to/devsdaddy
 * @updated         28.08.2026
 */
/**
 * Keystream Generator Interface
 */
export interface IKeystreamGenerator {
    // Block size
    readonly blockSize: number;

    /**
     * Get bytes
     * @param offset {number} Offset
     * @param length {number} Number of return bytes
     */
    getBytes(offset: number, length: number): Uint8Array;

    /**
     * XOR data with keystream start from offset
     * @param data {Uint8Array} Data
     * @param keystreamOffset {number} Offset
     */
    xor(data: Uint8Array, keystreamOffset?: number): Uint8Array;

    /**
     * XOR without allocation
     * @param input {Uint8Array} Input buffer
     * @param output {Uint8Array} Output buffer
     * @param keystreamOffset {number} Offset
     */
    xorInto(
        input: Uint8Array,
        output: Uint8Array,
        keystreamOffset?: number,
    ): void;

    /**
     * Infinity blocks generator
     * @param startBlock {number} Start block
     */
    blocks(startBlock?: number): Generator<Uint8Array, void, unknown>;

    /**
     * Cursor (Position at stream)
     * @param byteOffset {number} Offset
     */
    seek(byteOffset: number): void;

    tell(): number;

    rewind(): void;
}

/**
 * Basic Keystream implementation
 * Store position, blocks cache and slicing
 */
export abstract class LazyKeystream implements IKeystreamGenerator {
    // read / xorRead cursor (position) like in a file
    protected position = 0;

    // Small LRU-cache for last N blocks
    protected cachedBlocks = new Map<number, Uint8Array>();
    protected maxCacheBlocks = 64;

    /**
     * Create keystream
     * @param blockSize {number} Block size
     */
    constructor(public readonly blockSize: number) {
    }

    /**
     * Generate block
     * @param blockIndex {number} Block index
     */
    abstract generateBlock(blockIndex: number): Uint8Array;

    /**
     * Get bytes
     * @param offset {number} Offset
     * @param length {number} Length
     */
    public getBytes(offset: number, length: number): Uint8Array {
        if (offset < 0 || length < 0) throw new Error("Invalid offset/length");

        const out = new Uint8Array(length);
        let remaining = length;
        let outPos = 0;
        let cur = offset;

        while (remaining > 0) {
            const blockIdx = Math.floor(cur / this.blockSize);
            const inBlockOffset = cur % this.blockSize;
            const block = this.getBlock(blockIdx);

            const take = Math.min(this.blockSize - inBlockOffset, remaining);
            out.set(block.subarray(inBlockOffset, inBlockOffset + take), outPos);

            outPos += take;
            cur += take;
            remaining -= take;
        }
        return out;
    }

    /**
     * XOR Data
     * @param data {Uint8Array} Input buffer
     * @param keystreamOffset {number} Offset
     */
    public xor(data: Uint8Array, keystreamOffset: number = 0): Uint8Array {
        const out = new Uint8Array(data.length);
        this.xorInto(data, out, keystreamOffset);
        return out;
    }

    /**
     * XOR Into
     * @param input {Uint8Array} Input buffer
     * @param output {Uint8Array} Output buffer
     * @param keystreamOffset {number} Offset
     */
    public xorInto(input: Uint8Array, output: Uint8Array, keystreamOffset: number = 0): void {
        if (output.length < input.length)
            throw new Error("Output buffer too small");
        let remaining = input.length;
        let inPos = 0;
        let ksPos = keystreamOffset;
        while (remaining > 0) {
            const blockIdx = (ksPos / this.blockSize) | 0;
            const inBlockOffset = ksPos % this.blockSize;
            const block = this.getBlock(blockIdx);
            const take = Math.min(this.blockSize - inBlockOffset, remaining);
            let i = 0;
            const blockView = new DataView(block.buffer, block.byteOffset, block.byteLength);
            const inView = new DataView(input.buffer, input.byteOffset + inPos, take);
            const outView = new DataView(output.buffer, output.byteOffset + inPos, take);
            const aligned = (inBlockOffset & 3) === 0 && (inPos & 3) === 0;
            if (aligned) {
                const words = take >> 2;
                for (let w = 0; w < words; w++) {
                    const off = inBlockOffset + (w << 2);
                    const kw = blockView.getUint32(off, true);
                    const iw = inView.getUint32(w << 2, true);
                    outView.setUint32(w << 2, kw ^ iw, true);
                }
                i = words << 2;
            }
            for (; i < take; i++) {
                output[inPos + i] = input[inPos + i] ^ block[inBlockOffset + i];
            }
            inPos += take;
            ksPos += take;
            remaining -= take;
        }
    }

    /**
     * Stream blocks
     * @param startBlock {number} Start block
     */
    * blocks(startBlock: number = 0): Generator<Uint8Array, void, unknown> {
        let idx = startBlock;
        while (true) {
            yield this.getBlock(idx++);
        }
    }

    /**
     * Seek
     * @param byteOffset {number} Byte offset
     */
    public seek(byteOffset: number): void {
        if (byteOffset < 0) throw new Error("Negative seek");
        this.position = byteOffset;
    }

    /**
     * Get current position
     */
    public tell(): number {
        return this.position;
    }

    /**
     * Reset position
     */
    public rewind(): void {
        this.position = 0;
    }

    /**
     * Read bytes from current position and move current position
     * @param length {number} Length
     */
    public read(length: number): Uint8Array {
        const out = this.getBytes(this.position, length);
        this.position += length;
        return out;
    }

    /**
     * XOR data block from current position in stream
     * @param data {Uint8Array} Data buffer
     */
    public xorRead(data: Uint8Array): Uint8Array {
        const out = this.xor(data, this.position);
        this.position += data.length;
        return out;
    }

    /**
     * Get block
     * @param idx {number} Index
     * @protected
     */
    protected getBlock(idx: number): Uint8Array {
        const cached = this.cachedBlocks.get(idx);
        if (cached) return cached;

        const block = this.generateBlock(idx);

        // simple LRU: remove old cached data
        if (this.cachedBlocks.size >= this.maxCacheBlocks) {
            const first = this.cachedBlocks.keys().next().value as number;
            this.cachedBlocks.delete(first);
        }
        this.cachedBlocks.set(idx, block);
        return block;
    }

    /**
     * Clear cache
     */
    public clearCache(): void {
        this.cachedBlocks.clear();
    }

    /**
     * Set cache limit
     * @param n {number} Limit
     */
    public setCacheLimit(n: number): void {
        this.maxCacheBlocks = n;
    }
}
