/**
 * QuarkDash Lazy Keystream
 * Instead of generate a megabytes of keystream, we build a lazy generator.
 * Compute only requested block and cache last 64.
 *
 * @git             https://github.com/devsdaddy/quarkdash
 * @version         1.2.0
 * @author          Elijah Rastorguev
 * @build           1030
 * @website         https://dev.to/devsdaddy
 * @updated         05.09.2026
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

    // Cache Queue
    private cacheQueue: number[] = [];

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
        if (output.length < input.length) throw new Error("Output buffer too small");
        let remaining = input.length;
        let inPos = 0;
        let ksPos = keystreamOffset;
        while (remaining > 0) {
            const blockIdx = (ksPos / this.blockSize) | 0;
            const inBlockOffset = ksPos % this.blockSize;
            const block = this.getBlock(blockIdx);
            const take = Math.min(this.blockSize - inBlockOffset, remaining);
            if ((inBlockOffset & 3) === 0 && (inPos & 3) === 0) {
                const words = take >> 2;
                const blockU32 = new Uint32Array(block.buffer, block.byteOffset + inBlockOffset, words);
                const inU32 = new Uint32Array(input.buffer, input.byteOffset + inPos, words);
                const outU32 = new Uint32Array(output.buffer, output.byteOffset + inPos, words);
                for (let w = 0; w < words; w++) outU32[w] = blockU32[w] ^ inU32[w];
                const tail = take & 3;
                const base = words << 2;
                for (let i = 0; i < tail; i++) output[inPos + base + i] = input[inPos + base + i] ^ block[inBlockOffset + base + i];
            } else {
                for (let i = 0; i < take; i++) output[inPos + i] = input[inPos + i] ^ block[inBlockOffset + i];
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
        if (this.cachedBlocks.size >= this.maxCacheBlocks) {
            const first = this.cacheQueue.shift()!;
            this.cachedBlocks.delete(first);
        }
        this.cachedBlocks.set(idx, block);
        this.cacheQueue.push(idx);
        return block;
    }

    /**
     * Clear cache
     */
    public clearCache(): void {
        this.cachedBlocks.clear();
        this.cacheQueue.length = 0;
    }

    /**
     * Set cache limit
     * @param n {number} Limit
     */
    public setCacheLimit(n: number): void {
        this.maxCacheBlocks = n;
    }
}
