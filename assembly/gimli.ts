/**
 * QuarkDash Gimli Assemblyscript Implementation
 *
 * @git             https://github.com/devsdaddy/quarkdash
 * @version         1.1.0
 * @author          Elijah Rastorguev
 * @build           1008
 * @website         https://dev.to/devsdaddy
 * @updated         28.08.2026
 */
/**
 * Gimli Block
 * @param keyPtr
 * @param noncePtr
 * @param blockIndex
 * @param outPtr
 */
export function gimli_block(keyPtr: usize, noncePtr: usize, blockIndex: u32, outPtr: usize): void {
    let w0: u32 = load<u32>(keyPtr);
    let w1: u32 = load<u32>(keyPtr + 4);
    let w2: u32 = load<u32>(keyPtr + 8);
    let w3: u32 = load<u32>(keyPtr + 12);
    let w4: u32 = load<u32>(keyPtr + 16);
    let w5: u32 = load<u32>(keyPtr + 20);
    let w6: u32 = load<u32>(keyPtr + 24);
    let w7: u32 = load<u32>(keyPtr + 28);
    let w8: u32 = load<u32>(noncePtr);
    let w9: u32 = load<u32>(noncePtr + 4);
    let w10: u32 = load<u32>(noncePtr + 8);
    let w11: u32 = blockIndex;
    for (let round: u32 = 0; round < 24; round++) {
        let x0: u32 = w0, y0: u32 = w4, z0: u32 = w8;
        w0 = x0 ^ (z0 << 1) ^ ((y0 & z0) << 2);
        w4 = y0 ^ x0 ^ ((x0 | z0) << 1);
        w8 = z0 ^ y0 ^ ((x0 & y0) << 3);
        let x1: u32 = w1, y1: u32 = w5, z1: u32 = w9;
        w1 = x1 ^ (z1 << 1) ^ ((y1 & z1) << 2);
        w5 = y1 ^ x1 ^ ((x1 | z1) << 1);
        w9 = z1 ^ y1 ^ ((x1 & y1) << 3);
        let x2: u32 = w2, y2: u32 = w6, z2: u32 = w10;
        w2 = x2 ^ (z2 << 1) ^ ((y2 & z2) << 2);
        w6 = y2 ^ x2 ^ ((x2 | z2) << 1);
        w10 = z2 ^ y2 ^ ((x2 & y2) << 3);
        let x3: u32 = w3, y3: u32 = w7, z3: u32 = w11;
        w3 = x3 ^ (z3 << 1) ^ ((y3 & z3) << 2);
        w7 = y3 ^ x3 ^ ((x3 | z3) << 1);
        w11 = z3 ^ y3 ^ ((x3 & y3) << 3);
        let t: u32 = w1;
        w1 = w2;
        w2 = w3;
        w3 = t;
        if ((round & 3) == 0) w0 ^= (0x9e377900 | round);
    }
    store<u32>(outPtr, w0);
    store<u32>(outPtr + 4, w1);
    store<u32>(outPtr + 8, w2);
    store<u32>(outPtr + 12, w3);
    store<u32>(outPtr + 16, w4);
    store<u32>(outPtr + 20, w5);
    store<u32>(outPtr + 24, w6);
    store<u32>(outPtr + 28, w7);
    store<u32>(outPtr + 32, w8);
    store<u32>(outPtr + 36, w9);
    store<u32>(outPtr + 40, w10);
    store<u32>(outPtr + 44, w11);
}

/**
 * Gimli XOR
 * @param keyPtr
 * @param noncePtr
 * @param dataPtr
 * @param outPtr
 * @param dataLen
 * @param offset
 */
export function gimli_xor(keyPtr: usize, noncePtr: usize, dataPtr: usize, outPtr: usize, dataLen: u32, offset: u32): void {
    let blockIdx: u32 = offset / 48;
    let blockOff: u32 = offset % 48;
    let pos: u32 = 0;
    let tmp: usize = outPtr + dataLen + 32;
    while (pos < dataLen) {
        gimli_block(keyPtr, noncePtr, blockIdx, tmp);
        let take: u32 = 48 - blockOff;
        if (take > dataLen - pos) take = dataLen - pos;
        let src: usize = tmp + blockOff;
        let dst: usize = outPtr + pos;
        let inp: usize = dataPtr + pos;
        let i: u32 = 0;
        for (; i + 16 <= take; i += 16) {
            let k = v128.load(src + i);
            let d = v128.load(inp + i);
            v128.store(dst + i, v128.xor(k, d));
        }
        for (; i + 4 <= take; i += 4) {
            let kv = load<u32>(src + i);
            let dv = load<u32>(inp + i);
            store<u32>(dst + i, kv ^ dv);
        }
        for (; i < take; i++) {
            store<u8>(dst + i, load<u8>(src + i) ^ load<u8>(inp + i));
        }
        pos += take;
        blockIdx++;
        blockOff = 0;
    }
}
