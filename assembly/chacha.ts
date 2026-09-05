/**
 * QuarkDash ChaCha Assemblyscript Implementation
 *
 * @git             https://github.com/devsdaddy/quarkdash
 * @version         1.1.0
 * @author          Elijah Rastorguev
 * @build           1008
 * @website         https://dev.to/devsdaddy
 * @updated         28.08.2026
 */
/**
 * Rotl
 * @param v
 * @param n
 */
function rotl(v: u32, n: u32): u32 {
    return (v << n) | (v >>> (32 - n));
}

/**
 * ChaCha Block
 * @param keyPtr
 * @param noncePtr
 * @param blockIndex
 * @param outPtr
 */
export function chacha_block(keyPtr: usize, noncePtr: usize, blockIndex: u32, outPtr: usize): void {
    let s0: u32 = 0x61707865;
    let s1: u32 = 0x3320646e;
    let s2: u32 = 0x79622d32;
    let s3: u32 = 0x6b206574;
    let s4: u32 = load<u32>(keyPtr);
    let s5: u32 = load<u32>(keyPtr + 4);
    let s6: u32 = load<u32>(keyPtr + 8);
    let s7: u32 = load<u32>(keyPtr + 12);
    let s8: u32 = load<u32>(keyPtr + 16);
    let s9: u32 = load<u32>(keyPtr + 20);
    let s10: u32 = load<u32>(keyPtr + 24);
    let s11: u32 = load<u32>(keyPtr + 28);
    let s12: u32 = blockIndex;
    let s13: u32 = load<u32>(noncePtr);
    let s14: u32 = load<u32>(noncePtr + 4);
    let s15: u32 = load<u32>(noncePtr + 8);
    let w0: u32 = s0, w1: u32 = s1, w2: u32 = s2, w3: u32 = s3,
        w4: u32 = s4, w5: u32 = s5, w6: u32 = s6, w7: u32 = s7,
        w8: u32 = s8, w9: u32 = s9, w10: u32 = s10, w11: u32 = s11,
        w12: u32 = s12, w13: u32 = s13, w14: u32 = s14, w15: u32 = s15;
    for (let r: u32 = 0; r < 10; r++) {
        let a0: u32 = w0, b0: u32 = w4, c0: u32 = w8, d0: u32 = w12;
        a0 += b0;
        d0 ^= a0;
        d0 = rotl(d0, 16);
        c0 += d0;
        b0 ^= c0;
        b0 = rotl(b0, 12);
        a0 += b0;
        d0 ^= a0;
        d0 = rotl(d0, 8);
        c0 += d0;
        b0 ^= c0;
        b0 = rotl(b0, 7);
        w0 = a0;
        w4 = b0;
        w8 = c0;
        w12 = d0;
        let a1: u32 = w1, b1: u32 = w5, c1: u32 = w9, d1: u32 = w13;
        a1 += b1;
        d1 ^= a1;
        d1 = rotl(d1, 16);
        c1 += d1;
        b1 ^= c1;
        b1 = rotl(b1, 12);
        a1 += b1;
        d1 ^= a1;
        d1 = rotl(d1, 8);
        c1 += d1;
        b1 ^= c1;
        b1 = rotl(b1, 7);
        w1 = a1;
        w5 = b1;
        w9 = c1;
        w13 = d1;
        let a2: u32 = w2, b2: u32 = w6, c2: u32 = w10, d2: u32 = w14;
        a2 += b2;
        d2 ^= a2;
        d2 = rotl(d2, 16);
        c2 += d2;
        b2 ^= c2;
        b2 = rotl(b2, 12);
        a2 += b2;
        d2 ^= a2;
        d2 = rotl(d2, 8);
        c2 += d2;
        b2 ^= c2;
        b2 = rotl(b2, 7);
        w2 = a2;
        w6 = b2;
        w10 = c2;
        w14 = d2;
        let a3: u32 = w3, b3: u32 = w7, c3: u32 = w11, d3: u32 = w15;
        a3 += b3;
        d3 ^= a3;
        d3 = rotl(d3, 16);
        c3 += d3;
        b3 ^= c3;
        b3 = rotl(b3, 12);
        a3 += b3;
        d3 ^= a3;
        d3 = rotl(d3, 8);
        c3 += d3;
        b3 ^= c3;
        b3 = rotl(b3, 7);
        w3 = a3;
        w7 = b3;
        w11 = c3;
        w15 = d3;
        let a4: u32 = w0, b4: u32 = w5, c4: u32 = w10, d4: u32 = w15;
        a4 += b4;
        d4 ^= a4;
        d4 = rotl(d4, 16);
        c4 += d4;
        b4 ^= c4;
        b4 = rotl(b4, 12);
        a4 += b4;
        d4 ^= a4;
        d4 = rotl(d4, 8);
        c4 += d4;
        b4 ^= c4;
        b4 = rotl(b4, 7);
        w0 = a4;
        w5 = b4;
        w10 = c4;
        w15 = d4;
        let a5: u32 = w1, b5: u32 = w6, c5: u32 = w11, d5: u32 = w12;
        a5 += b5;
        d5 ^= a5;
        d5 = rotl(d5, 16);
        c5 += d5;
        b5 ^= c5;
        b5 = rotl(b5, 12);
        a5 += b5;
        d5 ^= a5;
        d5 = rotl(d5, 8);
        c5 += d5;
        b5 ^= c5;
        b5 = rotl(b5, 7);
        w1 = a5;
        w6 = b5;
        w11 = c5;
        w12 = d5;
        let a6: u32 = w2, b6: u32 = w7, c6: u32 = w8, d6: u32 = w13;
        a6 += b6;
        d6 ^= a6;
        d6 = rotl(d6, 16);
        c6 += d6;
        b6 ^= c6;
        b6 = rotl(b6, 12);
        a6 += b6;
        d6 ^= a6;
        d6 = rotl(d6, 8);
        c6 += d6;
        b6 ^= c6;
        b6 = rotl(b6, 7);
        w2 = a6;
        w7 = b6;
        w8 = c6;
        w13 = d6;
        let a7: u32 = w3, b7: u32 = w4, c7: u32 = w9, d7: u32 = w14;
        a7 += b7;
        d7 ^= a7;
        d7 = rotl(d7, 16);
        c7 += d7;
        b7 ^= c7;
        b7 = rotl(b7, 12);
        a7 += b7;
        d7 ^= a7;
        d7 = rotl(d7, 8);
        c7 += d7;
        b7 ^= c7;
        b7 = rotl(b7, 7);
        w3 = a7;
        w4 = b7;
        w9 = c7;
        w14 = d7;
    }
    w0 += s0;
    w1 += s1;
    w2 += s2;
    w3 += s3;
    w4 += s4;
    w5 += s5;
    w6 += s6;
    w7 += s7;
    w8 += s8;
    w9 += s9;
    w10 += s10;
    w11 += s11;
    w12 += s12;
    w13 += s13;
    w14 += s14;
    w15 += s15;
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
    store<u32>(outPtr + 48, w12);
    store<u32>(outPtr + 52, w13);
    store<u32>(outPtr + 56, w14);
    store<u32>(outPtr + 60, w15);
}

/**
 * ChaCha XOR
 * @param keyPtr
 * @param noncePtr
 * @param dataPtr
 * @param outPtr
 * @param dataLen
 * @param offset
 */
export function chacha_xor(keyPtr: usize, noncePtr: usize, dataPtr: usize, outPtr: usize, dataLen: u32, offset: u32): void {
    let blockIdx: u32 = offset / 64;
    let blockOff: u32 = offset % 64;
    let pos: u32 = 0;
    let tmp: usize = outPtr + dataLen + 32;
    while (pos < dataLen) {
        chacha_block(keyPtr, noncePtr, blockIdx, tmp);
        let take: u32 = 64 - blockOff;
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
        for (; i < take; i++) store<u8>(dst + i, load<u8>(src + i) ^ load<u8>(inp + i));
        pos += take;
        blockIdx++;
        blockOff = 0;
    }
}
