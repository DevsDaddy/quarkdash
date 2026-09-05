/**
 * QuarkDash NTT Assemblyscript Implementation
 *
 * @git             https://github.com/devsdaddy/quarkdash
 * @version         1.1.0
 * @author          Elijah Rastorguev
 * @build           1008
 * @website         https://dev.to/devsdaddy
 * @updated         28.08.2026
 */
const N: u32 = 256;

/**
 * Mod POW
 * @param base
 * @param exp
 * @param mod
 */
function modPow(base: u32, exp: u32, mod: u32): u32 {
  let res: u64 = 1;
  let b: u64 = base % mod;
  let e: u32 = exp;
  while (e > 0) {
    if (e & 1) res = (res * b) % mod;
    b = (b * b) % mod;
    e >>= 1;
  }
  return res as u32;
}

/**
 * MOD Inv
 * @param a
 * @param m
 */
function modInv(a: u32, m: u32): u32 {
  let old_r: i32 = a as i32, r: i32 = m as i32;
  let old_s: i32 = 1, s: i32 = 0;
  while (r != 0) {
    let q: i32 = old_r / r;
    let tmp: i32 = r; r = old_r - q * r; old_r = tmp;
    tmp = s; s = old_s - q * s; old_s = tmp;
  }
  let res: i32 = old_s % (m as i32);
  if (res < 0) res += m as i32;
  return res as u32;
}

/**
 * Bit reverse in place
 * @param ptr
 */
function bitReverseInPlace(ptr: usize): void {
  let j: u32 = 0;
  for (let i: u32 = 1; i < N; i++) {
    let bit: u32 = N >> 1;
    while ((j & bit) != 0) { j ^= bit; bit >>= 1; }
    j ^= bit;
    if (i < j) {
      let ai: u32 = load<u32>(ptr + (i << 2));
      let aj: u32 = load<u32>(ptr + (j << 2));
      store<u32>(ptr + (i << 2), aj);
      store<u32>(ptr + (j << 2), ai);
    }
  }
}

/**
 * NTT Calculation
 * @param inPtr
 * @param outPtr
 * @param q
 * @param root
 */
export function ntt(inPtr: usize, outPtr: usize, q: u32, root: u32): void {
  for (let i: u32 = 0; i < N; i++) store<u32>(outPtr + (i << 2), load<u32>(inPtr + (i << 2)) % q);
  bitReverseInPlace(outPtr);
  let len: u32 = 2;
  while (len <= N) {
    let wlen: u32 = modPow(root, N / len, q);
    for (let i: u32 = 0; i < N; i += len) {
      let w: u32 = 1;
      for (let j: u32 = 0; j < len >> 1; j++) {
        let u: u32 = load<u32>(outPtr + ((i + j) << 2));
        let v: u32 = (load<u32>(outPtr + ((i + j + (len >> 1)) << 2)) * w) % q;
        store<u32>(outPtr + ((i + j) << 2), (u + v) % q);
        store<u32>(outPtr + ((i + j + (len >> 1)) << 2), (u + q - v) % q);
        w = (w * wlen) % q;
      }
    }
    len <<= 1;
  }
}

/**
 * Inv NTT Calculation
 * @param inPtr
 * @param outPtr
 * @param q
 * @param root
 * @param invN
 */
export function inv_ntt(inPtr: usize, outPtr: usize, q: u32, root: u32, invN: u32): void {
  for (let i: u32 = 0; i < N; i++) store<u32>(outPtr + (i << 2), load<u32>(inPtr + (i << 2)) % q);
  bitReverseInPlace(outPtr);
  let len: u32 = 2;
  while (len <= N) {
    let wlen: u32 = modInv(modPow(root, N / len, q), q);
    for (let i: u32 = 0; i < N; i += len) {
      let w: u32 = 1;
      for (let j: u32 = 0; j < len >> 1; j++) {
        let u: u32 = load<u32>(outPtr + ((i + j) << 2));
        let v: u32 = (load<u32>(outPtr + ((i + j + (len >> 1)) << 2)) * w) % q;
        store<u32>(outPtr + ((i + j) << 2), (u + v) % q);
        store<u32>(outPtr + ((i + j + (len >> 1)) << 2), (u + q - v) % q);
        w = (w * wlen) % q;
      }
    }
    len <<= 1;
  }
  for (let i: u32 = 0; i < N; i++) {
    let v: u32 = load<u32>(outPtr + (i << 2));
    store<u32>(outPtr + (i << 2), (v * invN) % q);
  }
}

/**
 * Multiply
 * @param aPtr
 * @param bPtr
 * @param outPtr
 * @param q
 * @param root
 * @param invN
 */
export function multiply(aPtr: usize, bPtr: usize, outPtr: usize, q: u32, root: u32, invN: u32): void {
  let tmpA: usize = outPtr + 2048;
  let tmpB: usize = tmpA + 1024;
  let tmpC: usize = tmpB + 1024;
  ntt(aPtr, tmpA, q, root);
  ntt(bPtr, tmpB, q, root);
  pointwise_mul(tmpA, tmpB, tmpC, q, N);
  inv_ntt(tmpC, outPtr, q, root, invN);
}

/**
 * Pointwise multiplication
 * @param aPtr
 * @param bPtr
 * @param outPtr
 * @param q
 * @param len
 */
export function pointwise_mul(aPtr: usize, bPtr: usize, outPtr: usize, q: u32, len: u32): void {
  let i: u32 = 0;
  for (; i + 4 <= len; i += 4) {
    let a0: u32 = load<u32>(aPtr + (i << 2)); let b0: u32 = load<u32>(bPtr + (i << 2)); store<u32>(outPtr + (i << 2), (a0 * b0) % q);
    let a1: u32 = load<u32>(aPtr + ((i+1) << 2)); let b1: u32 = load<u32>(bPtr + ((i+1) << 2)); store<u32>(outPtr + ((i+1) << 2), (a1 * b1) % q);
    let a2: u32 = load<u32>(aPtr + ((i+2) << 2)); let b2: u32 = load<u32>(bPtr + ((i+2) << 2)); store<u32>(outPtr + ((i+2) << 2), (a2 * b2) % q);
    let a3: u32 = load<u32>(aPtr + ((i+3) << 2)); let b3: u32 = load<u32>(bPtr + ((i+3) << 2)); store<u32>(outPtr + ((i+3) << 2), (a3 * b3) % q);
  }
  for (; i < len; i++) {
    let av: u32 = load<u32>(aPtr + (i << 2)); let bv: u32 = load<u32>(bPtr + (i << 2)); store<u32>(outPtr + (i << 2), (av * bv) % q);
  }
}

/**
 * Bulk XOR
 * @param dataPtr
 * @param keystreamPtr
 * @param outPtr
 * @param len
 */
export function bulk_xor(dataPtr: usize, keystreamPtr: usize, outPtr: usize, len: u32): void {
  let i: u32 = 0;
  for (; i + 16 <= len; i += 16) {
    let d = v128.load(dataPtr + i);
    let k = v128.load(keystreamPtr + i);
    v128.store(outPtr + i, v128.xor(d, k));
  }
  for (; i + 4 <= len; i += 4) {
    store<u32>(outPtr + i, load<u32>(dataPtr + i) ^ load<u32>(keystreamPtr + i));
  }
  for (; i < len; i++) store<u8>(outPtr + i, load<u8>(dataPtr + i) ^ load<u8>(keystreamPtr + i));
}
