import crypto from "crypto";
import {SHA256, SHA512} from "../src/hash/sha";
import {Shake256, Shake256Wasm, isWasmShake} from "../src/hash/shake";
import {QuarkDashMAC} from "../src/core/mac";
import {QuarkDashUtils} from "../src/core/utils";
import {BaseRingLWE} from "../src/session/baselwe";
import {QuarkDashRRLWE} from "../src/session/rringlwe";
import {QuarkDashKDF} from "../src/core/kdf";
import {QuarkDashChaCha, QuarkDashGimli} from "../src";

function hex(b: Uint8Array){ return Buffer.from(b).toString('hex'); }

describe("SHA critical", () => {
  test("SHA256 known vectors", () => {
    const vectors: [string,string][] = [
      ["", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"],
      ["abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"],
      ["The quick brown fox jumps over the lazy dog", "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"],
    ];
    for(const [msg,exp] of vectors){
      const got = SHA256.hash(msg,true) as Uint8Array;
      expect(hex(got)).toBe(exp);
      expect(hex(got)).toBe(crypto.createHash('sha256').update(msg).digest('hex'));
    }
  });
  test("SHA256 padding edge 55/56", () => {
    for(const n of [55,56,63,64,127,128]){
      const msg='a'.repeat(n);
      const got = hex(SHA256.hash(msg,true) as Uint8Array);
      const exp = crypto.createHash('sha256').update(msg).digest('hex');
      expect(got).toBe(exp);
    }
  });
  test("SHA512 vectors and edge 111/112", () => {
    const msgs = ["", "abc", 'a'.repeat(111), 'a'.repeat(112), 'a'.repeat(128)];
    for(const msg of msgs){
      const got = hex(SHA512.hash(msg,true) as Uint8Array);
      const exp = crypto.createHash('sha512').update(msg).digest('hex');
      expect(got).toBe(exp);
    }
  });
  test("SHA256 handles Uint8Array input", () => {
    const data = new TextEncoder().encode("hello");
    const got = hex(SHA256.hash(data,true) as Uint8Array);
    const exp = crypto.createHash('sha256').update(Buffer.from(data)).digest('hex');
    expect(got).toBe(exp);
  });
});

describe("SHAKE256 critical", () => {
  test("empty vector 32 and 64", () => {
    const empty32 = hex(Shake256.hashSync(new Uint8Array(0),32));
    const exp32 = crypto.createHash('shake256',{outputLength:32} as any).update(Buffer.alloc(0)).digest('hex');
    expect(empty32).toBe(exp32);
    expect(empty32).toBe("46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f");
    const empty64 = hex(Shake256.hashSync(new Uint8Array(0),64));
    const exp64 = crypto.createHash('shake256',{outputLength:64} as any).update(Buffer.alloc(0)).digest('hex');
    expect(empty64).toBe(exp64);
  });
  test("abc, 135,136, rate boundaries", () => {
    for(const [len,msg] of [[3,'abc'],[135,'a'.repeat(135)],[136,'a'.repeat(136)],[137,'a'.repeat(137)]] as any){
      const data = new TextEncoder().encode(msg);
      const got = hex(Shake256.hashSync(data,32));
      const exp = crypto.createHash('shake256',{outputLength:32} as any).update(Buffer.from(data)).digest('hex');
      expect(got).toBe(exp);
    }
  });
  test("squeeze multi-block output 200 bytes", () => {
    const data = new TextEncoder().encode("test");
    const got = hex(Shake256.hashSync(data,200));
    const exp = crypto.createHash('shake256',{outputLength:200} as any).update(Buffer.from(data)).digest('hex');
    expect(got).toBe(exp);
  });
  test("async vs sync equivalence", async () => {
    const data = QuarkDashUtils.randomBytes(100);
    const a = await Shake256.hash(data, 64);
    const b = Shake256.hashSync(data, 64);
    expect(a).toEqual(b);
  });
  test("KeccakState absorb/extract roundtrip", () => {
    const data = new Uint8Array([1,2,3]);
    const out = Shake256.hashSync(data, 10);
    expect(out.length).toBe(10);
    expect(out).not.toEqual(new Uint8Array(10));
  });
});

describe("MAC critical", () => {
  test("sign/verify roundtrip", async () => {
    const mac = new QuarkDashMAC();
    const key = QuarkDashUtils.randomBytes(32);
    const data = QuarkDashUtils.randomBytes(100);
    const tag = await mac.sign(data, key);
    expect(tag.length).toBe(32);
    expect(await mac.verify(data, key, tag)).toBe(true);
    expect(mac.verifySync(data, key, tag)).toBe(true);
  });
  test("signTwo equals concat", async () => {
    const mac = new QuarkDashMAC();
    const key = QuarkDashUtils.randomBytes(32);
    const d1 = QuarkDashUtils.randomBytes(20);
    const d2 = QuarkDashUtils.randomBytes(30);
    const tag1 = await mac.sign(QuarkDashUtils.concatBytes(d1,d2), key);
    const tag2 = await mac.signTwo(d1,d2,key);
    expect(tag1).toEqual(tag2);
    const tag1s = mac.signSync(QuarkDashUtils.concatBytes(d1,d2), key);
    const tag2s = mac.signTwoSync(d1,d2,key);
    expect(tag1s).toEqual(tag2s);
    expect(tag1).toEqual(tag1s);
  });
  test("verify fails on tampered tag or data", async () => {
    const mac = new QuarkDashMAC();
    const key = QuarkDashUtils.randomBytes(32);
    const data = new TextEncoder().encode("hello");
    const tag = await mac.sign(data, key);
    const badTag = new Uint8Array(tag); badTag[0]^=0xff;
    expect(await mac.verify(data, key, badTag)).toBe(false);
    const badData = new Uint8Array(data); badData[0]^=1;
    expect(await mac.verify(badData, key, tag)).toBe(false);
    const otherKey = QuarkDashUtils.randomBytes(32);
    expect(await mac.verify(data, otherKey, tag)).toBe(false);
  });
  test("constantTimeEqual", () => {
    expect(QuarkDashUtils.constantTimeEqual(new Uint8Array([1,2]), new Uint8Array([1,2]))).toBe(true);
    expect(QuarkDashUtils.constantTimeEqual(new Uint8Array([1,2]), new Uint8Array([1,3]))).toBe(false);
    expect(QuarkDashUtils.constantTimeEqual(new Uint8Array([1]), new Uint8Array([1,2]))).toBe(false);
  });
  test("tempBuffer reallocation for large signTwo", async () => {
    const mac = new QuarkDashMAC();
    const key = QuarkDashUtils.randomBytes(32);
    const d1 = QuarkDashUtils.randomBytes(40000);
    const d2 = QuarkDashUtils.randomBytes(40000);
    const tag = await mac.signTwo(d1,d2,key);
    expect(tag.length).toBe(32);
    const expected = Shake256.hashSync(QuarkDashUtils.concatBytes(key,d1,d2),32);
    expect(tag).toEqual(expected);
  });
  test("sync vs async consistency", async () => {
    const mac = new QuarkDashMAC();
    const key = QuarkDashUtils.randomBytes(32);
    const data = QuarkDashUtils.randomBytes(50);
    const asyncTag = await mac.sign(data, key);
    const syncTag = mac.signSync(data, key);
    expect(asyncTag).toEqual(syncTag);
  });
});

describe("KDF critical", () => {
  test("deriveSync not zero and deterministic", () => {
    const kdf = new QuarkDashKDF();
    const ikm = new TextEncoder().encode("input");
    const salt = new TextEncoder().encode("salt");
    const info = new TextEncoder().encode("info");
    const out1 = kdf.deriveSync(ikm,salt,info,64);
    const out2 = kdf.deriveSync(ikm,salt,info,64);
    expect(out1).toEqual(out2);
    expect(out1.every(b=>b===0)).toBe(false);
    expect(out1.length).toBe(64);
    const outLong = kdf.deriveSync(ikm,salt,info,100);
    expect(outLong.length).toBe(100);
    expect(outLong.slice(0,64)).toEqual(out1);
  });
  test("derive async equals sync", async () => {
    const kdf = new QuarkDashKDF();
    const ikm = QuarkDashUtils.randomBytes(20);
    const salt = QuarkDashUtils.randomBytes(20);
    const info = QuarkDashUtils.randomBytes(10);
    const a = await kdf.derive(ikm,salt,info,64);
    const b = kdf.deriveSync(ikm,salt,info,64);
    expect(a).toEqual(b);
  });
});

describe("NTT critical", () => {
  test("ntt/invNTT roundtrip", () => {
    const lwe = new BaseRingLWE() as any;
    const poly = Array.from({length:256}, (_,i)=>BigInt(i % 7681));
    const ntt = lwe.ntt(poly);
    const inv = lwe.invNTT(ntt);
    for(let i=0;i<256;i++) expect(inv[i].toString()).toBe(((poly[i]%7681n+7681n)%7681n).toString());
    const hntt = lwe.hardenedNTT(poly);
    const hinv = lwe.hardenedInvNTT(hntt);
    for(let i=0;i<256;i++) expect(hinv[i].toString()).toBe(((poly[i]%7681n+7681n)%7681n).toString());
  });
  test("secureMultiply equals naive cyclic", () => {
    const lwe = new BaseRingLWE() as any;
    lwe.setNTTProtection({blinding:false,doubleCheck:false});
    const a=[1n,2n,3n,4n].concat(Array(252).fill(0n));
    const b=[5n,6n,7n,8n].concat(Array(252).fill(0n));
    const r = lwe.secureMultiply(a,b);
    const naive = new Array(256).fill(0n);
    const Q=7681n;
    for(let i=0;i<256;i++) for(let j=0;j<256;j++) naive[(i+j)%256]=(naive[(i+j)%256]+a[i]*b[j])%Q;
    expect(r.map(String)).toEqual(naive.map(String));
  });
  test("blinding preserves product", () => {
    const lwe = new BaseRingLWE() as any;
    lwe.setNTTProtection({blinding:false,doubleCheck:false});
    const a=Array.from({length:256},()=>BigInt(Math.floor(Math.random()*7681)));
    const b=Array.from({length:256},()=>BigInt(Math.floor(Math.random()*7681)));
    const r1=lwe.secureMultiply(a,b);
    lwe.setNTTProtection({blinding:true,doubleCheck:false});
    const r2=lwe.secureMultiply(a,b);
    expect(r1.map(String)).toEqual(r2.map(String));
  });
  test("doubleCheck detects no fault", () => {
    const lwe = new BaseRingLWE() as any;
    lwe.setNTTProtection({doubleCheck:true,blinding:false});
    const a=Array.from({length:256},()=>BigInt(Math.floor(Math.random()*100)));
    const b=Array.from({length:256},()=>BigInt(Math.floor(Math.random()*100)));
    expect(()=>lwe.secureMultiply(a,b)).not.toThrow();
  });
  test("validatePoly rejects out of range when enabled", () => {
    const lwe = new BaseRingLWE() as any;
    lwe.setNTTProtection({validateInputs:true});
    const bad = Array(256).fill(0n); bad[0]=8000n;
    expect(()=>lwe.validatePoly(bad)).toThrow();
    lwe.setNTTProtection({validateInputs:false});
    expect(()=>lwe.validatePoly(bad)).not.toThrow();
  });
  test("getWlen caching and inv", () => {
    const lwe = new BaseRingLWE() as any;
    const w2: bigint=lwe.getWlen(2);
    const inv: bigint=lwe.getInvWlen(2);
    expect((w2*inv) % 7681n).toBe(1n);
    expect(lwe.getWlen(2)).toBe(w2);
  });
  test("RRLWE also roundtrips", () => {
    const lwe = new QuarkDashRRLWE() as any;
    const poly=Array.from({length:256},(_,i)=>BigInt(i%12289));
    const ntt=lwe.ntt(poly);
    const inv=lwe.invNTT(ntt);
    for(let i=0;i<256;i++) expect(inv[i].toString()).toBe(((poly[i]%12289n+12289n)%12289n).toString());
  });
  test("encaps/decaps with hint succeeds", () => {
    const lwe = new BaseRingLWE() as any;
    for(let t=0;t<20;t++){
      const kp=lwe.generateKeyPairSync();
      const ct=lwe.encapsulateSync(kp.publicKey);
      expect(ct.ciphertext.length).toBe(512+32);
      const ss2=lwe.decapsulateSync(kp.privateKey,kp.publicKey,ct.ciphertext);
      expect(Buffer.from(ct.sharedSecret).equals(Buffer.from(ss2))).toBe(true);
    }
  });
  test("invalid public key / ciphertext throws", () => {
    const lwe=new BaseRingLWE() as any;
    expect(()=>lwe.validatePublicKey(new Uint8Array(10))).toThrow();
    expect(()=>lwe.validateCiphertext(new Uint8Array(10))).toThrow();
  });
});

describe("WASM fallback & optimized APIs", () => {
  test("hashMulti equals concat", () => {
    const a=QuarkDashUtils.randomBytes(100);
    const b=QuarkDashUtils.randomBytes(200);
    const c=QuarkDashUtils.randomBytes(50);
    const concat = QuarkDashUtils.concatBytes(a,b,c);
    const h1 = Shake256.hashSync(concat, 32);
    const h2 = Shake256.hashMultiSync([a,b,c], 32);
    expect(h1).toEqual(h2);
  });
  test("hashMulti async equals sync", async () => {
    const a=QuarkDashUtils.randomBytes(64);
    const b=QuarkDashUtils.randomBytes(64);
    const h1 = await Shake256.hashMulti([a,b], 64);
    const h2 = Shake256.hashMultiSync([a,b], 64);
    expect(h1).toEqual(h2);
  });
  test("WASM vs JS same output (if available) and fallback", async () => {
    const data = QuarkDashUtils.randomBytes(1024);
    const js = Shake256.hashSync(data, 32);
    try{ await Shake256Wasm.initWasm("./wasm/shake.wasm"); }catch{}
    if(isWasmShake()){
      const wasm = Shake256Wasm.shake256Wasm(data, 32);
      expect(wasm).toEqual(js);
      expect(hex(wasm)).toBe(crypto.createHash('shake256',{outputLength:32} as any).update(Buffer.from(data)).digest('hex'));
      (Shake256Wasm as any).initializedWasm=false;
      const fallback = Shake256Wasm.shake256Wasm(data, 32);
      expect(fallback).toEqual(js);
    } else {
      const fallback = Shake256Wasm.shake256Wasm(data, 32);
      expect(fallback).toEqual(js);
    }
  });
  test("WASM fallback for signTwo large data", async () => {
    const mac=new QuarkDashMAC();
    const key=QuarkDashUtils.randomBytes(32);
    const d1=QuarkDashUtils.randomBytes(1000);
    const d2=QuarkDashUtils.randomBytes(1000);
    // force JS path
    (Shake256Wasm as any).initializedWasm=false;
    const t1=await mac.signTwo(d1,d2,key);
    const t2=mac.signTwoSync(d1,d2,key);
    expect(t1).toEqual(t2);
    // try WASM path if available
    try{ await Shake256Wasm.initWasm("./wasm/shake.wasm"); if(isWasmShake()){ const t3=await mac.signTwo(d1,d2,key); expect(t3).toEqual(t1); } }catch{}
  });
  test("ChaCha/Gimli bulk XOR correctness after optimization", () => {
    const key=QuarkDashUtils.randomBytes(32);
    const nonce=QuarkDashUtils.randomBytes(12);
    const cc=new QuarkDashChaCha(key, nonce);
    const data=QuarkDashUtils.randomBytes(5000);
    const out=cc.encryptSync(data);
    const ks=cc.createKeystream();
    const out2=ks.xor(data,0);
    expect(out).toEqual(out2);
    // test unaligned offset bulk path
    const off=5;
    const out3=ks.xor(data,off);
    const ref=cc.createKeystream().xor(data,off);
    expect(out3).toEqual(ref);
    const gm=new QuarkDashGimli(key, nonce);
    const gout=gm.encryptSync(data);
    const gks=gm.createKeystream();
    expect(gks.xor(gout,0)).toEqual(data);
  });
});
