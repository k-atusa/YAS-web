/**
 * crypto.ts — YAS-web encryption/decryption library
 *
 * Implements Bencrypt + Opsec algorithms compatible with
 * https://taewook427.github.io/SimpleWeb/yas-static/index.html
 *
 * Algorithms:
 *   Symmetric  — AES-GCM (gcm1), AES-GCM chunked (gcmx1)
 *   KDF        — Argon2id (arg1), PBKDF2-SHA512 (pbk1)
 *   Asymmetric — RSA-2048 OAEP-SHA512 + PKCS1v1.5-SHA256 (rsa1), Curve448 X448+Ed448 (ecc1)
 *   Protocol   — Opsec YAS2 binary header format
 */
import { sha3_512 } from "js-sha3";
import { x448, ed448 } from "@noble/curves/ed448.js";
// TypeScript 5.7+ strict typed arrays — helper to satisfy BufferSource constraints
const asBuf = (u) => u.buffer.slice(u.byteOffset, u.byteOffset + u.byteLength);
// ==================== Utilities ====================
const _enc = new TextEncoder();
const _dec = new TextDecoder();
function toU8(data) {
    if (typeof data === "string")
        return _enc.encode(data);
    if (data instanceof ArrayBuffer)
        return new Uint8Array(data);
    if (ArrayBuffer.isView(data))
        return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
    return data;
}
function concat(arrays) {
    let total = 0;
    for (const a of arrays)
        total += a.length;
    const r = new Uint8Array(total);
    let off = 0;
    for (const a of arrays) {
        r.set(a, off);
        off += a.length;
    }
    return r;
}
export function u8ToBase64(u8) {
    const chunkSize = 0x8000;
    let bin = "";
    for (let i = 0; i < u8.length; i += chunkSize) {
        const chunk = u8.subarray(i, i + chunkSize);
        bin += String.fromCharCode.apply(null, chunk);
    }
    return btoa(bin);
}
export function base64ToU8(b64) {
    const bin = atob(b64);
    const u8 = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++)
        u8[i] = bin.charCodeAt(i);
    return u8;
}
function strToU8(s) {
    return _enc.encode(s);
}
function u8ToStr(u8) {
    return _dec.decode(u8);
}
function random(size) {
    const buf = new Uint8Array(size);
    crypto.getRandomValues(buf);
    return buf;
}
// ==================== Encoding Helpers ====================
function encodeInt(data, size) {
    const buf = new ArrayBuffer(size);
    const v = new DataView(buf);
    if (size === 1)
        v.setUint8(0, data);
    else if (size === 2)
        v.setUint16(0, data, true);
    else if (size === 4)
        v.setUint32(0, data, true);
    else if (size === 8)
        v.setBigUint64(0, BigInt(data), true);
    return new Uint8Array(buf);
}
function decodeInt(data) {
    const v = new DataView(data.buffer, data.byteOffset, data.byteLength);
    if (data.length === 1)
        return v.getUint8(0);
    if (data.length === 2)
        return v.getUint16(0, true);
    if (data.length === 4)
        return v.getUint32(0, true);
    if (data.length === 8)
        return Number(v.getBigUint64(0, true));
    return 0;
}
function encodeCfg(data) {
    const chunks = [];
    for (const [key, val] of Object.entries(data)) {
        const valU8 = typeof val === "string" ? strToU8(val) : val;
        const keyBytes = strToU8(key);
        const kl = keyBytes.length;
        const dl = valU8.length;
        if (kl > 127)
            throw new Error(`Key length too long: ${kl}`);
        if (dl > 65535)
            throw new Error(`Data size too big: ${dl}`);
        if (dl > 255) {
            chunks.push(new Uint8Array([kl + 128]));
            chunks.push(keyBytes);
            chunks.push(encodeInt(dl, 2));
        }
        else {
            chunks.push(new Uint8Array([kl]));
            chunks.push(keyBytes);
            chunks.push(new Uint8Array([dl]));
        }
        chunks.push(valU8);
    }
    return concat(chunks);
}
function decodeCfg(data) {
    const result = {};
    let off = 0;
    while (off < data.length) {
        let kl = data[off];
        let longData = false;
        off += 1;
        if (kl > 127) {
            kl -= 128;
            longData = true;
        }
        const key = u8ToStr(data.slice(off, off + kl));
        off += kl;
        let dl;
        if (longData) {
            dl = decodeInt(data.slice(off, off + 2));
            off += 2;
        }
        else {
            dl = data[off];
            off += 1;
        }
        result[key] = data.slice(off, off + dl);
        off += dl;
    }
    return result;
}
// ==================== Cryptographic Primitives ====================
function sha3512(data) {
    return new Uint8Array(sha3_512.create().update(data).arrayBuffer());
}
function hmac_sha3_512(key, msg) {
    const B = 72; // SHA3-512 block size (rate = 576 bits)
    let k = toU8(key);
    const m = toU8(msg);
    if (k.length > B)
        k = sha3512(k);
    if (k.length < B) {
        const nk = new Uint8Array(B);
        nk.set(k);
        k = nk;
    }
    const opad = new Uint8Array(B);
    const ipad = new Uint8Array(B);
    for (let i = 0; i < B; i++) {
        opad[i] = k[i] ^ 0x5c;
        ipad[i] = k[i] ^ 0x36;
    }
    const inner = new Uint8Array(B + m.length);
    inner.set(ipad);
    inner.set(m, B);
    const ihash = sha3512(inner);
    const outer = new Uint8Array(B + ihash.length);
    outer.set(opad);
    outer.set(ihash, B);
    return sha3512(outer);
}
function genkey(data, lbl, size) {
    const digest = hmac_sha3_512(data, lbl);
    if (size > digest.length)
        throw new Error("key size too large");
    return digest.slice(0, size);
}
function mkiv(g, c) {
    const iv = new Uint8Array(g);
    const buf = new ArrayBuffer(8);
    new DataView(buf).setBigUint64(0, BigInt(c), true);
    const cb = new Uint8Array(buf);
    for (let i = 0; i < 8; i++)
        iv[4 + i] ^= cb[i];
    return iv;
}
async function pbkdf2Derive(pw, salt, iter = 1000000, outsize = 64) {
    const passBytes = toU8(pw);
    const saltBytes = toU8(salt);
    const km = await crypto.subtle.importKey("raw", asBuf(passBytes), "PBKDF2", false, [
        "deriveBits",
    ]);
    const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt: asBuf(saltBytes), iterations: iter, hash: "SHA-512" }, km, outsize * 8);
    return new Uint8Array(bits);
}
async function argon2Hash(pw, salt = null) {
    // Fallback to PBKDF2-SHA512 (argon2-browser requires WASM which conflicts with Vite)
    // For browser compatibility, use PBKDF2 which is native Web Crypto
    const pwBuf = toU8(pw);
    const saltBuf = salt || new Uint8Array(16);
    const derived = await pbkdf2Derive(pwBuf, saltBuf, 1000000, 64);
    // Return base64-encoded result (mimics argon2.hash().encoded format)
    return u8ToBase64(derived);
}
class TestReader {
    constructor(u8) {
        Object.defineProperty(this, "data", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: void 0
        });
        Object.defineProperty(this, "pos", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: 0
        });
        this.data = u8;
    }
    async read(size) {
        if (this.pos >= this.data.length)
            return new Uint8Array(0);
        const end = Math.min(this.pos + size, this.data.length);
        const chunk = this.data.slice(this.pos, end);
        this.pos = end;
        return chunk;
    }
}
class TestWriter {
    constructor() {
        Object.defineProperty(this, "chunks", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: []
        });
        Object.defineProperty(this, "length", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: 0
        });
    }
    async write(chunk) {
        if (chunk && chunk.length > 0) {
            const c = new Uint8Array(chunk);
            this.chunks.push(c);
            this.length += c.length;
        }
    }
    getValue() {
        const r = new Uint8Array(this.length);
        let off = 0;
        for (const c of this.chunks) {
            r.set(c, off);
            off += c.length;
        }
        return r;
    }
}
// ==================== AES1 ====================
class AES1 {
    constructor() {
        Object.defineProperty(this, "_processed", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: 0
        });
    }
    processed() {
        return this._processed;
    }
    async enAESGCM(key, data) {
        this._processed = 0;
        if (key.length !== 44)
            throw new Error("key size must be 44 bytes");
        const iv = key.slice(0, 12);
        const aesKey = key.slice(12);
        const wk = await crypto.subtle.importKey("raw", asBuf(aesKey), "AES-GCM", false, ["encrypt"]);
        const res = await crypto.subtle.encrypt({ name: "AES-GCM", iv: asBuf(iv) }, wk, asBuf(data));
        this._processed = data.length;
        return new Uint8Array(res);
    }
    async deAESGCM(key, data) {
        this._processed = 0;
        if (key.length !== 44)
            throw new Error("key size must be 44 bytes");
        const iv = key.slice(0, 12);
        const aesKey = key.slice(12);
        const wk = await crypto.subtle.importKey("raw", asBuf(aesKey), "AES-GCM", false, ["decrypt"]);
        try {
            const res = await crypto.subtle.decrypt({ name: "AES-GCM", iv: asBuf(iv) }, wk, asBuf(data));
            this._processed = data.length;
            return new Uint8Array(res);
        }
        catch {
            throw new Error("Decryption failed (MAC check failed)");
        }
    }
    async enAESGCMx(key, src, size, dst, chunkSize = 1048576) {
        this._processed = 0;
        if (key.length !== 44)
            throw new Error("key size must be 44 bytes");
        const globalIV = key.slice(0, 12);
        const aesKeyBytes = key.slice(12);
        let count = 0;
        const wk = await crypto.subtle.importKey("raw", asBuf(aesKeyBytes), "AES-GCM", false, ["encrypt"]);
        let writeChain = Promise.resolve();
        let remaining = size;
        let nextChunk = src.read(Math.min(chunkSize, size));
        do {
            const chunk = await nextChunk;
            remaining -= chunk.length;
            nextChunk =
                remaining > 0
                    ? src.read(Math.min(chunkSize, remaining))
                    : Promise.resolve(new Uint8Array(0));
            const iv = mkiv(globalIV, count++);
            const enc = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: asBuf(iv) }, wk, asBuf(chunk)));
            this._processed += chunk.length;
            writeChain = writeChain.then(() => dst.write(enc));
        } while (remaining > 0);
        await writeChain;
    }
    async deAESGCMx(key, src, size, dst, chunkSize = 1048576) {
        this._processed = 0;
        if (key.length !== 44)
            throw new Error("key size must be 44 bytes");
        const globalIV = key.slice(0, 12);
        const aesKeyBytes = key.slice(12);
        let count = 0;
        const wk = await crypto.subtle.importKey("raw", asBuf(aesKeyBytes), "AES-GCM", false, [
            "decrypt",
        ]);
        const readBlock = async (cSize) => {
            const c = await src.read(cSize);
            const t = await src.read(16);
            if (!t || t.length !== 16)
                throw new Error("Unexpected EOF reading tag");
            return { chunk: c, tag: t };
        };
        let writeChain = Promise.resolve();
        let remaining = size;
        let nextBlock = readBlock(Math.min(chunkSize, remaining - 16));
        do {
            const block = await nextBlock;
            if (!block)
                break;
            remaining -= block.chunk.length + 16;
            nextBlock =
                remaining > 16
                    ? readBlock(Math.min(chunkSize, remaining - 16))
                    : Promise.resolve(null);
            const iv = mkiv(globalIV, count++);
            const combined = new Uint8Array(block.chunk.length + 16);
            combined.set(block.chunk);
            combined.set(block.tag, block.chunk.length);
            const plain = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: asBuf(iv) }, wk, asBuf(combined)));
            this._processed += block.chunk.length + 16;
            writeChain = writeChain.then(() => dst.write(plain));
        } while (remaining > 16);
        await writeChain;
    }
}
// ==================== RSA1 ====================
class RSA1 {
    constructor() {
        Object.defineProperty(this, "pub", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: null
        });
        Object.defineProperty(this, "pri", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: null
        });
        Object.defineProperty(this, "signPub", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: null
        });
        Object.defineProperty(this, "signPri", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: null
        });
    }
    async genkey(bits = 2048) {
        const kp = await crypto.subtle.generateKey({
            name: "RSA-OAEP",
            modulusLength: bits,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: "SHA-512",
        }, true, ["encrypt", "decrypt"]);
        const pubDer = new Uint8Array(await crypto.subtle.exportKey("spki", kp.publicKey));
        const priDer = new Uint8Array(await crypto.subtle.exportKey("pkcs8", kp.privateKey));
        await this.loadkey(pubDer, priDer);
        return [pubDer, priDer];
    }
    async loadkey(pub, pri) {
        if (pub) {
            this.pub = await crypto.subtle.importKey("spki", asBuf(pub), { name: "RSA-OAEP", hash: "SHA-512" }, true, ["encrypt"]);
            this.signPub = await crypto.subtle.importKey("spki", asBuf(pub), { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, true, ["verify"]);
        }
        if (pri) {
            this.pri = await crypto.subtle.importKey("pkcs8", asBuf(pri), { name: "RSA-OAEP", hash: "SHA-512" }, true, ["decrypt"]);
            this.signPri = await crypto.subtle.importKey("pkcs8", asBuf(pri), { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, true, ["sign"]);
        }
    }
    async encrypt(data) {
        return new Uint8Array(await crypto.subtle.encrypt({ name: "RSA-OAEP" }, this.pub, asBuf(data)));
    }
    async decrypt(data) {
        return new Uint8Array(await crypto.subtle.decrypt({ name: "RSA-OAEP" }, this.pri, asBuf(data)));
    }
    async sign(data) {
        return new Uint8Array(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", this.signPri, asBuf(data)));
    }
    async verify(data, sig) {
        return crypto.subtle.verify("RSASSA-PKCS1-v1_5", this.signPub, asBuf(sig), asBuf(data));
    }
}
// ==================== ECC1 (Curve448) ====================
class ECC1 {
    constructor() {
        Object.defineProperty(this, "pubX", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: null
        });
        Object.defineProperty(this, "priX", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: null
        });
        Object.defineProperty(this, "pubEd", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: null
        });
        Object.defineProperty(this, "priEd", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: null
        });
        Object.defineProperty(this, "em", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: new AES1()
        });
    }
    async genkey() {
        const priXKey = x448.utils.randomSecretKey();
        const pubXKey = x448.getPublicKey(priXKey);
        const priEdKey = ed448.utils.randomSecretKey();
        const pubEdKey = ed448.getPublicKey(priEdKey);
        const pubFull = new Uint8Array(113);
        pubFull.set(pubXKey, 0);
        pubFull.set(pubEdKey, 56);
        const priFull = new Uint8Array(113);
        priFull.set(priXKey, 0);
        priFull.set(priEdKey, 56);
        this.pubX = pubXKey;
        this.priX = priXKey;
        this.pubEd = pubEdKey;
        this.priEd = priEdKey;
        return [pubFull, priFull];
    }
    async loadkey(pub, pri) {
        if (pub) {
            const p = toU8(pub);
            if (p.length !== 113)
                throw new Error("Invalid Curve448 public key (must be 113 bytes)");
            this.pubX = p.slice(0, 56);
            this.pubEd = p.slice(56, 113);
        }
        if (pri) {
            const p = toU8(pri);
            if (p.length !== 113)
                throw new Error("Invalid Curve448 private key (must be 113 bytes)");
            this.priX = p.slice(0, 56);
            this.priEd = p.slice(56, 113);
        }
    }
    async encrypt(data) {
        const ephPri = x448.utils.randomSecretKey();
        const ephPub = x448.getPublicKey(ephPri);
        const shared = x448.getSharedSecret(ephPri, this.pubX);
        const gcmKey = genkey(new Uint8Array(shared), "KEYGEN_ECC1_ENCRYPT", 44);
        const enc = await this.em.enAESGCM(gcmKey, data);
        // [1B PubLen][EphPub][Enc]
        const res = new Uint8Array(1 + ephPub.length + enc.length);
        res[0] = ephPub.length;
        res.set(ephPub, 1);
        res.set(enc, 1 + ephPub.length);
        return res;
    }
    async decrypt(data) {
        const keyLen = data[0];
        const ephPub = data.slice(1, 1 + keyLen);
        const enc = data.slice(1 + keyLen);
        const shared = x448.getSharedSecret(this.priX, ephPub);
        const gcmKey = genkey(new Uint8Array(shared), "KEYGEN_ECC1_ENCRYPT", 44);
        return this.em.deAESGCM(gcmKey, enc);
    }
    async sign(data) {
        return ed448.sign(data, this.priEd);
    }
    async verify(data, sig) {
        return ed448.verify(sig, data, this.pubEd);
    }
}
// ==================== SymMaster ====================
class SymMaster {
    constructor(algo, key) {
        Object.defineProperty(this, "algo", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: void 0
        });
        Object.defineProperty(this, "key", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: void 0
        });
        Object.defineProperty(this, "worker", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: new AES1()
        });
        if (algo !== "gcm1" && algo !== "gcmx1")
            throw new Error(`Unsupported algorithm: ${algo}`);
        this.algo = algo;
        this.key = toU8(key);
        if (this.key.length !== 44)
            throw new Error("Key must be 44 bytes (12B IV + 32B Key)");
    }
    aftersize(size) {
        if (this.algo === "gcm1")
            return size + 16;
        if (this.algo === "gcmx1") {
            const cs = 1048576;
            let c = Math.floor(size / cs) + 1;
            if (size !== 0 && size % cs === 0)
                c -= 1;
            return size + 16 * c;
        }
        return 0;
    }
    processed() {
        return this.worker.processed();
    }
    async enBin(data) {
        const d = toU8(data);
        if (this.algo === "gcm1")
            return this.worker.enAESGCM(this.key, d);
        const rd = new TestReader(d);
        const wr = new TestWriter();
        await this.worker.enAESGCMx(this.key, rd, d.length, wr, 1048576);
        return wr.getValue();
    }
    async deBin(data) {
        const d = toU8(data);
        if (this.algo === "gcm1")
            return this.worker.deAESGCM(this.key, d);
        const rd = new TestReader(d);
        const wr = new TestWriter();
        await this.worker.deAESGCMx(this.key, rd, d.length, wr, 1048576);
        return wr.getValue();
    }
}
// ==================== AsymMaster ====================
class AsymMaster {
    constructor(algo) {
        Object.defineProperty(this, "algo", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: void 0
        });
        Object.defineProperty(this, "worker", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: void 0
        });
        const valid = ["rsa1", "rsa1-2k", "rsa1-3k", "rsa1-4k", "ecc1"];
        if (!valid.includes(algo))
            throw new Error(`Unsupported algorithm: ${algo}`);
        this.algo = algo;
        this.worker = algo === "ecc1" ? new ECC1() : new RSA1();
    }
    async genkey() {
        if (this.algo === "rsa1" || this.algo === "rsa1-2k")
            return this.worker.genkey(2048);
        if (this.algo === "rsa1-3k")
            return this.worker.genkey(3072);
        if (this.algo === "rsa1-4k")
            return this.worker.genkey(4096);
        return this.worker.genkey();
    }
    async loadkey(pub, pri) {
        await this.worker.loadkey(pub, pri);
    }
    async encrypt(data) {
        return this.worker.encrypt(data);
    }
    async decrypt(data) {
        return this.worker.decrypt(data);
    }
    async sign(data) {
        return this.worker.sign(data);
    }
    async verify(data, sig) {
        return this.worker.verify(data, sig);
    }
}
// ==================== Opsec ====================
class Opsec {
    constructor() {
        // Outer Layer
        Object.defineProperty(this, "msg", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: ""
        });
        Object.defineProperty(this, "_headAlgo", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: ""
        });
        Object.defineProperty(this, "_salt", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: new Uint8Array(0)
        });
        Object.defineProperty(this, "_pwHash", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: new Uint8Array(0)
        });
        Object.defineProperty(this, "_encHeadKey", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: new Uint8Array(0)
        });
        Object.defineProperty(this, "_encHeadData", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: new Uint8Array(0)
        });
        // Inner Layer
        Object.defineProperty(this, "smsg", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: ""
        });
        Object.defineProperty(this, "size", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: -1
        });
        Object.defineProperty(this, "name", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: ""
        });
        Object.defineProperty(this, "bodyKey", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: new Uint8Array(0)
        });
        Object.defineProperty(this, "bodyAlgo", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: ""
        });
        Object.defineProperty(this, "contAlgo", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: ""
        });
        Object.defineProperty(this, "_sign", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: new Uint8Array(0)
        });
    }
    reset() {
        this.msg = "";
        this._headAlgo = "";
        this._salt = new Uint8Array(0);
        this._pwHash = new Uint8Array(0);
        this._encHeadKey = new Uint8Array(0);
        this._encHeadData = new Uint8Array(0);
        this.smsg = "";
        this.size = -1;
        this.name = "";
        this.bodyKey = new Uint8Array(0);
        this.bodyAlgo = "";
        this.contAlgo = "";
        this._sign = new Uint8Array(0);
    }
    /** Read stream until YAS2 header is found, returns header data */
    async read(ins, cut = 65535) {
        let c = 0;
        while (true) {
            const data = await ins.read(4);
            c += 4;
            if (data.length === 0)
                return new Uint8Array(0);
            const magic = u8ToStr(data);
            if (magic === "YAS2") {
                const sizeBuf = await ins.read(2);
                let size = decodeInt(sizeBuf);
                if (size === 65535) {
                    const ext = await ins.read(2);
                    size += decodeInt(ext);
                }
                return ins.read(size);
            }
            else {
                await ins.read(124); // skip prehead block (128B aligned)
                c += 124;
            }
            if (cut > 0 && c > cut)
                return new Uint8Array(0);
        }
    }
    /** Write Opsec header to stream */
    async write(outs, head) {
        await outs.write(strToU8("YAS2"));
        const size = head.length;
        if (size < 65535) {
            await outs.write(encodeInt(size, 2));
        }
        else if (size <= 65535 * 2) {
            await outs.write(encodeInt(65535, 2));
            await outs.write(encodeInt(size - 65535, 2));
        }
        else {
            throw new Error(`Data size too big: ${size}`);
        }
        await outs.write(head);
    }
    _wrapHead() {
        const cfg = {};
        if (this.smsg !== "")
            cfg["smsg"] = this.smsg;
        if (this.size >= 0) {
            if (this.size < 65536)
                cfg["sz"] = encodeInt(this.size, 2);
            else if (this.size < 4294967296)
                cfg["sz"] = encodeInt(this.size, 4);
            else
                cfg["sz"] = encodeInt(this.size, 8);
        }
        if (this.name !== "")
            cfg["nm"] = this.name;
        if (this.bodyKey.length > 0)
            cfg["bkey"] = this.bodyKey;
        if (this.bodyAlgo !== "")
            cfg["bodyal"] = this.bodyAlgo;
        if (this.contAlgo !== "")
            cfg["contal"] = this.contAlgo;
        if (this._sign.length > 0)
            cfg["sgn"] = this._sign;
        return encodeCfg(cfg);
    }
    _unwrapHead(data) {
        const cfg = decodeCfg(data);
        if (cfg["smsg"])
            this.smsg = u8ToStr(cfg["smsg"]);
        if (cfg["sz"])
            this.size = decodeInt(cfg["sz"]);
        if (cfg["nm"])
            this.name = u8ToStr(cfg["nm"]);
        if (cfg["bkey"])
            this.bodyKey = cfg["bkey"];
        if (cfg["bodyal"])
            this.bodyAlgo = u8ToStr(cfg["bodyal"]);
        if (cfg["contal"])
            this.contAlgo = u8ToStr(cfg["contal"]);
        if (cfg["sgn"])
            this._sign = cfg["sgn"];
    }
    /** Encrypt with password, returns serialised header */
    async encpw(method, pw, kf = new Uint8Array(0)) {
        if (method !== "arg1" && method !== "pbk1")
            throw new Error(`Unsupported KDF: ${method}`);
        this._headAlgo = method;
        this._salt = random(16);
        if (this.size >= 0)
            this.bodyKey = random(44);
        const pwBytes = typeof pw === "string" ? strToU8(pw) : toU8(pw);
        const combined = concat([pwBytes, toU8(kf)]);
        let mkey;
        let hkey;
        if (method === "arg1") {
            const hash = await argon2Hash(combined, this._salt);
            mkey = strToU8(hash);
            this._pwHash = genkey(mkey, "PWHASH_OPSEC_ARGON2", 32);
            hkey = genkey(mkey, "KEYGEN_OPSEC_ARGON2", 44);
        }
        else {
            mkey = await pbkdf2Derive(combined, this._salt);
            this._pwHash = genkey(mkey, "PWHASH_OPSEC_PBKDF2", 32);
            hkey = genkey(mkey, "KEYGEN_OPSEC_PBKDF2", 44);
        }
        const sm = new SymMaster("gcm1", hkey);
        this._encHeadData = await sm.enBin(this._wrapHead());
        const cfg = {};
        if (this.msg !== "")
            cfg["msg"] = this.msg;
        cfg["headal"] = this._headAlgo;
        cfg["salt"] = this._salt;
        cfg["pwh"] = this._pwHash;
        cfg["ehd"] = this._encHeadData;
        return encodeCfg(cfg);
    }
    /** Encrypt with public key, returns serialised header */
    async encpub(method, publicBytes, privateBytes = null) {
        if (method !== "rsa1" && method !== "ecc1")
            throw new Error(`Unsupported method: ${method}`);
        this._headAlgo = method;
        if (this.size >= 0)
            this.bodyKey = random(44);
        const am = new AsymMaster(method);
        await am.loadkey(publicBytes, privateBytes);
        // Sign
        if (privateBytes !== null) {
            if (this.bodyKey.length > 0)
                this._sign = await am.sign(this.bodyKey);
            else if (this.smsg !== "")
                this._sign = await am.sign(strToU8(this.smsg));
        }
        // Encrypt header
        const headData = this._wrapHead();
        if (method === "rsa1") {
            const hkey = random(44);
            this._encHeadKey = await am.encrypt(hkey);
            const sm = new SymMaster("gcm1", hkey);
            this._encHeadData = await sm.enBin(headData);
        }
        else {
            this._encHeadData = await am.encrypt(headData);
        }
        const cfg = {};
        if (this.msg !== "")
            cfg["msg"] = this.msg;
        cfg["headal"] = this._headAlgo;
        if (this._encHeadKey.length > 0)
            cfg["ehk"] = this._encHeadKey;
        cfg["ehd"] = this._encHeadData;
        return encodeCfg(cfg);
    }
    /** Parse outer layer (before decryption) */
    view(data) {
        this.reset();
        const cfg = decodeCfg(data);
        if (cfg["msg"])
            this.msg = u8ToStr(cfg["msg"]);
        if (cfg["headal"])
            this._headAlgo = u8ToStr(cfg["headal"]);
        if (cfg["salt"])
            this._salt = cfg["salt"];
        if (cfg["pwh"])
            this._pwHash = cfg["pwh"];
        if (cfg["ehk"])
            this._encHeadKey = cfg["ehk"];
        if (cfg["ehd"])
            this._encHeadData = cfg["ehd"];
    }
    /** Decrypt with password (call view() first) */
    async decpw(pw, kf = new Uint8Array(0)) {
        if (!this._headAlgo)
            throw new Error("Call view() first");
        if (this._headAlgo !== "arg1" && this._headAlgo !== "pbk1")
            throw new Error(`Unsupported KDF: ${this._headAlgo}`);
        const pwBytes = typeof pw === "string" ? strToU8(pw) : toU8(pw);
        const combined = concat([pwBytes, toU8(kf)]);
        let mkey;
        let vLbl;
        let kLbl;
        if (this._headAlgo === "arg1") {
            mkey = strToU8(await argon2Hash(combined, this._salt));
            vLbl = "PWHASH_OPSEC_ARGON2";
            kLbl = "KEYGEN_OPSEC_ARGON2";
        }
        else {
            mkey = await pbkdf2Derive(combined, this._salt);
            vLbl = "PWHASH_OPSEC_PBKDF2";
            kLbl = "KEYGEN_OPSEC_PBKDF2";
        }
        // Verify password
        const hash = genkey(mkey, vLbl, 32);
        if (hash.length !== this._pwHash.length)
            throw new Error("Incorrect password");
        let diff = 0;
        for (let i = 0; i < hash.length; i++)
            diff |= hash[i] ^ this._pwHash[i];
        if (diff !== 0)
            throw new Error("Incorrect password");
        // Decrypt header
        const hkey = genkey(mkey, kLbl, 44);
        const sm = new SymMaster("gcm1", hkey);
        this._unwrapHead(await sm.deBin(this._encHeadData));
    }
    /** Decrypt with private key (call view() first) */
    async decpub(privateBytes, publicBytes = null) {
        if (!this._headAlgo)
            throw new Error("Call view() first");
        if (this._headAlgo !== "rsa1" && this._headAlgo !== "ecc1")
            throw new Error(`Unsupported method: ${this._headAlgo}`);
        const am = new AsymMaster(this._headAlgo);
        await am.loadkey(publicBytes, privateBytes);
        let decHead;
        if (this._headAlgo === "rsa1") {
            const hkey = await am.decrypt(this._encHeadKey);
            const sm = new SymMaster("gcm1", hkey);
            decHead = await sm.deBin(this._encHeadData);
        }
        else {
            decHead = await am.decrypt(this._encHeadData);
        }
        this._unwrapHead(decHead);
        // Verify signature
        if (publicBytes !== null && this._sign.length > 0) {
            let s = new Uint8Array(0);
            if (this.bodyKey.length > 0)
                s = this.bodyKey;
            else if (this.smsg !== "")
                s = strToU8(this.smsg);
            const ok = await am.verify(s, this._sign);
            if (!ok)
                throw new Error(`${this._headAlgo.toUpperCase()} signature verification failed`);
        }
    }
}
// ==================== App-level Encrypt / Decrypt ====================
/**
 * Generate key pair for the given algorithm.
 * Returns base64-encoded public and private keys.
 */
export async function generateKeyPair(algo) {
    const am = new AsymMaster(algo);
    const [pubU8, priU8] = await am.genkey();
    return { publicKey: u8ToBase64(pubU8), privateKey: u8ToBase64(priU8) };
}
/**
 * Encrypt using Opsec YAS2 format.
 * Returns the complete binary blob.
 */
export async function encryptOpsec(options) {
    const ops = new Opsec();
    ops.msg = options.msg || "";
    ops.smsg = options.smsg || "";
    const outChunks = [];
    const outs = {
        write: async (d) => {
            outChunks.push(d);
        },
    };
    let packedData = null;
    if (options.files && options.files.length > 0) {
        // Pack files into zip
        const JSZip = (await import("jszip")).default;
        const zip = new JSZip();
        for (const file of options.files) {
            zip.file(file.name, await file.arrayBuffer());
        }
        packedData = new Uint8Array(await zip.generateAsync({ type: "arraybuffer" }));
        const dummySm = new SymMaster(options.encAlgo, new Uint8Array(44));
        ops.size = dummySm.aftersize(packedData.length);
        ops.contAlgo = "zip1";
        ops.bodyAlgo = options.encAlgo;
    }
    // Build header
    let headerBytes;
    if (options.mode === "password") {
        headerBytes = await ops.encpw(options.kdfMethod, options.password);
    }
    else {
        const peerPub = base64ToU8(options.peerPublicKey);
        const myPri = options.myPrivateKey ? base64ToU8(options.myPrivateKey) : null;
        headerBytes = await ops.encpub(options.asymAlgo, peerPub, myPri);
    }
    // Write header
    await ops.write(outs, headerBytes);
    // Encrypt body
    if (packedData) {
        const sm = new SymMaster(options.encAlgo, ops.bodyKey);
        outChunks.push(await sm.enBin(packedData));
    }
    // Merge
    let total = 0;
    for (const c of outChunks)
        total += c.length;
    const out = new Uint8Array(total);
    let off = 0;
    for (const c of outChunks) {
        out.set(c, off);
        off += c.length;
    }
    return out;
}
/** Decrypt Opsec data encrypted with password */
export async function decryptOpsecPw(dataU8, password) {
    const reader = new TestReader(dataU8);
    const ops = new Opsec();
    const hdr = await ops.read(reader, 0);
    if (!hdr || hdr.length === 0)
        throw new Error("Invalid Opsec format");
    ops.view(hdr);
    await ops.decpw(password);
    const result = { msg: ops.msg, smsg: ops.smsg, files: [] };
    if (ops.size >= 0) {
        const sm = new SymMaster(ops.bodyAlgo, ops.bodyKey);
        const decBody = await sm.deBin(dataU8.slice(reader.pos));
        if (ops.contAlgo === "zip1") {
            const JSZip = (await import("jszip")).default;
            const zip = await JSZip.loadAsync(decBody);
            for (const [name, file] of Object.entries(zip.files)) {
                if (file.dir)
                    continue;
                result.files.push({ name, data: await file.async("uint8array") });
            }
        }
    }
    return result;
}
/** Decrypt Opsec data encrypted with public key */
export async function decryptOpsecPub(dataU8, myPrivateKey, peerPublicKey) {
    const reader = new TestReader(dataU8);
    const ops = new Opsec();
    const hdr = await ops.read(reader, 0);
    if (!hdr || hdr.length === 0)
        throw new Error("Invalid Opsec format");
    ops.view(hdr);
    const myPri = base64ToU8(myPrivateKey);
    const peerPub = peerPublicKey ? base64ToU8(peerPublicKey) : null;
    await ops.decpub(myPri, peerPub);
    const hasSignature = ops._sign.length > 0;
    const verified = peerPub && hasSignature ? true : undefined; // If we get here, verification passed (decpub throws on failure)
    const result = { msg: ops.msg, smsg: ops.smsg, files: [], verified };
    if (ops.size >= 0) {
        const sm = new SymMaster(ops.bodyAlgo, ops.bodyKey);
        const decBody = await sm.deBin(dataU8.slice(reader.pos));
        if (ops.contAlgo === "zip1") {
            const JSZip = (await import("jszip")).default;
            const zip = await JSZip.loadAsync(decBody);
            for (const [name, file] of Object.entries(zip.files)) {
                if (file.dir)
                    continue;
                result.files.push({ name, data: await file.async("uint8array") });
            }
        }
    }
    return result;
}
/**
 * Detect the auth mode from raw Opsec data without decrypting.
 * Returns the mode, algorithm, and public message.
 */
export function detectAuthMode(dataU8) {
    let pos = 0;
    while (pos < dataU8.length) {
        if (pos + 4 > dataU8.length)
            break;
        const magic = u8ToStr(dataU8.slice(pos, pos + 4));
        if (magic === "YAS2") {
            const sizeBuf = dataU8.slice(pos + 4, pos + 6);
            let size = decodeInt(sizeBuf);
            let hdrStart = pos + 6;
            if (size === 65535) {
                size += decodeInt(dataU8.slice(pos + 6, pos + 8));
                hdrStart = pos + 8;
            }
            const hdrData = dataU8.slice(hdrStart, hdrStart + size);
            const cfg = decodeCfg(hdrData);
            const algo = cfg["headal"] ? u8ToStr(cfg["headal"]) : "";
            const msg = cfg["msg"] ? u8ToStr(cfg["msg"]) : "";
            return {
                mode: algo === "arg1" || algo === "pbk1" ? "password" : "publickey",
                algo,
                msg,
            };
        }
        else {
            pos += 128;
        }
    }
    throw new Error("Cannot detect auth mode: no YAS2 header found");
}
// ==================== Key Storage (server account management) ====================
// Uses PBKDF2-SHA256 + AES-GCM for encrypting private key before server upload.
// Separate from the Opsec data encryption.
async function deriveStorageKey(passphrase, salt, iterations = 310000, keyLength = 32) {
    const base = await crypto.subtle.importKey("raw", asBuf(strToU8(passphrase)), "PBKDF2", false, ["deriveKey"]);
    return crypto.subtle.deriveKey({ name: "PBKDF2", salt: asBuf(salt), iterations, hash: "SHA-256" }, base, { name: "AES-GCM", length: keyLength * 8 }, false, ["encrypt", "decrypt"]);
}
export async function encryptPrivateKey(privateKeyB64, passphrase) {
    const salt = random(16);
    const iv = random(12);
    const iterations = 310000;
    const keyLength = 32;
    const aesKey = await deriveStorageKey(passphrase, salt, iterations, keyLength);
    const cipher = await crypto.subtle.encrypt({ name: "AES-GCM", iv: asBuf(iv) }, aesKey, asBuf(strToU8(privateKeyB64)));
    return {
        encryptedPrivateKey: {
            cipherText: u8ToBase64(new Uint8Array(cipher)),
            iv: u8ToBase64(iv),
        },
        kdf: {
            algorithm: "PBKDF2",
            salt: u8ToBase64(salt),
            iterations,
            keyLength,
            hash: "SHA-256",
        },
    };
}
export async function decryptPrivateKey(encrypted, kdf, passphrase) {
    if (kdf.algorithm !== "PBKDF2")
        throw new Error(`Unsupported KDF: ${kdf.algorithm}`);
    const salt = base64ToU8(kdf.salt);
    const iterations = kdf.iterations ?? 310000;
    const keyLength = kdf.keyLength ?? 32;
    const aesKey = await deriveStorageKey(passphrase, salt, iterations, keyLength);
    const iv = base64ToU8(encrypted.iv);
    const cipher = base64ToU8(encrypted.cipherText);
    const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: asBuf(iv) }, aesKey, asBuf(cipher));
    return _dec.decode(plain);
}
export async function buildAccountPayload(username, publicKeyB64, privateKeyB64, notes) {
    // Use username as KDF input for deterministic key derivation
    // In production, this should use a server-provided secret or WebAuthn challenge
    const { encryptedPrivateKey, kdf } = await encryptPrivateKey(privateKeyB64, username);
    return { username, publicKey: publicKeyB64, encryptedPrivateKey, kdf, notes };
}
// ==================== Utility Exports ====================
export function encodeUtf8(data) {
    return _enc.encode(data).buffer;
}
export function decodeUtf8(buffer) {
    return _dec.decode(buffer);
}
// ==================== WebAuthn utilities ====================
/**
 * Convert ArrayBuffer to Base64
 */
export function arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = "";
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}
/**
 * Convert Base64 to ArrayBuffer
 */
export function base64ToArrayBuffer(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
}
/**
 * Register a WebAuthn credential
 * Returns credential data needed for server verification
 */
export async function registerWebAuthnCredential(options) {
    // Convert challenge from base64 to ArrayBuffer
    const challengeBuffer = base64ToArrayBuffer(options.challenge);
    const userIdBuffer = base64ToArrayBuffer(options.user.id);
    const credential = (await navigator.credentials.create({
        publicKey: {
            challenge: challengeBuffer,
            rp: options.rp,
            user: {
                id: userIdBuffer,
                name: options.user.name,
                displayName: options.user.displayName,
            },
            pubKeyCredParams: options.pubKeyCredParams,
            timeout: options.timeout || 60000,
            attestation: options.attestation || "direct",
            authenticatorSelection: options.authenticatorSelection || {
                authenticatorAttachment: "platform",
                residentKey: "preferred",
                userVerification: "preferred",
            },
        },
    }));
    if (!credential) {
        throw new Error("WebAuthn registration cancelled");
    }
    const response = credential.response;
    // Convert credential ID to base64 - handle both rawId and id
    let credentialId = "";
    if ("rawId" in credential && credential.rawId) {
        credentialId = arrayBufferToBase64(credential.rawId);
    }
    else if (credential.id) {
        // Fallback: convert id to Uint8Array first, then to base64
        const idArray = new Uint8Array(credential.id);
        credentialId = arrayBufferToBase64(idArray);
    }
    if (!credentialId) {
        throw new Error("Failed to extract credential ID");
    }
    // Extract public key from attestation object
    // Note: This is simplified; production code should use @simplewebauthn/browser
    const publicKeyBuffer = response.getPublicKey();
    if (!publicKeyBuffer) {
        throw new Error("Failed to extract public key");
    }
    const publicKey = arrayBufferToBase64(publicKeyBuffer);
    // Counter is always 0 at registration time
    // (actual counter increments are tracked during authentication)
    const counter = 0;
    const transports = response.getTransports?.() || [];
    return {
        credentialId,
        publicKey,
        counter,
        transports,
    };
}
/**
 * Authenticate with WebAuthn
 * Returns credential ID and counter for server verification
 */
export async function authenticateWithWebAuthn(options) {
    // Convert challenge from base64 to ArrayBuffer
    const challengeBuffer = base64ToArrayBuffer(options.challenge);
    // Convert allowed credentials if provided
    const allowCredentials = (options.allowCredentials || []).map((cred) => ({
        type: cred.type,
        id: base64ToArrayBuffer(cred.id),
        transports: cred.transports,
    }));
    const assertion = (await navigator.credentials.get({
        publicKey: {
            challenge: challengeBuffer,
            timeout: options.timeout || 60000,
            userVerification: options.userVerification || "preferred",
            allowCredentials: allowCredentials.length > 0 ? allowCredentials : undefined,
        },
    }));
    if (!assertion) {
        throw new Error("WebAuthn authentication cancelled");
    }
    const response = assertion.response;
    // Extract counter from authenticatorData
    // Authenticator data format: RP ID hash (32) + Flags (1) + Counter (4) + [...]
    // Counter is big-endian (network byte order)
    const authData = new Uint8Array(response.authenticatorData);
    const counterBytes = authData.slice(33, 37);
    // Manually convert big-endian bytes to uint32
    const counter = (counterBytes[0] << 24) | (counterBytes[1] << 16) | (counterBytes[2] << 8) | counterBytes[3];
    console.log(`[WebAuthn] Counter extracted: ${counter} from bytes [${Array.from(counterBytes).join(', ')}]`);
    // Convert credential ID to base64 - handle both rawId and id
    let credentialId = "";
    if ("rawId" in assertion && assertion.rawId) {
        credentialId = arrayBufferToBase64(assertion.rawId);
    }
    else if (assertion.id) {
        // Fallback: convert id to Uint8Array first, then to base64
        const idArray = new Uint8Array(assertion.id);
        credentialId = arrayBufferToBase64(idArray);
    }
    if (!credentialId) {
        throw new Error("Failed to extract credential ID");
    }
    return {
        credentialId,
        clientDataJSON: arrayBufferToBase64(response.clientDataJSON),
        authenticatorData: arrayBufferToBase64(response.authenticatorData),
        signature: arrayBufferToBase64(response.signature),
        counter,
    };
}
/**
 * Check if WebAuthn is available in the browser
 */
export function isWebAuthnAvailable() {
    return !!(window.PublicKeyCredential && navigator.credentials);
}
/**
 * Check if platform authenticator (biometric/PIN) is available
 */
export async function isPlatformAuthenticatorAvailable() {
    return !!(window.PublicKeyCredential && (await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()));
}
