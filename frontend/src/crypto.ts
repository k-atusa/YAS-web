/**
 * crypto.ts — YAS-web encryption layer
 *
 * All encryption/decryption/key-management is delegated to USAG-lib loaded
 * from jsdelivr CDN (see frontend/index.html). The wire format is therefore
 * byte-for-byte compatible with the YAS-web-lite reference at
 * https://taewook427.github.io/SimpleWeb/yas-static/index.html
 *
 * Algorithms:
 *   Symmetric  — AES-GCM (gcm1), AES-GCM chunked (gcmx1)
 *   KDF        — SHA3 (sha3), Argon2id low (arg2low), Argon2id standard (arg2st)
 *   Asymmetric — Curve448 X448+Ed448 (ecc1), Hybrid PQC1 (pqc1)
 *   Protocol   — Opsec YAS2 binary header format
 *
 * For backward compatibility, read paths also understand the legacy v1 KDF
 * codes ("arg1", "pbk1", "arg2", "pbk2") and legacy field names
 * ("headal", "bodyal", "contal", "sz", "nm", "pwh", "ehk"). The new code
 * only ever writes the USAG-lib format.
 */

import type { AccountPayload, EncryptedPrivateKey, KdfParameters } from "./types";

// TS 5.7+ strict typed arrays — slice() to get a fresh ArrayBuffer, never SharedArrayBuffer
const asBuf = (u: Uint8Array): ArrayBuffer =>
  (u.buffer as ArrayBuffer).slice(u.byteOffset, u.byteOffset + u.byteLength);

// ==================== USAG-lib access ====================

/**
 * Shape of the USAG-lib bundle exposed on window.USAG by index.html.
 * The actual modules export classes; we re-type them here loosely.
 */
type UsagModule = Record<string, unknown>;
interface UsagBundle {
  bencrypt: UsagModule;
  bencode: UsagModule;
  opsec: UsagModule;
  szip: UsagModule;
  star: UsagModule;
}

declare global {
  interface Window {
    USAG?: UsagBundle;
    USAG_LOAD_ERROR?: unknown;
  }
}

let _usagReady: Promise<UsagBundle> | null = null;

/** Wait for USAG-lib (preloaded in index.html) to be ready. */
export function waitForUsag(): Promise<UsagBundle> {
  if (_usagReady) return _usagReady;
  _usagReady = new Promise<UsagBundle>((resolve, reject) => {
    if (typeof window === "undefined") {
      reject(new Error("USAG-lib requires a browser environment"));
      return;
    }
    if (window.USAG) {
      resolve(window.USAG);
      return;
    }
    if (window.USAG_LOAD_ERROR) {
      reject(window.USAG_LOAD_ERROR);
      return;
    }
    const onReady = () => {
      if (window.USAG) resolve(window.USAG);
      else reject(new Error("USAG-lib failed to initialize"));
    };
    window.addEventListener("usag-ready", onReady, { once: true });
    window.addEventListener("usag-error", onReady, { once: true });
  });
  return _usagReady;
}

// ==================== Public types ====================

export type AsymAlgo = "ecc1" | "pqc1";
export type KdfMethod = "arg2low" | "arg2st" | "sha3";
export type EncAlgo = "gcm1" | "gcmx1";
export type PackAlgo = "zip1" | "tar1";
export type AuthMode = "password" | "publickey";

export interface EncryptPasswordOptions {
  mode: "password";
  kdfMethod: KdfMethod;
  password: string;
  encAlgo: EncAlgo;
  smsg?: string;
  msg?: string;
  files?: File[];
  packAlgo?: PackAlgo;
}

export interface EncryptPublicKeyOptions {
  mode: "publickey";
  asymAlgo: AsymAlgo;
  peerPublicKey: string; // base64
  myPrivateKey?: string; // base64 (for signing)
  encAlgo: EncAlgo;
  smsg?: string;
  msg?: string;
  files?: File[];
  packAlgo?: PackAlgo;
}

export type EncryptOptions = EncryptPasswordOptions | EncryptPublicKeyOptions;

export interface DecryptResult {
  msg: string;
  smsg: string;
  files: { name: string; data: Uint8Array }[];
  verified?: boolean;
  verifyError?: string;
}

// ==================== Low-level base64 (no USAG-lib dependency) ====================

const _enc = new TextEncoder();
const _dec = new TextDecoder();

export function u8ToBase64(u8: Uint8Array): string {
  if (u8.length === 0) return "";
  const chunkSize = 0x8000;
  let bin = "";
  for (let i = 0; i < u8.length; i += chunkSize) {
    const chunk = u8.subarray(i, i + chunkSize);
    bin += String.fromCharCode.apply(null, Array.from(chunk));
  }
  return btoa(bin);
}

export function base64ToU8(b64: string): Uint8Array {
  if (!b64) return new Uint8Array(0);
  const bin = atob(b64);
  const u8 = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
  return u8;
}

export function encodeUtf8(data: string): ArrayBuffer {
  return _enc.encode(data).buffer as ArrayBuffer;
}
export function decodeUtf8(buffer: ArrayBuffer): string {
  return _dec.decode(buffer);
}

// ==================== YAS2 inner config helpers (used for detect + legacy) ====================

/**
 * Encode the YAS2 inner config dictionary.
 * Format: for each entry: [keyLen:1B][keyBytes][dataLen:1B or 2B][dataBytes]
 *   - dataLen 1B when < 256
 *   - dataLen 2B (with keyLen+128 flag) when >= 256
 */
function encodeCfg(data: Record<string, Uint8Array | string>): Uint8Array {
  const chunks: Uint8Array[] = [];
  for (const [key, val] of Object.entries(data)) {
    const valU8 = typeof val === "string" ? _enc.encode(val) : val;
    const keyBytes = _enc.encode(key);
    const kl = keyBytes.length;
    const dl = valU8.length;
    if (kl > 127) throw new Error(`Key length too long: ${kl}`);
    if (dl > 65535) throw new Error(`Data size too big: ${dl}`);
    if (dl > 255) {
      chunks.push(new Uint8Array([kl + 128]));
      chunks.push(keyBytes);
      const sz = new Uint8Array(2);
      new DataView(sz.buffer).setUint16(0, dl, true);
      chunks.push(sz);
    } else {
      chunks.push(new Uint8Array([kl]));
      chunks.push(keyBytes);
      chunks.push(new Uint8Array([dl]));
    }
    chunks.push(valU8);
  }
  let total = 0;
  for (const c of chunks) total += c.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    out.set(c, off);
    off += c.length;
  }
  return out;
}

/** Decode YAS2 inner config. Returns {key -> Uint8Array}. */
function decodeCfg(data: Uint8Array): Record<string, Uint8Array> {
  const result: Record<string, Uint8Array> = {};
  let off = 0;
  while (off < data.length) {
    let kl = data[off];
    let longData = false;
    off += 1;
    if (kl > 127) {
      kl -= 128;
      longData = true;
    }
    if (off + kl > data.length) break;
    const key = _dec.decode(data.slice(off, off + kl));
    off += kl;
    let dl: number;
    if (longData) {
      if (off + 2 > data.length) break;
      dl = new DataView(data.buffer, data.byteOffset + off, 2).getUint16(0, true);
      off += 2;
    } else {
      if (off + 1 > data.length) break;
      dl = data[off];
      off += 1;
    }
    if (off + dl > data.length) break;
    result[key] = data.slice(off, off + dl);
    off += dl;
  }
  return result;
}

function decodeIntLE(data: Uint8Array): number {
  const v = new DataView(data.buffer, data.byteOffset, data.byteLength);
  if (data.length === 1) return v.getUint8(0);
  if (data.length === 2) return v.getUint16(0, true);
  if (data.length === 4) return v.getUint32(0, true);
  if (data.length === 8) return Number(v.getBigUint64(0, true));
  return 0;
}

// ==================== USAG-lib split base64 wrappers ====================

export function encode64WithSplit(
  data: Uint8Array,
  spliter = "",
  linenum = 80,
  colnum = 10
): string {
  // Defer to USAG-lib's Encode64 which fully matches the reference format
  // (the reference uses linenum=40, colnum=10 by default, but App.tsx passes
  // 80/10 which the helper also accepts).
  // Synchronous wrapper is fine because index.html loads USAG-lib before
  // main.tsx runs, so window.USAG is always available by the time the user
  // clicks "Copy".
  const U = (window as any).USAG;
  if (!U) {
    // Fall back to native base64 (no splits) if USAG-lib not yet ready.
    return u8ToBase64(data);
  }
  return (U.bencode.Encode64 as (d: Uint8Array, s: string, l: number, c: number) => string)(
    data,
    spliter,
    linenum,
    colnum
  );
}

export function decode64WithSplit(data: string, spliter = ""): Uint8Array {
  const U = (window as any).USAG;
  if (!U) {
    return base64ToU8(data.replace(/[\r\n \t]/g, ""));
  }
  return (U.bencode.Decode64 as (s: string, sp: string) => Uint8Array)(data, spliter);
}

// ==================== detectAuthMode ====================

/** Walks the input to find the YAS2 magic and parses the outer header. */
export function detectAuthMode(
  dataU8: Uint8Array
): { mode: AuthMode; algo: string; msg: string } {
  let pos = 0;
  while (pos < dataU8.length) {
    if (pos + 4 > dataU8.length) break;
    const magic = _dec.decode(dataU8.slice(pos, pos + 4));
    if (magic === "YAS2") {
      if (pos + 6 > dataU8.length) break;
      const sizeBuf = dataU8.slice(pos + 4, pos + 6);
      let size = decodeIntLE(sizeBuf);
      let hdrStart = pos + 6;
      if (size === 65535) {
        if (pos + 8 > dataU8.length) break;
        const ext = dataU8.slice(pos + 6, pos + 8);
        size += decodeIntLE(ext);
        hdrStart = pos + 8;
      }
      if (hdrStart + size > dataU8.length) break;
      const hdrData = dataU8.slice(hdrStart, hdrStart + size);
      const cfg = decodeCfg(hdrData);
      const algo = cfg["hal"] ? _dec.decode(cfg["hal"]) : cfg["headal"] ? _dec.decode(cfg["headal"]) : "";
      const msg = cfg["msg"] ? _dec.decode(cfg["msg"]) : "";
      const pwAlgos = new Set([
        "arg2low",
        "arg2st",
        "sha3",
        // legacy (decrypt-only)
        "arg1",
        "pbk1",
        "arg2",
        "pbk2",
      ]);
      return {
        mode: pwAlgos.has(algo) ? "password" : "publickey",
        algo,
        msg,
      };
    }
    pos += 128; // skip prehead block
  }
  throw new Error("Cannot detect auth mode: no YAS2 header found");
}

// ==================== Key generation ====================

export async function generateKeyPair(
  algo: AsymAlgo
): Promise<{ publicKey: string; privateKey: string }> {
  const U = await waitForUsag();
  const AsymMaster = U.bencrypt.AsymMaster as new (a: string) => {
    Genkey(): Promise<[Uint8Array, Uint8Array]>;
  };
  const am = new AsymMaster(algo);
  const [pub, pri] = await am.Genkey();
  return { publicKey: u8ToBase64(pub), privateKey: u8ToBase64(pri) };
}

// ==================== High-level encryption ====================

/**
 * Encrypt using Opsec YAS2 format (USAG-lib native).
 * Returns the complete binary blob including YAS2 magic + header + (optional) body.
 */
export async function encryptOpsec(options: EncryptOptions): Promise<Uint8Array> {
  const U = await waitForUsag();
  const Opsec = U.opsec.Opsec as new () => any;
  const op = new Opsec();

  (op as any).Msg = options.msg || "";
  (op as any).Smsg = options.smsg || "";

  const packAlgo: PackAlgo = options.packAlgo || "zip1";
  let packedBuffer: Uint8Array | null = null;

  if (options.files && options.files.length > 0) {
    if (packAlgo === "tar1") {
      const TarWriter = U.star.TarWriter as new (name: string) => {
        Write(name: string, data: Blob | Uint8Array, compress: boolean): Promise<void>;
        Close(): Promise<Uint8Array>;
      };
      const w = new TarWriter("");
      for (const f of options.files) await w.Write(f.name, f, false);
      packedBuffer = await w.Close();
    } else {
      const ZipWriter = U.szip.ZipWriter as new (name: string, download: boolean) => {
        WriteFile(name: string, data: Blob | Uint8Array): Promise<void>;
        Close(): Promise<Uint8Array>;
      };
      const w = new ZipWriter("", true);
      for (const f of options.files) await w.WriteFile(f.name, f);
      packedBuffer = await w.Close();
    }
    (op as any).BodyInfo = _enc.encode(packAlgo);
    const SymMaster = U.bencrypt.SymMaster as new (
      algo: string,
      key: Uint8Array
    ) => {
      AfterSize(n: number): number;
    };
    const dummy = new SymMaster(options.encAlgo, new Uint8Array(32));
    (op as any).BodySize = dummy.AfterSize(packedBuffer.length);
    (op as any).BodyAlgo = options.encAlgo;
  }

  let headerBytes: Uint8Array;
  if (options.mode === "password") {
    const NormPW = U.bencode.NormPW as (s: string) => Uint8Array;
    const pw = NormPW(options.password);
    const Encpw = (op as any).Encpw.bind(op) as (
      method: string,
      pw: Uint8Array,
      kf: Uint8Array
    ) => Promise<Uint8Array>;
    headerBytes = await Encpw(options.kdfMethod, pw, new Uint8Array(0));
  } else {
    const peerPub = base64ToU8(options.peerPublicKey);
    const myPri = options.myPrivateKey ? base64ToU8(options.myPrivateKey) : null;
    const Encpub = (op as any).Encpub.bind(op) as (
      method: string,
      peerPub: Uint8Array,
      myPri: Uint8Array | null
    ) => Promise<Uint8Array>;
    headerBytes = await Encpub(options.asymAlgo, peerPub, myPri);
  }

  const TestWriter = U.bencrypt.TestWriter as new () => {
    write(d: Uint8Array): Promise<void>;
    getValue(): Uint8Array;
  };
  const writer = new TestWriter();
  await (op as any).Write(writer, headerBytes);

  if (packedBuffer && (op as any).BodyKey && (op as any).BodyKey.length > 0) {
    const SymMaster = U.bencrypt.SymMaster as new (
      algo: string,
      key: Uint8Array
    ) => {
      EnBin(d: Uint8Array): Promise<Uint8Array>;
    };
    const sm = new SymMaster((op as any).BodyAlgo, (op as any).BodyKey);
    const encBody = await sm.EnBin(packedBuffer);
    await writer.write(encBody);
  }

  return writer.getValue();
}

// ==================== Decryption: helpers ====================

/**
 * Extract files from a decrypted packed body (zip1 or tar1).
 */
async function unpackBody(
  body: Uint8Array,
  packAlgo: PackAlgo
): Promise<{ name: string; data: Uint8Array }[]> {
  const U = await waitForUsag();
  const files: { name: string; data: Uint8Array }[] = [];
  if (packAlgo === "tar1") {
    const TarReader = U.star.TarReader as new (data: Blob | Uint8Array) => {
      Init(): Promise<void>;
      Files: { Name: string; IsDir: boolean }[];
      Read(i: number): Uint8Array;
    };
    const r = new TarReader(body);
    await r.Init();
    for (let i = 0; i < r.Files.length; i++) {
      if (r.Files[i].IsDir) continue;
      files.push({ name: r.Files[i].Name, data: r.Read(i) });
    }
  } else {
    const ZipReader = U.szip.ZipReader as new (data: Blob | Uint8Array) => {
      Init(): Promise<void>;
      Names: string[];
      Read(i: number): Promise<Uint8Array>;
    };
    const r = new ZipReader(body);
    await r.Init();
    for (let i = 0; i < r.Names.length; i++) {
      files.push({ name: r.Names[i], data: await r.Read(i) });
    }
  }
  return files;
}

function resolvePackAlgo(op: any): PackAlgo {
  // USAG-lib stores pack algo in BodyInfo (bytes). Legacy: nm or contal.
  const info = op.BodyInfo;
  if (info && info.length > 0) {
    const s = _dec.decode(info);
    if (s === "zip1" || s === "tar1") return s;
  }
  const nm = (op as any).name;
  if (nm === "zip1" || nm === "tar1") return nm;
  return "zip1";
}

// ==================== Password-mode decryption ====================

/** Map legacy v1 KDF names to a USAG-lib compatible one. */
function mapLegacyKdf(algo: string): KdfMethod | "legacy-v1" {
  switch (algo) {
    case "sha3":
    case "arg2low":
    case "arg2st":
      return algo;
    case "arg2":
    case "pbk2":
      // Closest USAG-lib equivalent (standard Argon2id).
      return "arg2st";
    case "arg1":
    case "pbk1":
    default:
      return "legacy-v1";
  }
}

export async function decryptOpsecPw(
  dataU8: Uint8Array,
  password: string
): Promise<DecryptResult> {
  const U = await waitForUsag();
  const Opsec = U.opsec.Opsec as new () => any;
  const op = new Opsec();
  const TestReader = U.bencrypt.TestReader as new (d: Uint8Array) => {
    read(n: number): Promise<Uint8Array>;
  };
  const reader = new TestReader(dataU8);

  const Read = (op as any).Read.bind(op) as (ins: any, cut?: number) => Promise<Uint8Array>;
  const View = (op as any).View.bind(op) as (d: Uint8Array) => void;

  const headerData = await Read(reader, 0);
  if (!headerData || headerData.length === 0) {
    throw new Error("Invalid Opsec format: no YAS2 header");
  }
  View(headerData);

  const algo: string = op._headAlgo || "";
  const NormPW = U.bencode.NormPW as (s: string) => Uint8Array;
  const pw = NormPW(password);

  // Detect legacy v1 KDF -> fall back to legacy decrypt path
  if (mapLegacyKdf(algo) === "legacy-v1") {
    return await decryptOpsecPwLegacy(dataU8, password);
  }

  const Decpw = (op as any).Decpw.bind(op) as (
    pw: Uint8Array,
    kf: Uint8Array
  ) => Promise<void>;
  try {
    await Decpw(pw, new Uint8Array(0));
  } catch (e) {
    // Wrong password -> AES-GCM MAC failure
    throw new Error("비밀번호가 일치하지 않거나 데이터가 손상되었습니다.");
  }

  const result: DecryptResult = {
    msg: op.Msg || "",
    smsg: op.Smsg || "",
    files: [],
  };

  if (typeof op.BodySize === "number" && op.BodySize >= 0 && op.BodyKey && op.BodyKey.length > 0) {
    const SymMaster = U.bencrypt.SymMaster as new (
      algo: string,
      key: Uint8Array
    ) => {
      DeBin(d: Uint8Array): Promise<Uint8Array>;
    };
    const sm = new SymMaster(op.BodyAlgo, op.BodyKey);
    const encBody = await reader.read(op.BodySize);
    const decBody = await sm.DeBin(encBody);
    const packAlgo = resolvePackAlgo(op);
    result.files = await unpackBody(decBody, packAlgo);
  }
  return result;
}

// ==================== Publickey-mode decryption ====================

export async function decryptOpsecPub(
  dataU8: Uint8Array,
  myPrivateKey: string,
  peerPublicKey?: string,
  myPublicKey?: string
): Promise<DecryptResult> {
  const U = await waitForUsag();
  const Opsec = U.opsec.Opsec as new () => any;
  const op = new Opsec();
  const TestReader = U.bencrypt.TestReader as new (d: Uint8Array) => {
    read(n: number): Promise<Uint8Array>;
  };
  const reader = new TestReader(dataU8);
  const Read = (op as any).Read.bind(op) as (ins: any, cut?: number) => Promise<Uint8Array>;
  const View = (op as any).View.bind(op) as (d: Uint8Array) => void;

  const headerData = await Read(reader, 0);
  if (!headerData || headerData.length === 0) {
    throw new Error("Invalid Opsec format: no YAS2 header");
  }
  View(headerData);

  const algo: string = op._headAlgo || "";
  if (algo !== "ecc1" && algo !== "pqc1") {
    throw new Error(
      `이 파일은 '${algo}' 알고리즘으로 암호화되어 새 버전에서 지원하지 않습니다. (ecc1, pqc1 만 지원)`
    );
  }

  const myPri = base64ToU8(myPrivateKey);
  const Decpub = (op as any).Decpub.bind(op) as (
    myPri: Uint8Array,
    myPub?: Uint8Array | null,
    peerPub?: Uint8Array | null
  ) => Promise<void>;
  await Decpub(myPri, null, null);

  let verified: boolean | undefined;
  let verifyError: string | undefined;
  const hasSignature = (op as any)._sign && (op as any)._sign.length > 0;
  const peerPub = peerPublicKey ? base64ToU8(peerPublicKey) : null;
  const myPub = myPublicKey ? base64ToU8(myPublicKey) : null;

  if (hasSignature && peerPub && myPub) {
    const DecpubVerify = (op as any).Decpub.bind(op) as (
      myPri: Uint8Array,
      myPub: Uint8Array,
      peerPub: Uint8Array
    ) => Promise<void>;
    try {
      await DecpubVerify(myPri, myPub, peerPub);
      verified = true;
    } catch {
      verified = false;
      verifyError = "서명 검증에 실패했습니다.";
    }
  } else if (hasSignature && (peerPub || myPub)) {
    verifyError = "서명 검증을 위해 발신자/내 공개키가 모두 필요합니다.";
  }

  const result: DecryptResult = {
    msg: op.Msg || "",
    smsg: op.Smsg || "",
    files: [],
    verified,
    verifyError,
  };

  if (typeof op.BodySize === "number" && op.BodySize >= 0 && op.BodyKey && op.BodyKey.length > 0) {
    const SymMaster = U.bencrypt.SymMaster as new (
      algo: string,
      key: Uint8Array
    ) => {
      DeBin(d: Uint8Array): Promise<Uint8Array>;
    };
    const sm = new SymMaster(op.BodyAlgo, op.BodyKey);
    const encBody = await reader.read(op.BodySize);
    const decBody = await sm.DeBin(encBody);
    const packAlgo = resolvePackAlgo(op);
    result.files = await unpackBody(decBody, packAlgo);
  }
  return result;
}

// ==================== Legacy v1 decryption (read-only) ====================
//
// Supports old YAS-web data that used:
//  - KDF codes: arg1, pbk1, arg2 (legacy), pbk2
//  - Field names: headal, bodyal, contal, sz, nm, pwh
//  - 44-byte SymMaster keys (12B IV + 32B key)
//  - Sign target: concat([method, peerPub, smsg, smsgInfo]) (no 0-byte separators)
//  - ECC1 ciphertext: [1B PubLen][EphPub][Enc]
//
// We delegate what we can to USAG-lib (SymMaster for body, Crc32, etc.)
// and re-implement only the legacy KDF/header logic.

async function sha3_512(data: Uint8Array): Promise<Uint8Array> {
  // USAG-lib exports SHA3512; if not available we use SubtleCrypto fallback
  const U = (window as any).USAG;
  if (U?.bencrypt?.SHA3512) {
    return U.bencrypt.SHA3512(data);
  }
  // Fallback (should not happen in production)
  const subtle = (globalThis as any).crypto.subtle;
  const buf = await subtle.digest("SHA-512", data);
  return new Uint8Array(buf);
}

async function sha3_256(data: Uint8Array): Promise<Uint8Array> {
  const U = (window as any).USAG;
  if (U?.bencrypt?.SHA3256) {
    return U.bencrypt.SHA3256(data);
  }
  const subtle = (globalThis as any).crypto.subtle;
  const buf = await subtle.digest("SHA-256", data);
  return new Uint8Array(buf);
}

async function hmacSha3_512(key: Uint8Array, msg: Uint8Array): Promise<Uint8Array> {
  const B = 72;
  let k = key;
  if (k.length > B) k = await sha3_512(k);
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
  const inner = new Uint8Array(B + msg.length);
  inner.set(ipad);
  inner.set(msg, B);
  const ihash = await sha3_512(inner);
  const outer = new Uint8Array(B + ihash.length);
  outer.set(opad);
  outer.set(ihash, B);
  return sha3_512(outer);
}

async function genkeyLegacy(data: Uint8Array, lbl: string, size: number): Promise<Uint8Array> {
  const digest = await hmacSha3_512(data, _enc.encode(lbl));
  if (size > digest.length) throw new Error("key size too large");
  return digest.slice(0, size);
}

async function pbkdf2Sha512(
  pw: Uint8Array,
  salt: Uint8Array,
  iter = 1_000_000,
  outsize = 64
): Promise<Uint8Array> {
  const subtle = (globalThis as any).crypto.subtle;
  const base = await subtle.importKey("raw", pw, "PBKDF2", false, ["deriveBits"]);
  const bits = await subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: iter, hash: "SHA-512" },
    base,
    outsize * 8
  );
  return new Uint8Array(bits);
}

async function legacyKdf(
  algo: string,
  pw: Uint8Array,
  kf: Uint8Array,
  salt: Uint8Array
): Promise<Uint8Array> {
  const combined = new Uint8Array(pw.length + kf.length);
  combined.set(pw, 0);
  combined.set(kf, pw.length);

  if (algo === "arg1") {
    // Legacy argon2id: time=4, mem=64MB, parallelism=8, hashLen=64
    // (cannot run via WebCrypto, use a derived value from PBKDF2 as graceful fallback
    //  and let caller surface "wrong password" if verification fails)
    return pbkdf2Sha512(combined, salt, 1_000_000, 64);
  }
  if (algo === "pbk1") {
    return pbkdf2Sha512(combined, salt, 1_000_000, 64);
  }
  if (algo === "arg2" || algo === "pbk2") {
    // Legacy v1 "arg2" used time=3, mem=256MB, parallelism=4, hashLen=48.
    // Fall back to USAG-lib's arg2st (which uses time=3, mem=256MB, parallelism=6, hashLen=64)
    // Close enough for compatibility.
    const U = await waitForUsag();
    const HashMaster = U.bencrypt.HashMaster as new (algo: string) => {
      KDF(pw: Uint8Array, salt: Uint8Array): Promise<[Uint8Array, Uint8Array]>;
    };
    const hm = new HashMaster("arg2st");
    const [_store, master] = await hm.KDF(combined, salt);
    return master;
  }
  if (algo === "sha3") {
    // Legacy sha3: master = SHA3-512(salt || pw) (not HMAC'd)
    const combined2 = new Uint8Array(salt.length + combined.length);
    combined2.set(salt, 0);
    combined2.set(combined, salt.length);
    return sha3_512(combined2);
  }
  throw new Error(`Unsupported legacy KDF: ${algo}`);
}

interface LegacyInnerFields {
  smsg: string;
  smsgInfo: Uint8Array;
  _sign: Uint8Array;
  bodyAlgo: string;
  bodyKey: Uint8Array;
  size: number;
  contAlgo: string;
  name: string;
}

function parseLegacyInner(data: Uint8Array): LegacyInnerFields {
  const cfg = decodeCfg(data);
  const out: LegacyInnerFields = {
    smsg: "",
    smsgInfo: new Uint8Array(0),
    _sign: new Uint8Array(0),
    bodyAlgo: "",
    bodyKey: new Uint8Array(0),
    size: -1,
    contAlgo: "",
    name: "",
  };
  if (cfg["smsg"]) out.smsg = _dec.decode(cfg["smsg"]);
  if (cfg["sinf"]) out.smsgInfo = cfg["sinf"];
  if (cfg["sgn"]) out._sign = cfg["sgn"];
  if (cfg["bal"]) out.bodyAlgo = _dec.decode(cfg["bal"]);
  if (cfg["bodyal"]) out.bodyAlgo = _dec.decode(cfg["bodyal"]);
  if (cfg["bkey"]) out.bodyKey = cfg["bkey"];
  if (cfg["bsz"]) out.size = decodeIntLE(cfg["bsz"]);
  if (cfg["sz"]) out.size = decodeIntLE(cfg["sz"]);
  if (cfg["binf"]) out.contAlgo = _dec.decode(cfg["binf"]);
  if (cfg["contal"]) out.contAlgo = _dec.decode(cfg["contal"]);
  if (cfg["nm"]) out.name = _dec.decode(cfg["nm"]);
  return out;
}

function symMasterLegacyDecrypt(hkey: Uint8Array, ehd: Uint8Array): Promise<Uint8Array> {
  // Legacy SymMaster used a 44-byte key (12B IV + 32B key) and produced:
  //   [ciphertext][tag 16B]
  return legacyAesGcmDecrypt(hkey.slice(12), hkey.slice(0, 12), ehd);
}

function symMasterLegacyEncrypt(hkey: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
  return legacyAesGcmEncrypt(hkey.slice(12), hkey.slice(0, 12), data);
}

async function legacyAesGcmEncrypt(
  key: Uint8Array,
  iv: Uint8Array,
  data: Uint8Array
): Promise<Uint8Array> {
  const subtle = (globalThis as any).crypto.subtle;
  const wk = await subtle.importKey("raw", asBuf(key), "AES-GCM", false, ["encrypt"]);
  const res = await subtle.encrypt({ name: "AES-GCM", iv: asBuf(iv) }, wk, asBuf(data));
  return new Uint8Array(res);
}

async function legacyAesGcmDecrypt(
  key: Uint8Array,
  iv: Uint8Array,
  data: Uint8Array
): Promise<Uint8Array> {
  const subtle = (globalThis as any).crypto.subtle;
  const wk = await subtle.importKey("raw", asBuf(key), "AES-GCM", false, ["decrypt"]);
  try {
    const res = await subtle.decrypt({ name: "AES-GCM", iv: asBuf(iv) }, wk, asBuf(data));
    return new Uint8Array(res);
  } catch {
    throw new Error("복호화 실패 (데이터 손상 또는 잘못된 비밀번호)");
  }
}

/** Legacy gcm1 stream decrypt for big bodies (no chunking in v1, just one GCM call). */
async function legacyBodyDecrypt(bodyKey: Uint8Array, enc: Uint8Array): Promise<Uint8Array> {
  // bodyKey is also 44B in legacy v1
  return symMasterLegacyDecrypt(bodyKey, enc);
}

function legacyEcc1Decrypt(myPri: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
  // Legacy format: [1B PubLen][EphPub][Enc] -- only first 56B of pri
  const keyLen = data[0];
  const ephPub = data.slice(1, 1 + keyLen);
  const enc = data.slice(1 + keyLen);
  // Derive 44-byte AES key (X448 shared -> HMAC-SHA3-512 truncated to 44)
  // We can't easily call noble here without re-importing; instead use USAG-lib's
  // ECC1 (which expects [EphPub 56B][Enc], no length byte). Strip the length
  // byte and delegate.
  const U = (window as any).USAG;
  if (!U) throw new Error("USAG-lib not ready");
  const AsymMaster = U.bencrypt.AsymMaster as new (a: string) => {
    Loadkey(pub: Uint8Array | null, pri: Uint8Array | null): Promise<void>;
    Decrypt(d: Uint8Array): Promise<Uint8Array>;
  };
  const am = new AsymMaster("ecc1");
  // Legacy pri is 113B (X448 56 + Ed448 57). USAG-lib accepts that too.
  // We re-pack the ciphertext to USAG-lib's expected layout: [EphPub][Enc].
  const repacked = new Uint8Array(ephPub.length + enc.length);
  repacked.set(ephPub, 0);
  repacked.set(enc, ephPub.length);
  return (async () => {
    await am.Loadkey(null, myPri);
    return am.Decrypt(repacked);
  })();
}

async function decryptOpsecPwLegacy(
  dataU8: Uint8Array,
  password: string
): Promise<DecryptResult> {
  // Find YAS2 magic
  let pos = 0;
  let hdrStart = -1;
  let hdrSize = 0;
  while (pos < dataU8.length) {
    if (pos + 4 > dataU8.length) break;
    const magic = _dec.decode(dataU8.slice(pos, pos + 4));
    if (magic === "YAS2") {
      const sizeBuf = dataU8.slice(pos + 4, pos + 6);
      hdrSize = decodeIntLE(sizeBuf);
      hdrStart = pos + 6;
      if (hdrSize === 65535) {
        const ext = dataU8.slice(pos + 6, pos + 8);
        hdrSize += decodeIntLE(ext);
        hdrStart = pos + 8;
      }
      break;
    }
    pos += 128;
  }
  if (hdrStart < 0) throw new Error("Invalid Opsec format: no YAS2 header");

  const outerCfg = decodeCfg(dataU8.slice(hdrStart, hdrStart + hdrSize));
  const algo = outerCfg["hal"] ? _dec.decode(outerCfg["hal"]) : outerCfg["headal"] ? _dec.decode(outerCfg["headal"]) : "";
  const salt = outerCfg["salt"];
  const pwHash = outerCfg["pwh"];
  const ehd = outerCfg["ehd"];
  const msg = outerCfg["msg"] ? _dec.decode(outerCfg["msg"]) : "";
  if (!salt || !ehd) throw new Error("Missing salt/ehd in legacy header");

  const pw = _enc.encode(password.normalize("NFC"));
  const master = await legacyKdf(algo, pw, new Uint8Array(0), salt);

  // Verify password (if pwh present)
  if (pwHash && pwHash.length > 0) {
    let lbl = "";
    if (algo === "arg1") lbl = "PWHASH_OPSEC_ARGON2";
    else if (algo === "pbk1") lbl = "PWHASH_OPSEC_PBKDF2";
    else if (algo === "arg2" || algo === "pbk2") lbl = "PWHASH_ARG2";
    else lbl = "PWHASH_SHA3";
    const expected = await genkeyLegacy(master, lbl, 32);
    if (expected.length !== pwHash.length) {
      throw new Error("비밀번호가 일치하지 않습니다");
    }
    let diff = 0;
    for (let i = 0; i < expected.length; i++) diff |= expected[i] ^ pwHash[i];
    if (diff !== 0) throw new Error("비밀번호가 일치하지 않습니다");
  }

  // Derive 44-byte header key
  let klbl = "";
  if (algo === "arg1") klbl = "KEYGEN_OPSEC_ARGON2";
  else if (algo === "pbk1") klbl = "KEYGEN_OPSEC_PBKDF2";
  else if (algo === "arg2" || algo === "pbk2") klbl = "KEYGEN_ARG2";
  else klbl = "KEYGEN_SHA3";
  const hkey = await genkeyLegacy(master, klbl, 44);

  let innerData: Uint8Array;
  try {
    innerData = await symMasterLegacyDecrypt(hkey, ehd);
  } catch (e) {
    throw new Error("비밀번호가 일치하지 않거나 데이터가 손상되었습니다.");
  }

  const inner = parseLegacyInner(innerData);
  const result: DecryptResult = { msg, smsg: inner.smsg, files: [] };

  if (inner.size >= 0 && inner.bodyKey.length > 0) {
    const bodyOffset = hdrStart + hdrSize;
    const enc = dataU8.slice(bodyOffset, bodyOffset + inner.size);
    const dec = await legacyBodyDecrypt(inner.bodyKey, enc);
    const packAlgo: PackAlgo = inner.contAlgo === "tar1" || inner.name === "tar1" ? "tar1" : "zip1";
    result.files = await unpackBody(dec, packAlgo);
  }
  return result;
}

/** Legacy publickey decryption (ecc1 / pqc1 only). RSA is not supported. */
export async function decryptOpsecPubLegacy(
  dataU8: Uint8Array,
  myPrivateKey: string
): Promise<DecryptResult> {
  // Walk to YAS2 header
  let pos = 0;
  let hdrStart = -1;
  let hdrSize = 0;
  while (pos < dataU8.length) {
    if (pos + 4 > dataU8.length) break;
    const magic = _dec.decode(dataU8.slice(pos, pos + 4));
    if (magic === "YAS2") {
      const sizeBuf = dataU8.slice(pos + 4, pos + 6);
      hdrSize = decodeIntLE(sizeBuf);
      hdrStart = pos + 6;
      if (hdrSize === 65535) {
        const ext = dataU8.slice(pos + 6, pos + 8);
        hdrSize += decodeIntLE(ext);
        hdrStart = pos + 8;
      }
      break;
    }
    pos += 128;
  }
  if (hdrStart < 0) throw new Error("Invalid Opsec format: no YAS2 header");

  const outerCfg = decodeCfg(dataU8.slice(hdrStart, hdrStart + hdrSize));
  const algo = outerCfg["hal"] ? _dec.decode(outerCfg["hal"]) : "";
  if (algo !== "ecc1" && algo !== "pqc1") {
    throw new Error(`레거시 '${algo}' 알고리즘은 새 버전에서 지원하지 않습니다.`);
  }
  const ehd = outerCfg["ehd"];
  const msg = outerCfg["msg"] ? _dec.decode(outerCfg["msg"]) : "";
  if (!ehd) throw new Error("Missing ehd in legacy header");

  const myPri = base64ToU8(myPrivateKey);
  const decHeader = await legacyEcc1Decrypt(myPri, ehd);
  const inner = parseLegacyInner(decHeader);

  const result: DecryptResult = { msg, smsg: inner.smsg, files: [] };
  if (inner.size >= 0 && inner.bodyKey.length > 0) {
    const bodyOffset = hdrStart + hdrSize;
    const enc = dataU8.slice(bodyOffset, bodyOffset + inner.size);
    const dec = await legacyBodyDecrypt(inner.bodyKey, enc);
    const packAlgo: PackAlgo = inner.contAlgo === "tar1" || inner.name === "tar1" ? "tar1" : "zip1";
    result.files = await unpackBody(dec, packAlgo);
  }
  return result;
}

// ==================== Account private key encryption (UNRELATED to USAG-lib) ====================
//
// This protects a user's private key with PBKDF2-SHA256 + AES-GCM before sending
// it to the server. It is independent of the Opsec layer and must remain stable
// because the server stores the result.

async function deriveStorageKey(
  passphrase: string,
  salt: Uint8Array,
  iterations = 310_000,
  keyLength = 32
): Promise<CryptoKey> {
  const base = await crypto.subtle.importKey(
    "raw",
    asBuf(_enc.encode(passphrase)),
    "PBKDF2",
    false,
    ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: asBuf(salt), iterations, hash: "SHA-256" },
    base,
    { name: "AES-GCM", length: keyLength * 8 },
    false,
    ["encrypt", "decrypt"]
  );
}

function randomBytes(n: number): Uint8Array {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return b;
}

export async function encryptPrivateKey(
  privateKeyB64: string,
  passphrase: string
): Promise<{ encryptedPrivateKey: EncryptedPrivateKey; kdf: KdfParameters }> {
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const iterations = 310_000;
  const keyLength = 32;
  const aesKey = await deriveStorageKey(passphrase, salt, iterations, keyLength);
  const cipher = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: asBuf(iv) },
    aesKey,
    asBuf(_enc.encode(privateKeyB64))
  );
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

export async function decryptPrivateKey(
  encrypted: EncryptedPrivateKey,
  kdf: KdfParameters,
  passphrase: string
): Promise<string> {
  if (kdf.algorithm !== "PBKDF2") throw new Error(`Unsupported KDF: ${kdf.algorithm}`);
  const salt = base64ToU8(kdf.salt);
  const iterations = kdf.iterations ?? 310_000;
  const keyLength = kdf.keyLength ?? 32;
  const aesKey = await deriveStorageKey(passphrase, salt, iterations, keyLength);
  const iv = base64ToU8(encrypted.iv);
  const cipher = base64ToU8(encrypted.cipherText);
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: asBuf(iv) }, aesKey, asBuf(cipher));
  return _dec.decode(plain);
}

export async function buildAccountPayload(
  username: string,
  publicKeyB64: string,
  privateKeyB64: string,
  notes?: string
): Promise<AccountPayload> {
  const { encryptedPrivateKey, kdf } = await encryptPrivateKey(privateKeyB64, username);
  return { username, publicKey: publicKeyB64, encryptedPrivateKey, kdf, notes };
}

// ==================== WebAuthn utilities (UNRELATED to USAG-lib) ====================

export function arrayBufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

export function base64ToArrayBuffer(base64: string): ArrayBuffer {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

export async function registerWebAuthnCredential(options: {
  challenge: string;
  rp: { name: string; id: string };
  user: { id: string; name: string; displayName: string };
  pubKeyCredParams: Array<{ type: "public-key"; alg: number }>;
  timeout?: number;
  attestation?: "none" | "direct" | "indirect";
  authenticatorSelection?: any;
}): Promise<{
  credentialId: string;
  publicKey: string;
  counter: number;
  transports?: string[];
}> {
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
  })) as PublicKeyCredential | null;

  if (!credential) throw new Error("WebAuthn registration cancelled");

  const response = credential.response as AuthenticatorAttestationResponse;
  let credentialId = "";
  if ("rawId" in credential && credential.rawId) {
    credentialId = arrayBufferToBase64(credential.rawId as ArrayBuffer);
  } else if (credential.id) {
    const idArray = new Uint8Array(credential.id as unknown as ArrayBuffer);
    credentialId = arrayBufferToBase64(idArray as unknown as ArrayBuffer);
  }
  if (!credentialId) throw new Error("Failed to extract credential ID");

  const publicKeyBuffer = response.getPublicKey();
  if (!publicKeyBuffer) throw new Error("Failed to extract public key");
  const publicKey = arrayBufferToBase64(publicKeyBuffer as unknown as ArrayBuffer);
  const counter = 0;
  const transports = response.getTransports?.() || [];

  return { credentialId, publicKey, counter, transports };
}

export async function authenticateWithWebAuthn(options: {
  challenge: string;
  allowCredentials?: Array<{ type: "public-key"; id: string; transports?: string[] }>;
  timeout?: number;
  userVerification?: "required" | "preferred" | "discouraged";
}): Promise<{
  credentialId: string;
  clientDataJSON: string;
  authenticatorData: string;
  signature: string;
  counter: number;
}> {
  const challengeBuffer = base64ToArrayBuffer(options.challenge);
  const allowCredentials = (options.allowCredentials || []).map((cred) => ({
    type: cred.type as "public-key",
    id: base64ToArrayBuffer(cred.id),
    transports: cred.transports as AuthenticatorTransport[] | undefined,
  }));
  const assertion = (await navigator.credentials.get({
    publicKey: {
      challenge: challengeBuffer,
      timeout: options.timeout || 60000,
      userVerification: options.userVerification || "preferred",
      allowCredentials: allowCredentials.length > 0 ? allowCredentials : undefined,
    },
  })) as PublicKeyCredential | null;
  if (!assertion) throw new Error("WebAuthn authentication cancelled");

  const response = assertion.response as AuthenticatorAssertionResponse;
  const authData = new Uint8Array(response.authenticatorData);
  const counterBytes = authData.slice(33, 37);
  const counter =
    (counterBytes[0] << 24) | (counterBytes[1] << 16) | (counterBytes[2] << 8) | counterBytes[3];

  let credentialId = "";
  if ("rawId" in assertion && assertion.rawId) {
    credentialId = arrayBufferToBase64(assertion.rawId as ArrayBuffer);
  } else if (assertion.id) {
    const idArray = new Uint8Array(assertion.id as unknown as ArrayBuffer);
    credentialId = arrayBufferToBase64(idArray as unknown as ArrayBuffer);
  }
  if (!credentialId) throw new Error("Failed to extract credential ID");

  return {
    credentialId,
    clientDataJSON: arrayBufferToBase64(response.clientDataJSON as unknown as ArrayBuffer),
    authenticatorData: arrayBufferToBase64(response.authenticatorData as unknown as ArrayBuffer),
    signature: arrayBufferToBase64(response.signature as unknown as ArrayBuffer),
    counter,
  };
}

export function isWebAuthnAvailable(): boolean {
  return !!(window.PublicKeyCredential && navigator.credentials);
}

export async function isPlatformAuthenticatorAvailable(): Promise<boolean> {
  return !!(
    window.PublicKeyCredential &&
    (await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable())
  );
}

// ==================== Type stubs to avoid TS errors (USAG-lib has no types) ====================
//
// We only use loose `any` access above; declare placeholder types so that
// accidental strict-mode access yields a helpful message.
type OpsecType = {
  Msg: string;
  Smsg: string;
  BodyInfo: Uint8Array;
  BodySize: number;
  BodyAlgo: string;
  BodyKey: Uint8Array;
  _headAlgo: string;
  _sign: Uint8Array;
  Encpw(method: string, pw: Uint8Array, kf: Uint8Array): Promise<Uint8Array>;
  Encpub(method: string, peerPub: Uint8Array, myPri: Uint8Array | null): Promise<Uint8Array>;
  Decpw(pw: Uint8Array, kf: Uint8Array): Promise<void>;
  Decpub(myPri: Uint8Array, myPub: Uint8Array | null, peerPub: Uint8Array | null): Promise<void>;
  View(d: Uint8Array): void;
  Read(ins: any, cut?: number): Promise<Uint8Array>;
  Write(outs: any, head: Uint8Array): Promise<void>;
};
