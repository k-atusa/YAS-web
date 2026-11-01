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
 *   KDF        — Argon2id standard (arg2st)
 *   Asymmetric — Hybrid PQC1 (pqc1)
 *   Protocol   — Opsec YAS2 binary header format
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
function waitForUsag(): Promise<UsagBundle> {
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

export type AsymAlgo = "pqc1";
export type KdfMethod = "arg2st";
export type EncAlgo = "gcm1" | "gcmx1";
type PackAlgo = "zip1" | "tar1";
export type AuthMode = "password" | "publickey";

interface EncryptPasswordOptions {
  mode: "password";
  kdfMethod?: KdfMethod;
  password: string;
  encAlgo: EncAlgo;
  smsg?: string;
  msg?: string;
  files?: File[];
  packAlgo?: PackAlgo;
}

interface EncryptPublicKeyOptions {
  mode: "publickey";
  asymAlgo?: AsymAlgo;
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

function u8ToBase64(u8: Uint8Array): string {
  if (u8.length === 0) return "";
  const chunkSize = 0x8000;
  let bin = "";
  for (let i = 0; i < u8.length; i += chunkSize) {
    const chunk = u8.subarray(i, i + chunkSize);
    bin += String.fromCharCode.apply(null, Array.from(chunk));
  }
  return btoa(bin);
}

export function base64UrlToBase64(str: string): string {
  if (!str) return "";
  let output = str.replace(/-/g, "+").replace(/_/g, "/").replace(/\s/g, "");
  const mod4 = output.length % 4;
  if (mod4 === 2) {
    output += "==";
  } else if (mod4 === 3) {
    output += "=";
  } else if (mod4 === 1) {
    throw new Error("Invalid base64 string length");
  }
  return output;
}

export function base64ToU8(b64: string): Uint8Array {
  if (!b64) return new Uint8Array(0);
  const normalized = base64UrlToBase64(b64);
  const bin = atob(normalized);
  const u8 = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
  return u8;
}

// ==================== YAS2 inner config helpers (used for detect + legacy) ====================

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
      const pwAlgos = new Set(["arg2st", "arg2"]);
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
  _algo?: AsymAlgo
): Promise<{ publicKey: string; privateKey: string }> {
  const U = await waitForUsag();
  const AsymMaster = U.bencrypt.AsymMaster as new (a: string) => {
    Genkey(): Promise<[Uint8Array, Uint8Array]>;
  };
  const am = new AsymMaster("pqc1");
  const [pub, pri] = await am.Genkey();
  return { publicKey: u8ToBase64(pub), privateKey: u8ToBase64(pri) };
}

// ==================== Key cleaning & validation ====================

export function cleanBase64Key(raw: string): string {
  if (!raw) return "";
  let cleaned = raw.trim();
  cleaned = cleaned.replace(/-----BEGIN [^-]+-----/g, "");
  cleaned = cleaned.replace(/-----END [^-]+-----/g, "");
  cleaned = cleaned.replace(/\s+/g, "");
  return cleaned;
}

export async function validateKeyPair(
  publicKeyInput: string,
  privateKeyInput: string
): Promise<{ valid: boolean; error?: string; cleanPublicKey?: string; cleanPrivateKey?: string }> {
  const pubClean = cleanBase64Key(publicKeyInput);
  const priClean = cleanBase64Key(privateKeyInput);

  if (!pubClean) {
    return { valid: false, error: "공개키를 입력해주세요." };
  }
  if (!priClean) {
    return { valid: false, error: "개인키를 입력해주세요." };
  }

  let pubU8: Uint8Array;
  try {
    pubU8 = base64ToU8(pubClean);
  } catch {
    return { valid: false, error: "공개키가 올바른 암호문 형식이 아닙니다." };
  }

  let priU8: Uint8Array;
  try {
    priU8 = base64ToU8(priClean);
  } catch {
    return { valid: false, error: "개인키가 올바른 암호문 형식이 아닙니다." };
  }

  if (pubU8.length !== 4273) {
    return {
      valid: false,
      error: `공개키 형식이 올바르지 않습니다. (디코딩 크기: ${pubU8.length}B, 필요: 4273B)`,
    };
  }

  if (priU8.length !== 8177) {
    return {
      valid: false,
      error: `개인키 형식이 올바르지 않습니다. (디코딩 크기: ${priU8.length}B, 필요: 8177B)`,
    };
  }

  try {
    const U = await waitForUsag();
    const AsymMaster = U.bencrypt.AsymMaster as new (a: string) => {
      Loadkey(publicBuf: Uint8Array | null, privateBuf: Uint8Array | null): Promise<void>;
      Sign(data: Uint8Array): Promise<Uint8Array>;
      Verify(data: Uint8Array, signature: Uint8Array): Promise<boolean>;
      Encrypt(data: Uint8Array): Promise<Uint8Array>;
      Decrypt(data: Uint8Array): Promise<Uint8Array>;
    };

    const am = new AsymMaster("pqc1");
    try {
      await am.Loadkey(pubU8, priU8);
    } catch (e) {
      return { valid: false, error: `키 로드 실패: ${(e as Error).message}` };
    }

    // Verify key pair match using digital signature
    const testPayload = new Uint8Array([89, 65, 83, 45, 87, 69, 66]); // "YAS-WEB"
    try {
      const signature = await am.Sign(testPayload);
      const isVerified = await am.Verify(testPayload, signature);
      if (!isVerified) {
        return { valid: false, error: "공개키와 개인키가 일치하지 않는 쌍입니다." };
      }
    } catch (e) {
      return { valid: false, error: `서명 검증 실패: ${(e as Error).message}` };
    }

    // Verify key pair match using encryption/decryption
    try {
      const enc = await am.Encrypt(testPayload);
      const dec = await am.Decrypt(enc);
      if (dec.length !== testPayload.length || !dec.every((b, i) => b === testPayload[i])) {
        return { valid: false, error: "공개키와 개인키가 일치하지 않는 쌍입니다." };
      }
    } catch (e) {
      return { valid: false, error: `암/복호화 검증 실패: ${(e as Error).message}` };
    }

    return { valid: true, cleanPublicKey: pubClean, cleanPrivateKey: priClean };
  } catch (err) {
    return { valid: false, error: (err as Error).message || "키 검증에 실패했습니다." };
  }
}

export async function validatePublicKey(
  publicKeyInput: string
): Promise<{ valid: boolean; error?: string; cleanKey?: string }> {
  const pubClean = cleanBase64Key(publicKeyInput);
  if (!pubClean) return { valid: false, error: "공개키를 입력해주세요." };
  let pubU8: Uint8Array;
  try {
    pubU8 = base64ToU8(pubClean);
  } catch {
    return { valid: false, error: "공개키가 올바른 암호문 형식이 아닙니다." };
  }
  if (pubU8.length !== 4273) {
    return {
      valid: false,
      error: `공개키 형식이 올바르지 않습니다. (디코딩 크기: ${pubU8.length}B, 필요: 4273B)`,
    };
  }
  try {
    const U = await waitForUsag();
    const AsymMaster = U.bencrypt.AsymMaster as new (a: string) => {
      Loadkey(publicBuf: Uint8Array | null, privateBuf: Uint8Array | null): Promise<void>;
    };
    const am = new AsymMaster("pqc1");
    await am.Loadkey(pubU8, null);
    return { valid: true, cleanKey: pubClean };
  } catch (e) {
    return { valid: false, error: `공개키 검증 실패: ${(e as Error).message}` };
  }
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
    headerBytes = await Encpw("arg2st", pw, new Uint8Array(0));
  } else {
    const peerPub = base64ToU8(options.peerPublicKey);
    const myPri = options.myPrivateKey ? base64ToU8(options.myPrivateKey) : null;
    const Encpub = (op as any).Encpub.bind(op) as (
      method: string,
      peerPub: Uint8Array,
      myPri: Uint8Array | null
    ) => Promise<Uint8Array>;
    headerBytes = await Encpub("pqc1", peerPub, myPri);
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
  if (algo !== "arg2st" && algo !== "arg2") {
    throw new Error(
      `이 파일은 '${algo}' 알고리즘으로 암호화되어 지원하지 않습니다. (Argon2id standard 만 지원)`
    );
  }

  const NormPW = U.bencode.NormPW as (s: string) => Uint8Array;
  const pw = NormPW(password);

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
  if (algo !== "pqc1") {
    throw new Error(
      `이 파일은 '${algo}' 알고리즘으로 암호화되어 지원하지 않습니다. (PQC pqc1 만 지원)`
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

async function encryptPrivateKey(
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

export async function buildAccountPayload(
  username: string,
  publicKeyB64: string,
  privateKeyB64: string,
  passphrase: string,
  notes?: string
): Promise<AccountPayload> {
  if (!passphrase || !passphrase.trim()) {
    throw new Error("개인키 암호화를 위한 비밀번호(Passphrase)가 필요합니다.");
  }
  const { encryptedPrivateKey, kdf } = await encryptPrivateKey(privateKeyB64, passphrase);
  return { username, publicKey: publicKeyB64, encryptedPrivateKey, kdf, notes };
}

export async function decryptStoredPrivateKeyClient(
  encrypted: EncryptedPrivateKey,
  kdf: KdfParameters,
  passphrase: string
): Promise<string> {
  if (!passphrase || !passphrase.trim()) {
    throw new Error("개인키 복호화를 위한 비밀번호(Passphrase)가 필요합니다.");
  }
  const salt = base64ToU8(kdf.salt);
  const iv = base64ToU8(encrypted.iv);
  let cipherBytes = base64ToU8(encrypted.cipherText);
  if (encrypted.authTag) {
    const tag = base64ToU8(encrypted.authTag);
    const combined = new Uint8Array(cipherBytes.length + tag.length);
    combined.set(cipherBytes, 0);
    combined.set(tag, cipherBytes.length);
    cipherBytes = combined;
  }

  const iterations = kdf.iterations ?? 310_000;
  const keyLength = kdf.keyLength ?? 32;
  const hash = kdf.hash ?? "SHA-256";

  const base = await crypto.subtle.importKey(
    "raw",
    asBuf(_enc.encode(passphrase)),
    "PBKDF2",
    false,
    ["deriveKey"]
  );
  const aesKey = await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: asBuf(salt), iterations, hash },
    base,
    { name: "AES-GCM", length: keyLength * 8 },
    false,
    ["decrypt"]
  );

  const decrypted = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: asBuf(iv) },
    aesKey,
    asBuf(cipherBytes)
  );

  return _dec.decode(decrypted);
}

// ==================== WebAuthn utilities (UNRELATED to USAG-lib) ====================

function arrayBufferToBase64(buffer: ArrayBuffer): string {
  return u8ToBase64(new Uint8Array(buffer));
}

function base64ToArrayBuffer(base64: string): ArrayBuffer {
  if (!base64) return new ArrayBuffer(0);
  const normalized = base64UrlToBase64(base64);
  const binary = atob(normalized);
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
  clientDataJSON: string;
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
    credentialId = base64UrlToBase64(credential.id);
  }
  if (!credentialId) throw new Error("Failed to extract credential ID");

  let publicKey = "";
  if (typeof response.getPublicKey === "function") {
    const pkBuf = response.getPublicKey();
    if (pkBuf) publicKey = arrayBufferToBase64(pkBuf);
  }
  if (!publicKey) throw new Error("Failed to extract public key");
  const counter = 0;
  const transports = response.getTransports?.() || [];
  const clientDataJSON = arrayBufferToBase64(response.clientDataJSON as unknown as ArrayBuffer);

  return { credentialId, publicKey, counter, transports, clientDataJSON };
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
    credentialId = base64UrlToBase64(assertion.id);
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
