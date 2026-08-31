import { ERROR_CODES, protocolError } from "./errors.js";

/** 使用 Web Crypto HKDF-SHA256 派生 32 字节 AES 密钥。 */
export async function deriveKey(sharedSecret: Uint8Array, salt: Uint8Array, info: Uint8Array): Promise<Uint8Array> {
  try {
    const base = await globalThis.crypto.subtle.importKey("raw", new Uint8Array(sharedSecret), "HKDF", false, ["deriveBits"]);
    const bits = await globalThis.crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: new Uint8Array(salt), info: new Uint8Array(info) }, base, 256);
    return new Uint8Array(bits);
  } catch (cause) {
    throw protocolError(ERROR_CODES.OPEN_FAILED, "HKDF 派生失败", cause);
  }
}
/** 使用 AES-256-GCM 加密，返回 ciphertext || 16-byte tag。 */
export async function encrypt(key: Uint8Array, nonce: Uint8Array, plaintext: Uint8Array, aad: Uint8Array): Promise<Uint8Array> {
  if (key.length !== 32 || nonce.length !== 12) throw protocolError(ERROR_CODES.INVALID_ENVELOPE, "AES-256-GCM key/nonce 长度不合法");
  try {
    const cryptoKey = await globalThis.crypto.subtle.importKey("raw", new Uint8Array(key), { name: "AES-GCM" }, false, ["encrypt"]);
    const result = await globalThis.crypto.subtle.encrypt({ name: "AES-GCM", iv: new Uint8Array(nonce), additionalData: new Uint8Array(aad), tagLength: 128 }, cryptoKey, new Uint8Array(plaintext));
    return new Uint8Array(result);
  } catch (cause) {
    throw protocolError(ERROR_CODES.INVALID_ENVELOPE, "AES-GCM 加密失败", cause);
  }
}

/** 使用 AES-256-GCM 解密；任何密码学失败统一为 OPEN_FAILED。 */
export async function decrypt(key: Uint8Array, nonce: Uint8Array, ciphertext: Uint8Array, aad: Uint8Array): Promise<Uint8Array> {
  if (key.length !== 32 || nonce.length !== 12 || ciphertext.length < 16) throw protocolError(ERROR_CODES.OPEN_FAILED, "私密信封无法打开");
  try {
    const cryptoKey = await globalThis.crypto.subtle.importKey("raw", new Uint8Array(key), { name: "AES-GCM" }, false, ["decrypt"]);
    const result = await globalThis.crypto.subtle.decrypt({ name: "AES-GCM", iv: new Uint8Array(nonce), additionalData: new Uint8Array(aad), tagLength: 128 }, cryptoKey, new Uint8Array(ciphertext));
    return new Uint8Array(result);
  } catch {
    throw protocolError(ERROR_CODES.OPEN_FAILED, "私密信封无法打开");
  }
}

/** 尽力清零可控中间秘密；JavaScript 运行时不能保证完整内存擦除。 */
export function clearBytes(value: Uint8Array): void {
  value.fill(0);
}
