import { secp256k1 } from "@noble/curves/secp256k1";

import { ERROR_CODES, protocolError } from "./errors.js";
import { PrivateKey, PublicKey, Signature, parsePrivateKey, parsePublicKey, parseSignature, publicKeyFromBytes, signatureFromDER } from "./encoding.js";

/** 对已 SHA-256 的 digest 生成 RFC 6979 strict DER low-S 签名。 */
export function signDigest(privateKey: PrivateKey, digest: Uint8Array): Signature {
  const key = parsePrivateKey(privateKey);
  if (digest.length !== 32) throw protocolError(ERROR_CODES.INVALID_SIGNATURE, "ECDSA digest 必须是 32 字节");
  try {
    const signature = secp256k1.sign(new Uint8Array(digest), key, { prehash: false, lowS: true, format: "der" });
    return signatureFromDER(signature.toDERRawBytes());
  } catch (cause) {
    throw protocolError(ERROR_CODES.INVALID_SIGNATURE, "ECDSA 签名失败", cause);
  }
}
/** 严格验证 DER、low-S、r/s 范围和 ECDSA 签名。 */
export function verifyDigest(publicKey: PublicKey, digest: Uint8Array, signature: Signature): void {
  const publicBytes = publicKeyBytes(publicKey);
  const signatureText = parseSignature(signature);
  if (digest.length !== 32) throw protocolError(ERROR_CODES.INVALID_SIGNATURE, "ECDSA digest 必须是 32 字节");
  const der = signatureBytes(signatureText);
  let parsed: ReturnType<typeof secp256k1.Signature.fromBytes>;
  try {
    parsed = secp256k1.Signature.fromBytes(der, "der");
    if (parsed.hasHighS()) throw new Error("high-S");
    const canonical = parsed.toDERRawBytes();
    if (!equalBytes(canonical, der)) throw new Error("non-canonical DER");
    if (!secp256k1.verify(der, new Uint8Array(digest), publicBytes, { prehash: false, lowS: true, format: "der" })) throw new Error("invalid signature");
  } catch (cause) {
    throw protocolError(ERROR_CODES.INVALID_SIGNATURE, "signature 不是合法 strict DER low-S 签名", cause);
  }
}

/** 返回长期私钥和对端公钥的 ECDH 共享点 X 坐标。 */
export function ecdh(privateKey: PrivateKey, publicKey: PublicKey): Uint8Array {
  const key = parsePrivateKey(privateKey);
  const publicBytes = publicKeyBytes(publicKey);
  try {
    const compressed = secp256k1.getSharedSecret(key, publicBytes, true);
    return new Uint8Array(compressed.slice(1, 33));
  } catch (cause) {
    throw protocolError(ERROR_CODES.INVALID_ENVELOPE, "ECDH 共享秘密计算失败", cause);
  }
}

/** 从长期私钥推导公钥。 */
export function derivePublicKey(privateKey: PrivateKey): PublicKey {
  return publicKeyFromBytes(secp256k1.getPublicKey(parsePrivateKey(privateKey), true));
}

function publicKeyBytes(value: PublicKey): Uint8Array {
  const parsed = parsePublicKey(value);
  const bytes = new Uint8Array(parsed.length / 2);
  for (let index = 0; index < bytes.length; index += 1) bytes[index] = Number.parseInt(parsed.slice(index * 2, index * 2 + 2), 16);
  return bytes;
}

function signatureBytes(value: Signature): Uint8Array {
  const text = value as string;
  const padded = text.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (text.length % 4)) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) difference |= left[index] ^ right[index];
  return difference === 0;
}
