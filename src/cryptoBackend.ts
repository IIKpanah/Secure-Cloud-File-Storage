/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import crypto from "crypto";

// Server-wide master secret for HMAC-SHA256 JWTs and internal key wraps
const HMAC_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString("hex");

/**
 * Hash password with PBKDF2 (SHA-512)
 */
export function hashPassword(password: string, saltHex?: string): { hash: string; salt: string } {
  const salt = saltHex || crypto.randomBytes(16).toString("hex");
  const hash = crypto
    .pbkdf2Sync(password, salt, 100000, 64, "sha512")
    .toString("hex");
  return { hash, salt };
}

/**
 * Generate a JWT token using native node crypto
 */
export function signJwt(payload: any, expiresInSeconds = 86400): string {
  const header = { alg: "HS256", typ: "JWT" };
  const exp = Math.floor(Date.now() / 1000) + expiresInSeconds;
  const fullPayload = { ...payload, exp };

  const base64UrlEncode = (obj: any) =>
    Buffer.from(JSON.stringify(obj))
      .toString("base64")
      .replace(/=/g, "")
      .replace(/\+/g, "-")
      .replace(/\//g, "_");

  const unsignedToken = `${base64UrlEncode(header)}.${base64UrlEncode(fullPayload)}`;
  const signature = crypto
    .createHmac("sha256", HMAC_SECRET)
    .update(unsignedToken)
    .digest("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");

  return `${unsignedToken}.${signature}`;
}

/**
 * Verify checking a JWT token
 */
export function verifyJwt(token: string): any {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return null;

    const [headerB64, payloadB64, signatureB64] = parts;
    const unsignedToken = `${headerB64}.${payloadB64}`;

    const expectedSignature = crypto
      .createHmac("sha256", HMAC_SECRET)
      .update(unsignedToken)
      .digest("base64")
      .replace(/=/g, "")
      .replace(/\+/g, "-")
      .replace(/\//g, "_");

    if (signatureB64 !== expectedSignature) {
      return null;
    }

    const base64UrlDecode = (str: string) => {
      let b64 = str.replace(/-/g, "+").replace(/_/g, "/");
      while (b64.length % 4) b64 += "=";
      return JSON.parse(Buffer.from(b64, "base64").toString("utf8"));
    };

    const payload = base64UrlDecode(payloadB64);
    if (payload.exp && payload.exp < Date.now() / 1000) {
      return null; // Expired
    }

    return payload;
  } catch (e) {
    return null;
  }
}

/**
 * Generate RSA Key Pair for Key Wrapping
 */
export function generateRSAKeyPair(): { publicKey: string; privateKey: string } {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: {
      type: "spki",
      format: "pem"
    },
    privateKeyEncoding: {
      type: "pkcs8",
      format: "pem"
    }
  });

  return { publicKey, privateKey };
}

/**
 * AES-256-GCM Bulk Data Encryption
 * Encrypts buffer with AES-256-GCM.
 * Returns { ciphertext, iv, authTag } as Base64 strings.
 */
export function encryptAESGCM(
  plaintext: Buffer,
  key: Buffer,
  iv?: Buffer
): { ciphertext: string; iv: string; authTag: string } {
  const finalIv = iv || crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, finalIv);

  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const authTag = cipher.getAuthTag();

  return {
    ciphertext: encrypted.toString("base64"),
    iv: finalIv.toString("base64"),
    authTag: authTag.toString("base64")
  };
}

/**
 * AES-256-GCM Decryption
 */
export function decryptAESGCM(
  ciphertextBase64: string,
  key: Buffer,
  ivBase64: string,
  authTagBase64: string
): Buffer {
  const ciphertext = Buffer.from(ciphertextBase64, "base64");
  const iv = Buffer.from(ivBase64, "base64");
  const authTag = Buffer.from(authTagBase64, "base64");

  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(authTag);

  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

/**
 * RSA-OAEP Key Wrapping
 * Encrypts an AES session key (base64 or buffer) using RSA Public Key.
 * Returns Base64 encoded cipher text.
 */
export function wrapKeyRSA(aesKey: Buffer, publicKeyPem: string): string {
  const wrapped = crypto.publicEncrypt(
    {
      key: publicKeyPem,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: "sha256"
    },
    aesKey
  );
  return wrapped.toString("base64");
}

/**
 * RSA-OAEP Key Unwrapping
 * Decrypts wrapped AES key using RSA Private Key.
 * Returns plaintext AES key buffer.
 */
export function unwrapKeyRSA(wrappedKeyBase64: string, privateKeyPem: string): Buffer {
  const wrappedBuffer = Buffer.from(wrappedKeyBase64, "base64");
  return crypto.privateDecrypt(
    {
      key: privateKeyPem,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: "sha256"
    },
    wrappedBuffer
  );
}

/**
 * Generates SHA-256 Checksum of a Buffer
 */
export function getSHA256Checksum(data: Buffer): string {
  return crypto.createHash("sha256").update(data).digest("hex");
}
