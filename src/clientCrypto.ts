/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

function arrayBufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return window.btoa(binary);
}

function base64ToArrayBuffer(base64: string): ArrayBuffer {
  const binaryString = window.atob(base64);
  const len = binaryString.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes.buffer;
}

function formatAsPem(b64: string, type: "PUBLIC KEY" | "PRIVATE KEY"): string {
  const matches = b64.match(/.{1,64}/g);
  const lines = matches ? matches.join("\n") : b64;
  return `-----BEGIN ${type}-----\n${lines}\n-----END ${type}-----`;
}

function pemToArrayBuffer(pem: string): ArrayBuffer {
  const b64 = pem
    .replace(/-----BEGIN [A-Z ]+-----/, "")
    .replace(/-----END [A-Z ]+-----/, "")
    .replace(/\s/g, "");
  return base64ToArrayBuffer(b64);
}

/**
 * Generate a browser-compliant 2048-bit RSA key pair for key wrapping (RSA-OAEP + SHA-256)
 */
export async function generateClientRSAKeyPair(): Promise<{ publicKeyPem: string; privateKeyPem: string }> {
  const keyPair = await window.crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["encrypt", "decrypt"]
  );

  const exportedPublic = await window.crypto.subtle.exportKey("spki", keyPair.publicKey);
  const exportedPrivate = await window.crypto.subtle.exportKey("pkcs8", keyPair.privateKey);

  const publicB64 = arrayBufferToBase64(exportedPublic);
  const privateB64 = arrayBufferToBase64(exportedPrivate);

  return {
    publicKeyPem: formatAsPem(publicB64, "PUBLIC KEY"),
    privateKeyPem: formatAsPem(privateB64, "PRIVATE KEY")
  };
}

/**
 * Import public key from PEM string
 */
export async function importPublicKey(pem: string): Promise<CryptoKey> {
  const buffer = pemToArrayBuffer(pem);
  return await window.crypto.subtle.importKey(
    "spki",
    buffer,
    {
      name: "RSA-OAEP",
      hash: "SHA-256"
    },
    true,
    ["encrypt"]
  );
}

/**
 * Import private key from PEM string
 */
export async function importPrivateKey(pem: string): Promise<CryptoKey> {
  const buffer = pemToArrayBuffer(pem);
  return await window.crypto.subtle.importKey(
    "pkcs8",
    buffer,
    {
      name: "RSA-OAEP",
      hash: "SHA-256"
    },
    true,
    ["decrypt"]
  );
}

/**
 * Compute SHA-256 hash of a file ArrayBuffer
 */
export async function computeSHA256(buffer: ArrayBuffer): Promise<string> {
  const hashBuffer = await window.crypto.subtle.digest("SHA-256", buffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Encrypt file array buffer client-side using hybrid AES-256-GCM + RSA-OAEP
 */
export async function encryptFileClientSide(
  fileData: ArrayBuffer,
  recipientPublicKeyPem: string
): Promise<{
  ciphertextB64: string;
  wrappedAESKeyB64: string;
  ivB64: string;
  checksum: string;
}> {
  // 1. Generate ephemeral 256-bit AES symmetric key
  const aesKey = await window.crypto.subtle.generateKey(
    {
      name: "AES-GCM",
      length: 256
    },
    true,
    ["encrypt", "decrypt"]
  );

  // 2. Encrypt the file data using AES-GCM
  const ivArr = window.crypto.getRandomValues(new Uint8Array(12));
  const ciphertextBuffer = await window.crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: ivArr
    },
    aesKey,
    fileData
  );

  // 3. Export the AES symmetric key bytes to wrap it
  const rawAesKey = await window.crypto.subtle.exportKey("raw", aesKey);

  // 4. Wrap the AES symmetric key using RSA-OAEP with recipient's public key
  const recipientPublicKey = await importPublicKey(recipientPublicKeyPem);
  const wrappedAesKeyBuffer = await window.crypto.subtle.encrypt(
    {
      name: "RSA-OAEP"
    },
    recipientPublicKey,
    rawAesKey
  );

  // 5. Package results as Base64 format
  const ciphertextB64 = arrayBufferToBase64(ciphertextBuffer);
  const wrappedAESKeyB64 = arrayBufferToBase64(wrappedAesKeyBuffer);
  const ivB64 = arrayBufferToBase64(ivArr);
  const checksum = await computeSHA256(fileData);

  return {
    ciphertextB64,
    wrappedAESKeyB64,
    ivB64,
    checksum
  };
}

/**
 * Decrypt file ciphertext client-side using user private key
 */
export async function decryptFileClientSide(
  ciphertextB64: string,
  wrappedAESKeyB64: string,
  ivB64: string,
  userPrivateKeyPem: string
): Promise<ArrayBuffer> {
  // 1. Import User Private Key
  const userPrivateKey = await importPrivateKey(userPrivateKeyPem);

  // 2. Unwrap/Decrypt AES symmetric key using RSA-OAEP
  const wrappedAESKeyBuffer = base64ToArrayBuffer(wrappedAESKeyB64);
  const rawAesKeyBuffer = await window.crypto.subtle.decrypt(
    {
      name: "RSA-OAEP"
    },
    userPrivateKey,
    wrappedAESKeyBuffer
  );

  // 3. Import unwrapped AES Key back into Web Crypto
  const aesKey = await window.crypto.subtle.importKey(
    "raw",
    rawAesKeyBuffer,
    {
      name: "AES-GCM"
    },
    true,
    ["decrypt"]
  );

  // 4. Decrypt original ciphertext using AES-GCM
  const ciphertextBuffer = base64ToArrayBuffer(ciphertextB64);
  const ivArr = new Uint8Array(base64ToArrayBuffer(ivB64));

  return await window.crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: ivArr
    },
    aesKey,
    ciphertextBuffer
  );
}
