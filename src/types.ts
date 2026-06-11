/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

export enum UserRole {
  ADMIN = "Admin",
  USER = "User"
}

export interface User {
  id: string;
  username: string;
  passwordHash: string;
  salt: string;
  role: UserRole;
  createdAt: string;
  publicKeyPem: string; // User RSA Public Key for Key Wrapping
  privateKeyPemEncrypted: string; // RSA Private Key, encrypted client-side or server KMS-side
}

export interface FileMetadata {
  id: string;
  originalName: string;
  mimeType: string;
  size: number;
  encryptedSize: number;
  checksum: string; // SHA-256 hash of the ciphertext / plaintext
  ownerId: string;
  ownerUsername: string;
  storagePath: string; // Local storage path under /vault
  createdAt: string;
  isClientEncrypted: boolean; // Flag to indicate if client did the AES-GCM encryption
}

export interface FileKeyRecord {
  id: string;
  fileId: string;
  userId: string; // The user who can decrypt this file
  wrappedKey: string; // Base64 of RSA-wrapped AES session key
  wrappedIv: string; // Base64 of AES IV (or plain base64 iv if not sensitive)
  wrappedByPublicThumbprint: string;
  createdAt: string;
}

export enum PermissionType {
  READ = "read",
  WRITE = "write"
}

export interface FileACL {
  id: string;
  fileId: string;
  userId: string;
  username: string;
  permission: PermissionType;
  grantedBy: string;
  createdAt: string;
}

export enum AuditEventType {
  UPLOAD = "upload",
  DOWNLOAD = "download",
  DELETE = "delete",
  SHARE = "share",
  KEY_GEN = "key_generation",
  KEY_ACCESS = "key_access",
  AUTH_LOGIN = "auth_login",
  AUTH_FAIL = "auth_failure",
  ACCESS_DENIED = "access_denied"
}

export enum AuditStatus {
  SUCCESS = "success",
  FAILURE = "failure"
}

export interface AuditLog {
  id: string;
  timestamp: string;
  eventType: AuditEventType;
  status: AuditStatus;
  userId: string;
  username: string;
  fileId: string | null;
  fileName: string | null;
  ipAddress: string;
  details: string;
}

export interface PerformanceMetric {
  id: string;
  timestamp: string;
  operation: "upload_encrypt" | "download_decrypt" | "key_unwrap";
  fileSize: number;
  durationMs: number;
  throughputMbps: number;
  memoryBeforeMb: number;
  memoryAfterMb: number;
  concurrencyCount: number;
  integrityVerified: boolean;
}
