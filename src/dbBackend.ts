/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import fs from "fs";
import path from "path";
import {
  User,
  FileMetadata,
  FileKeyRecord,
  FileACL,
  AuditLog,
  PerformanceMetric,
  UserRole,
  AuditEventType,
  AuditStatus,
  PermissionType
} from "./types.js";
import { generateRSAKeyPair, hashPassword } from "./cryptoBackend.js";

// Database storage configurations
const VAULT_DIR = path.join(process.cwd(), "vault");
const FILES_DIR = path.join(VAULT_DIR, "files");
const DB_FILE = path.join(VAULT_DIR, "db.json");

interface DatabaseSchema {
  users: User[];
  files: FileMetadata[];
  keyRecords: FileKeyRecord[];
  acls: FileACL[];
  auditLogs: AuditLog[];
  performanceMetrics: PerformanceMetric[];
}

class DatabaseEngine {
  private data: DatabaseSchema = {
    users: [],
    files: [],
    keyRecords: [],
    acls: [],
    auditLogs: [],
    performanceMetrics: []
  };

  constructor() {
    this.init();
  }

  private init() {
    // Create folders
    if (!fs.existsSync(VAULT_DIR)) {
      fs.mkdirSync(VAULT_DIR, { recursive: true });
    }
    if (!fs.existsSync(FILES_DIR)) {
      fs.mkdirSync(FILES_DIR, { recursive: true });
    }

    // Load or create db.json
    if (fs.existsSync(DB_FILE)) {
      try {
        const raw = fs.readFileSync(DB_FILE, "utf-8");
        this.data = JSON.parse(raw);
        // Ensure all collections exist
        this.data.users = this.data.users || [];
        this.data.files = this.data.files || [];
        this.data.keyRecords = this.data.keyRecords || [];
        this.data.acls = this.data.acls || [];
        this.data.auditLogs = this.data.auditLogs || [];
        this.data.performanceMetrics = this.data.performanceMetrics || [];
      } catch (error) {
        console.error("Failed to read database, rebuilding default...", error);
        this.save();
      }
    } else {
      this.seedDefaults();
    }
  }

  private seedDefaults() {
    console.log("Seeding default database...");
    
    // Seed general admin
    const adminRsa = generateRSAKeyPair();
    const adminPassInfo = hashPassword("AdminSecurity2026!");
    const adminUser: User = {
      id: "u_admin",
      username: "admin",
      passwordHash: adminPassInfo.hash,
      salt: adminPassInfo.salt,
      role: UserRole.ADMIN,
      createdAt: new Date().toISOString(),
      publicKeyPem: adminRsa.publicKey,
      // In a production app, the private key would be encrypted client-side by derivation.
      // Here we simulate it or keep it safe.
      privateKeyPemEncrypted: adminRsa.privateKey
    };

    // Seed test users
    const aliceRsa = generateRSAKeyPair();
    const alicePassInfo = hashPassword("AliceSecurePass1!");
    const aliceUser: User = {
      id: "u_alice",
      username: "alice",
      passwordHash: alicePassInfo.hash,
      salt: alicePassInfo.salt,
      role: UserRole.USER,
      createdAt: new Date().toISOString(),
      publicKeyPem: aliceRsa.publicKey,
      privateKeyPemEncrypted: aliceRsa.privateKey
    };

    const bobRsa = generateRSAKeyPair();
    const bobPassInfo = hashPassword("BobSecurePass2!");
    const bobUser: User = {
      id: "u_bob",
      username: "bob",
      passwordHash: bobPassInfo.hash,
      salt: bobPassInfo.salt,
      role: UserRole.USER,
      createdAt: new Date().toISOString(),
      publicKeyPem: bobRsa.publicKey,
      privateKeyPemEncrypted: bobRsa.privateKey
    };

    this.data.users.push(adminUser, aliceUser, bobUser);

    // Add seed logs
    this.data.auditLogs.push({
      id: "log_seed_1",
      timestamp: new Date().toISOString(),
      eventType: AuditEventType.KEY_GEN,
      status: AuditStatus.SUCCESS,
      userId: "system",
      username: "system",
      fileId: null,
      fileName: null,
      ipAddress: "127.0.0.1",
      details: "System successfully generated RSA cryptographic identities for seed profiles (admin, alice, bob)."
    });

    this.save();
  }

  public save() {
    try {
      fs.writeFileSync(DB_FILE, JSON.stringify(this.data, null, 2), "utf-8");
    } catch (e) {
      console.error("Database failed to persist to disk:", e);
    }
  }

  // Users Collection Helpers
  public getUsers(): User[] {
    return this.data.users;
  }

  public findUserById(id: string): User | undefined {
    return this.data.users.find((u) => u.id === id);
  }

  public findUserByUsername(username: string): User | undefined {
    return this.data.users.find((u) => u.username.toLowerCase() === username.toLowerCase());
  }

  public addUser(user: User) {
    this.data.users.push(user);
    this.save();
  }

  // Files Collection Helpers
  public getFiles(): FileMetadata[] {
    return this.data.files;
  }

  public findFileById(id: string): FileMetadata | undefined {
    return this.data.files.find((f) => f.id === id);
  }

  public addFile(file: FileMetadata) {
    this.data.files.push(file);
    this.save();
  }

  public removeFile(id: string) {
    this.data.files = this.data.files.filter((f) => f.id !== id);
    this.data.keyRecords = this.data.keyRecords.filter((k) => k.fileId !== id);
    this.data.acls = this.data.acls.filter((a) => a.fileId !== id);
    this.save();
  }

  // Keys Helpers
  public getKeyRecords(): FileKeyRecord[] {
    return this.data.keyRecords;
  }

  public addKeyRecord(record: FileKeyRecord) {
    this.data.keyRecords.push(record);
    this.save();
  }

  // ACL Helpers
  public getAcls(): FileACL[] {
    return this.data.acls;
  }

  public getAclsForFile(fileId: string): FileACL[] {
    return this.data.acls.filter((a) => a.fileId === fileId);
  }

  public addAcl(acl: FileACL) {
    this.data.acls.push(acl);
    this.save();
  }

  public removeAcl(id: string) {
    this.data.acls = this.data.acls.filter((a) => a.id !== id);
    this.save();
  }

  // Audit Logs
  public getAuditLogs(): AuditLog[] {
    return this.data.auditLogs;
  }

  public addAuditLog(log: Omit<AuditLog, "id" | "timestamp">) {
    const fullLog: AuditLog = {
      ...log,
      id: "log_" + Math.random().toString(36).substring(2, 11),
      timestamp: new Date().toISOString()
    };
    this.data.auditLogs.unshift(fullLog); // latest first
    // Limit to 500 records to prevent bloating
    if (this.data.auditLogs.length > 500) {
      this.data.auditLogs = this.data.auditLogs.slice(0, 500);
    }
    this.save();
  }

  // Performance Metrics
  public getPerformanceMetrics(): PerformanceMetric[] {
    return this.data.performanceMetrics;
  }

  public addPerformanceMetric(metric: Omit<PerformanceMetric, "id" | "timestamp">) {
    const fullMetric: PerformanceMetric = {
      ...metric,
      id: "metric_" + Math.random().toString(36).substring(2, 11),
      timestamp: new Date().toISOString()
    };
    this.data.performanceMetrics.unshift(fullMetric);
    if (this.data.performanceMetrics.length > 200) {
      this.data.performanceMetrics = this.data.performanceMetrics.slice(0, 200);
    }
    this.save();
  }

  // Check Permissions Helper
  public hasPermission(fileId: string, userId: string, required: "read" | "write"): boolean {
    const file = this.findFileById(fileId);
    if (!file) return false;
    
    // Owner has full control
    if (file.ownerId === userId) return true;

    // Check ACLs
    const user = this.findUserById(userId);
    if (user && user.role === UserRole.ADMIN) return true; // Admin override

    const acl = this.data.acls.find(
      (a) => a.fileId === fileId && a.userId === userId
    );

    if (!acl) return false;

    if (required === "read") {
      return true; // if they have write permission, they can read as well
    } else {
      return acl.permission === PermissionType.WRITE;
    }
  }

  // Store encrypted file reference
  public writeEncryptedFile(fileId: string, encryptedBuffer: Buffer) {
    const dest = path.join(FILES_DIR, fileId + ".enc");
    fs.writeFileSync(dest, encryptedBuffer);
    console.log(`Saved encrypted file to: ${dest}`);
    return dest;
  }

  public readEncryptedFile(fileId: string): Buffer {
    const targetPath = path.join(FILES_DIR, fileId + ".enc");
    if (!fs.existsSync(targetPath)) {
      throw new Error("Physical encrypted storage file not found.");
    }
    return fs.readFileSync(targetPath);
  }

  public deletePhysicalEncryptedFile(fileId: string) {
    const targetPath = path.join(FILES_DIR, fileId + ".enc");
    if (fs.existsSync(targetPath)) {
      fs.unlinkSync(targetPath);
    }
  }
}

export const dbEngine = new DatabaseEngine();
export { FILES_DIR, VAULT_DIR };
