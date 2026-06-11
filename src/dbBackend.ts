/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import admin from "firebase-admin";
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

let firestoreInstance: admin.firestore.Firestore | null = null;

function getFirestore(): admin.firestore.Firestore {
  if (!firestoreInstance) {
    const configPath = path.join(process.cwd(), "firebase-applet-config.json");
    if (!fs.existsSync(configPath)) {
      throw new Error("firebase-applet-config.json not found. Please ensure Firebase is set up.");
    }
    const firebaseConfig = JSON.parse(fs.readFileSync(configPath, "utf-8"));

    if (!admin.apps.length) {
      admin.initializeApp({
        projectId: firebaseConfig.projectId
      });
    }
    firestoreInstance = admin.firestore(firebaseConfig.firestoreDatabaseId || "(default)");
  }
  return firestoreInstance;
}

// Physical storage for encrypted chunks remains in vault/
const VAULT_DIR = path.join(process.cwd(), "vault");
const FILES_DIR = path.join(VAULT_DIR, "files");

class DatabaseEngine {
  constructor() {
    this.init();
  }

  private init() {
    if (!fs.existsSync(VAULT_DIR)) {
      fs.mkdirSync(VAULT_DIR, { recursive: true });
    }
    if (!fs.existsSync(FILES_DIR)) {
      fs.mkdirSync(FILES_DIR, { recursive: true });
    }
  }

  // Users
  public async getUsers(): Promise<User[]> {
    const snapshot = await getFirestore().collection("users").get();
    return snapshot.docs.map(doc => doc.data() as User);
  }

  public async findUserById(id: string): Promise<User | undefined> {
    const doc = await getFirestore().collection("users").doc(id).get();
    return doc.exists ? (doc.data() as User) : undefined;
  }

  public async findUserByUsername(username: string): Promise<User | undefined> {
    const snapshot = await getFirestore().collection("users")
      .where("username", "==", username)
      .limit(1)
      .get();
    if (snapshot.empty) return undefined;
    return snapshot.docs[0].data() as User;
  }

  public async addUser(user: User) {
    await getFirestore().collection("users").doc(user.id).set(user);
  }

  // Files
  public async getFiles(): Promise<FileMetadata[]> {
    const snapshot = await getFirestore().collection("files").get();
    return snapshot.docs.map(doc => doc.data() as FileMetadata);
  }

  public async findFileById(id: string): Promise<FileMetadata | undefined> {
    const doc = await getFirestore().collection("files").doc(id).get();
    return doc.exists ? (doc.data() as FileMetadata) : undefined;
  }

  public async addFile(file: FileMetadata) {
    await getFirestore().collection("files").doc(file.id).set(file);
  }

  public async removeFile(id: string) {
    const db = getFirestore();
    const batch = db.batch();
    batch.delete(db.collection("files").doc(id));
    
    // Clear associations
    const keys = await db.collection("keyRecords").where("fileId", "==", id).get();
    keys.forEach(k => batch.delete(k.ref));
    
    const acls = await db.collection("acls").where("fileId", "==", id).get();
    acls.forEach(a => batch.delete(a.ref));
    
    await batch.commit();
  }

  // Keys
  public async getKeyRecords(): Promise<FileKeyRecord[]> {
    const snapshot = await getFirestore().collection("keyRecords").get();
    return snapshot.docs.map(doc => doc.data() as FileKeyRecord);
  }

  public async addKeyRecord(record: FileKeyRecord) {
    await getFirestore().collection("keyRecords").doc(record.id).set(record);
  }

  // ACL
  public async getAcls(): Promise<FileACL[]> {
    const snapshot = await getFirestore().collection("acls").get();
    return snapshot.docs.map(doc => doc.data() as FileACL);
  }

  public async getAclsForFile(fileId: string): Promise<FileACL[]> {
    const snapshot = await getFirestore().collection("acls").where("fileId", "==", fileId).get();
    return snapshot.docs.map(doc => doc.data() as FileACL);
  }

  public async addAcl(acl: FileACL) {
    await getFirestore().collection("acls").doc(acl.id).set(acl);
  }

  public async removeAcl(id: string) {
    await getFirestore().collection("acls").doc(id).delete();
  }

  // Audit
  public async getAuditLogs(): Promise<AuditLog[]> {
    const snapshot = await getFirestore().collection("auditLogs")
      .orderBy("timestamp", "desc")
      .limit(500)
      .get();
    return snapshot.docs.map(doc => doc.data() as AuditLog);
  }

  public async addAuditLog(log: Omit<AuditLog, "id" | "timestamp">) {
    const id = "log_" + Math.random().toString(36).substring(2, 11);
    const fullLog: AuditLog = {
      ...log,
      id,
      timestamp: new Date().toISOString()
    };
    await getFirestore().collection("auditLogs").doc(id).set(fullLog);
  }

  // Performance
  public async getPerformanceMetrics(): Promise<PerformanceMetric[]> {
    const snapshot = await getFirestore().collection("performanceMetrics")
      .orderBy("timestamp", "desc")
      .limit(200)
      .get();
    return snapshot.docs.map(doc => doc.data() as PerformanceMetric);
  }

  public async addPerformanceMetric(metric: Omit<PerformanceMetric, "id" | "timestamp">) {
    const id = "metric_" + Math.random().toString(36).substring(2, 11);
    const fullMetric: PerformanceMetric = {
      ...metric,
      id,
      timestamp: new Date().toISOString()
    };
    await getFirestore().collection("performanceMetrics").doc(id).set(fullMetric);
  }

  // Permissions
  public async hasPermission(fileId: string, userId: string, required: "read" | "write"): Promise<boolean> {
    const file = await this.findFileById(fileId);
    if (!file) return false;
    if (file.ownerId === userId) return true;

    const user = await this.findUserById(userId);
    if (user && user.role === UserRole.ADMIN) return true;

    const aclSnapshot = await getFirestore().collection("acls")
      .where("fileId", "==", fileId)
      .where("userId", "==", userId)
      .limit(1)
      .get();

    if (aclSnapshot.empty) return false;
    const acl = aclSnapshot.docs[0].data() as FileACL;

    if (required === "read") return true;
    return acl.permission === PermissionType.WRITE;
  }

  // Physical files (Zero-Trust blob storage simulated locally)
  public writeEncryptedFile(fileId: string, encryptedBuffer: Buffer) {
    const dest = path.join(FILES_DIR, fileId + ".enc");
    fs.writeFileSync(dest, encryptedBuffer);
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

  // Migration Helper: Seed defaults if empty
  public async seedIfEmpty() {
    const snapshot = await getFirestore().collection("users").limit(1).get();
    if (!snapshot.empty) return;

    console.log("Seeding Firestore with default administrator profile...");
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
      privateKeyPemEncrypted: adminRsa.privateKey
    };
    await this.addUser(adminUser);
  }
}

export const dbEngine = new DatabaseEngine();
export { FILES_DIR, VAULT_DIR };

