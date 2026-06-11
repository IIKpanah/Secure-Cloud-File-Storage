# Security Specification: Secure Cloud Vault

## Data Invariants
1.   A user cannot grant themselves Administrator status.
2.   File metadata is immutable once created, except for ACL references or explicit deletion.
3.   `AuditLog` entries are append-only and strictly immutable.
4.   Access to an encrypted file session key (`FileKeyRecord`) is strictly derived from document ownership or explicit ACL membership.
5.   All operations must be performed by verified users (email_verified: true).

## The Dirty Dozen Payloads (Audit Attack Traps)

| ID | Attack Vector | Expected Outcome |
|----|---------------|------------------|
| P1 | **Admin Escalation**: Create User with `role: "Admin"` | REJECT: Role assignment requires Admin privilege. |
| P2 | **Indentity Spoof**: Create FileMetadata with `ownerId: "target_user"` | REJECT: `ownerId` must match `request.auth.uid`. |
| P3 | **ACL Hijack**: Grant `WRITE` access to self on `foreign_file_id` | REJECT: Only owner can grant ACLs. |
| P4 | **Audit Poisoning**: `update` on `auditLogs/{logId}` | REJECT: Audit logs are immutable. |
| P5 | **Metric Bloat**: `create` metric with `fileSize: 999999999999` | REJECT: Size bounds validation. |
| P6 | **ID Traversal**: `get` on `files/../../etc/passwd` | REJECT: Path variable hardening `isValidId()`. |
| P7 | **Shadow Update**: `update` User with `publicKeyPem: "hacker_key"` | REJECT: User profile fields are strictly controlled. |
| P8 | **Unverified Write**: `create` File with `email_verified: false` | REJECT: Verification required. |
| P9 | **Key Record Leak**: `get` map of wrapped keys for a non-shared file | REJECT: Derivation check fails. |
| P10| **Checksum Tampering**: `update` file `checksum` directly | REJECT: Immutability invariant. |
| P11| **PII Scraping**: `list` all users to harvest emails | REJECT: List queries must be restricted. |
| P12| **State Shortcut**: `create` file with `storagePath` pointing to restricted area | REJECT: Path format validation. |
