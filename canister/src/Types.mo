/// Shared types for IC Memory Vault canisters.
/// Used by both Factory and UserVault.
module Types {

  // -- Audit log --

  /// Actions recorded in the immutable audit log
  public type AuditAction = {
    #store;        // memory stored or updated
    #delete;       // memory deleted
    #bulkSync;     // batch sync operation
    #restore;      // data restored from vault
    #created;      // vault created
    #accessDenied; // unauthorized access attempt
    #upgrade;      // vault WASM upgraded to a new version
  };

  /// Immutable record of a vault operation.
  /// Appended to the audit log via update calls (consensus-verified timestamp).
  public type AuditEntry = {
    timestamp : Int;       // IC consensus time via Time.now()
    action : AuditAction;
    caller : Principal;    // who performed the action
    key : ?Text;           // affected key (if applicable)
    category : ?Text;      // affected category (if applicable)
    details : ?Text;       // additional context (e.g., "synced 47 entries")
  };

  // -- Memory --

  /// V1 memory entry type — used by the EOP migration function to read old state.
  /// DO NOT modify this type — it must match the deployed v1.x canister's MemoryEntry exactly.
  public type MemoryEntryV1 = {
    key : Text;
    category : Text;
    content : Blob;
    metadata : Text;
    createdAt : Int;
    updatedAt : Int;
  };

  /// A single memory entry stored in the vault (v2).
  /// When isEncrypted is true, `content` holds AES-256-GCM ciphertext
  /// (format: [8-byte header "IC GCMv2"] [12-byte nonce] [ciphertext + 16-byte tag]).
  /// The canister never decrypts — all encryption/decryption happens client-side via vetKeys.
  public type MemoryEntry = {
    key : Text;
    category : Text;
    content : Blob;
    metadata : Text;   // JSON string for flexible metadata
    createdAt : Int;
    updatedAt : Int;
    isEncrypted : Bool; // true if content is AES-256-GCM ciphertext
  };

  // -- Sessions --

  /// A session record
  public type SessionEntry = {
    sessionId : Text;
    data : Blob;
    startedAt : Int;
    endedAt : Int;
  };

  // -- Stats and sync --

  /// Vault statistics
  public type VaultStats = {
    totalMemories : Nat;
    totalSessions : Nat;
    categories : [Text];
    bytesUsed : Nat;
    cycleBalance : Nat;
    lastUpdated : Int;
  };

  /// Manifest for differential sync
  public type SyncManifest = {
    lastUpdated : Int;
    memoriesCount : Nat;
    sessionsCount : Nat;
    categoryChecksums : [(Text, Text)];
  };

  /// Dashboard data returned by composite query
  public type DashboardData = {
    stats : VaultStats;
    recentMemories : [MemoryEntry];
    recentSessions : [SessionEntry];
  };

  /// Result of a bulk sync operation
  public type SyncResult = {
    stored : Nat;
    skipped : Nat;
    errors : [Text];
  };

  /// Result of a bulk vault upgrade operation
  public type UpgradeResult = {
    succeeded : Nat;
    failed : Nat;
    errors : [Text];
  };

  // -- Input types for bulk operations --

  /// Input for a single memory to store/sync
  public type MemoryInput = {
    key : Text;
    category : Text;
    content : Blob;
    metadata : Text;
    createdAt : Int;
    updatedAt : Int;
    isEncrypted : Bool; // true if content is AES-256-GCM ciphertext
  };

  /// Input for a session to sync
  public type SessionInput = {
    sessionId : Text;
    data : Blob;
    startedAt : Int;
    endedAt : Int;
  };

  // -- Error types --

  /// Errors returned by the factory
  public type FactoryError = {
    #alreadyExists;          // user already has a vault
    #insufficientCycles;     // not enough cycles to create a vault
    #unauthorized : Text;    // caller not permitted for this operation
    #notFound : Text;        // requested resource not found
    #creationFailed : Text;  // vault creation failed
    #upgradeError : Text;    // vault upgrade failed
    #noWasmUploaded;         // admin has not uploaded vault WASM yet
  };

  /// Errors returned by the vault
  public type VaultError = {
    #unauthorized;
    #notFound;
    #invalidInput : Text;
    #vetKeyError : Text;  // vetKey derivation or verification key retrieval failed
  };

  /// Vault version info for upgrade coordination
  public type VaultVersion = {
    version : Nat;        // incremented on schema changes
    supportsEncryption : Bool;
  };
};
