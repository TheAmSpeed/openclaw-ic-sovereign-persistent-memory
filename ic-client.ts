/// @dfinity/agent wrapper for IC Sovereign Persistent Memory.
/// Handles authentication (Ed25519KeyIdentity), agent creation, and canister calls.

import { Actor, HttpAgent } from "@dfinity/agent";
import type { Identity } from "@dfinity/agent";
import { IDL } from "@dfinity/candid";
import { Principal } from "@dfinity/principal";
import type { IcStorageConfig } from "./config.js";
import { loadIdentityAsync, identityExists } from "./identity.js";

// -- Candid IDL definitions for our canisters --

// Shared types
const AuditAction = IDL.Variant({
  store: IDL.Null,
  delete: IDL.Null,
  bulkSync: IDL.Null,
  restore: IDL.Null,
  created: IDL.Null,
  accessDenied: IDL.Null,
  upgrade: IDL.Null,
});

const AuditEntry = IDL.Record({
  timestamp: IDL.Int,
  action: AuditAction,
  caller: IDL.Principal,
  key: IDL.Opt(IDL.Text),
  category: IDL.Opt(IDL.Text),
  details: IDL.Opt(IDL.Text),
});

const MemoryEntry = IDL.Record({
  key: IDL.Text,
  category: IDL.Text,
  content: IDL.Vec(IDL.Nat8),
  metadata: IDL.Text,
  createdAt: IDL.Int,
  updatedAt: IDL.Int,
  isEncrypted: IDL.Bool,
});

const SessionEntry = IDL.Record({
  sessionId: IDL.Text,
  data: IDL.Vec(IDL.Nat8),
  startedAt: IDL.Int,
  endedAt: IDL.Int,
});

const VaultStats = IDL.Record({
  totalMemories: IDL.Nat,
  totalSessions: IDL.Nat,
  categories: IDL.Vec(IDL.Text),
  bytesUsed: IDL.Nat,
  cycleBalance: IDL.Nat,
  lastUpdated: IDL.Int,
});

const DashboardData = IDL.Record({
  stats: VaultStats,
  recentMemories: IDL.Vec(MemoryEntry),
  recentSessions: IDL.Vec(SessionEntry),
});

const SyncManifest = IDL.Record({
  lastUpdated: IDL.Int,
  memoriesCount: IDL.Nat,
  sessionsCount: IDL.Nat,
  categoryChecksums: IDL.Vec(IDL.Tuple(IDL.Text, IDL.Text)),
});

const SyncResult = IDL.Record({
  stored: IDL.Nat,
  skipped: IDL.Nat,
  errors: IDL.Vec(IDL.Text),
});

const VaultError = IDL.Variant({
  unauthorized: IDL.Null,
  notFound: IDL.Null,
  invalidInput: IDL.Text,
  vetKeyError: IDL.Text,
});

const FactoryError = IDL.Variant({
  alreadyExists: IDL.Null,
  insufficientCycles: IDL.Null,
  unauthorized: IDL.Text,
  notFound: IDL.Text,
  creationFailed: IDL.Text,
  upgradeError: IDL.Text,
  noWasmUploaded: IDL.Null,
});

const MemoryInput = IDL.Record({
  key: IDL.Text,
  category: IDL.Text,
  content: IDL.Vec(IDL.Nat8),
  metadata: IDL.Text,
  createdAt: IDL.Int,
  updatedAt: IDL.Int,
  isEncrypted: IDL.Bool,
});

const SessionInput = IDL.Record({
  sessionId: IDL.Text,
  data: IDL.Vec(IDL.Nat8),
  startedAt: IDL.Int,
  endedAt: IDL.Int,
});

// Result types
const ResultOkUnit = IDL.Variant({ ok: IDL.Null, err: VaultError });
const ResultOkSyncResult = IDL.Variant({ ok: SyncResult, err: VaultError });
const ResultOkPrincipal = IDL.Variant({
  ok: IDL.Principal,
  err: FactoryError,
});

// Result types for queries (queries now return Results instead of trapping)
const ResultOkOptMemory = IDL.Variant({ ok: IDL.Opt(MemoryEntry), err: VaultError });
const ResultOkStats = IDL.Variant({ ok: VaultStats, err: VaultError });
const ResultOkCategories = IDL.Variant({ ok: IDL.Vec(IDL.Text), err: VaultError });
const ResultOkAuditEntries = IDL.Variant({ ok: IDL.Vec(AuditEntry), err: VaultError });
const ResultOkNat = IDL.Variant({ ok: IDL.Nat, err: VaultError });
const ResultOkPrincipalVault = IDL.Variant({ ok: IDL.Principal, err: VaultError });
const ResultOkDashboard = IDL.Variant({ ok: DashboardData, err: VaultError });
const ResultOkMemories = IDL.Variant({ ok: IDL.Vec(MemoryEntry), err: VaultError });
const ResultOkSessions = IDL.Variant({ ok: IDL.Vec(SessionEntry), err: VaultError });
const ResultOkManifest = IDL.Variant({ ok: SyncManifest, err: VaultError });
const ResultOkBlob = IDL.Variant({ ok: IDL.Vec(IDL.Nat8), err: VaultError });

// VaultVersion type
const VaultVersion = IDL.Record({
  version: IDL.Nat,
  supportsEncryption: IDL.Bool,
});
const ResultOkVaultVersion = IDL.Variant({ ok: VaultVersion, err: VaultError });

// Factory Result types
const ResultOkFactoryVaults = IDL.Variant({
  ok: IDL.Vec(IDL.Tuple(IDL.Principal, IDL.Principal)),
  err: FactoryError,
});
const ResultOkFactoryUnit = IDL.Variant({ ok: IDL.Null, err: FactoryError });

const UpgradeResult = IDL.Record({
  succeeded: IDL.Nat,
  failed: IDL.Nat,
  errors: IDL.Vec(IDL.Text),
});
const ResultOkUpgradeResult = IDL.Variant({ ok: UpgradeResult, err: FactoryError });

// -- IDL factories --

// eslint-disable-next-line @typescript-eslint/no-explicit-any -- InterfaceFactory param type from @dfinity/candid
const userVaultIdlFactory = ({ IDL: _IDL }: any) => {
  return IDL.Service({
    // Update calls
    store: IDL.Func([IDL.Text, IDL.Text, IDL.Vec(IDL.Nat8), IDL.Text, IDL.Bool], [ResultOkUnit], []),
    delete: IDL.Func([IDL.Text], [ResultOkUnit], []),
    bulkSync: IDL.Func([IDL.Vec(MemoryInput), IDL.Vec(SessionInput)], [ResultOkSyncResult], []),
    storeSession: IDL.Func([IDL.Text, IDL.Vec(IDL.Nat8), IDL.Int, IDL.Int], [ResultOkUnit], []),
    // VetKey endpoints (update calls for consensus-verified security)
    getEncryptedVetkey: IDL.Func([IDL.Vec(IDL.Nat8)], [ResultOkBlob], []),
    getVetkeyVerificationKey: IDL.Func([], [ResultOkBlob], []),
    // Query calls (return Result types)
    recall: IDL.Func([IDL.Text], [ResultOkOptMemory], ["query"]),
    getStats: IDL.Func([], [ResultOkStats], ["query"]),
    getCategories: IDL.Func([], [ResultOkCategories], ["query"]),
    getAuditLog: IDL.Func([IDL.Nat, IDL.Nat], [ResultOkAuditEntries], ["query"]),
    getAuditLogSize: IDL.Func([], [ResultOkNat], ["query"]),
    getOwner: IDL.Func([], [ResultOkPrincipalVault], ["query"]),
    getVaultVersion: IDL.Func([], [ResultOkVaultVersion], ["query"]),
    // Composite queries (return Result types)
    getDashboard: IDL.Func([], [ResultOkDashboard], ["composite_query"]),
    recallRelevant: IDL.Func(
      [IDL.Opt(IDL.Text), IDL.Opt(IDL.Text), IDL.Nat],
      [ResultOkMemories],
      ["composite_query"],
    ),
    getSessions: IDL.Func([IDL.Nat, IDL.Nat], [ResultOkSessions], ["composite_query"]),
    getSyncManifest: IDL.Func([], [ResultOkManifest], ["composite_query"]),
  });
};

// eslint-disable-next-line @typescript-eslint/no-explicit-any -- InterfaceFactory param type from @dfinity/candid
const factoryIdlFactory = ({ IDL: _IDL }: any) => {
  return IDL.Service({
    createVault: IDL.Func([], [ResultOkPrincipal], []),
    transferController: IDL.Func([], [ResultOkFactoryUnit], []),
    revokeFactoryController: IDL.Func([], [ResultOkFactoryUnit], []),
    upgradeMyVault: IDL.Func([], [ResultOkFactoryUnit], []),
    claimAdmin: IDL.Func([], [ResultOkFactoryUnit], []),
    adminRegisterVault: IDL.Func([IDL.Principal, IDL.Principal], [ResultOkFactoryUnit], []),
    adminUploadVaultWasm: IDL.Func([IDL.Vec(IDL.Nat8), IDL.Nat], [ResultOkFactoryUnit], []),
    adminUpgradeVault: IDL.Func([IDL.Principal], [ResultOkFactoryUnit], []),
    adminUpgradeAllVaults: IDL.Func([], [ResultOkUpgradeResult], []),
    getAdmin: IDL.Func([], [IDL.Opt(IDL.Principal)], ["query"]),
    getVault: IDL.Func([], [IDL.Opt(IDL.Principal)], ["query"]),
    getTotalCreated: IDL.Func([], [IDL.Nat], ["query"]),
    getAllVaults: IDL.Func([], [ResultOkFactoryVaults], ["query"]),
    getLatestVaultVersion: IDL.Func([], [IDL.Nat], ["query"]),
  });
};

// -- TypeScript types matching Candid --

export interface MemoryEntryData {
  key: string;
  category: string;
  content: Uint8Array;
  metadata: string;
  createdAt: bigint;
  updatedAt: bigint;
  isEncrypted: boolean;
}

export interface SessionEntryData {
  sessionId: string;
  data: Uint8Array;
  startedAt: bigint;
  endedAt: bigint;
}

export interface VaultStatsData {
  totalMemories: bigint;
  totalSessions: bigint;
  categories: string[];
  bytesUsed: bigint;
  cycleBalance: bigint;
  lastUpdated: bigint;
}

export interface DashboardDataResult {
  stats: VaultStatsData;
  recentMemories: MemoryEntryData[];
  recentSessions: SessionEntryData[];
}

export interface SyncManifestData {
  lastUpdated: bigint;
  memoriesCount: bigint;
  sessionsCount: bigint;
  categoryChecksums: [string, string][];
}

export interface SyncResultData {
  stored: bigint;
  skipped: bigint;
  errors: string[];
}

export interface VaultVersionData {
  version: bigint;
  supportsEncryption: boolean;
}

export interface UpgradeResultData {
  succeeded: bigint;
  failed: bigint;
  errors: string[];
}

export interface AuditEntryData {
  timestamp: bigint;
  action:
    | { store: null }
    | { delete: null }
    | { bulkSync: null }
    | { restore: null }
    | { created: null }
    | { accessDenied: null }
    | { upgrade: null };
  caller: Principal;
  key: [] | [string];
  category: [] | [string];
  details: [] | [string];
}

// -- Helpers --

/// Unwrap a Candid Result variant. Throws on #err.
function unwrapResult<T>(result: { ok: T } | { err: unknown }, context: string): T {
  if ("ok" in result) {
    return result.ok;
  }
  const err = (result as { err: unknown }).err;
  if (err && typeof err === "object") {
    if ("unauthorized" in err) throw new Error(`${context}: Unauthorized -- you are not the vault owner`);
    if ("notFound" in err) throw new Error(`${context}: Not found`);
    if ("invalidInput" in err) throw new Error(`${context}: Invalid input -- ${(err as { invalidInput: string }).invalidInput}`);
    if ("vetKeyError" in err) throw new Error(`${context}: VetKey error -- ${(err as { vetKeyError: string }).vetKeyError}`);
    if ("alreadyExists" in err) throw new Error(`${context}: Already exists`);
    if ("insufficientCycles" in err) throw new Error(`${context}: Insufficient cycles`);
    if ("creationFailed" in err) throw new Error(`${context}: Creation failed -- ${(err as { creationFailed: string }).creationFailed}`);
    if ("upgradeError" in err) throw new Error(`${context}: Upgrade failed -- ${(err as { upgradeError: string }).upgradeError}`);
    if ("noWasmUploaded" in err) throw new Error(`${context}: No vault WASM has been uploaded to the Factory yet`);
  }
  throw new Error(`${context}: Unknown error`);
}

// -- IC Client --

export class IcClient {
  private agent: HttpAgent | null = null;
  private identity: Identity | null = null;
  private config: IcStorageConfig;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any -- cached actor; methods accessed dynamically
  private cachedVaultActor: any = null;

  constructor(config: IcStorageConfig) {
    this.config = config;
  }

  /// Get the IC host URL based on network config.
  private getHost(): string {
    return this.config.network === "local" ? "http://127.0.0.1:4943" : "https://icp0.io";
  }

  /// Load the Ed25519 identity from disk and create an authenticated HttpAgent.
  async initAgent(): Promise<HttpAgent> {
    if (this.agent) return this.agent;

    if (!identityExists()) {
      throw new Error(
        "No IC identity found. Run `openclaw ic-memory setup` to create one.",
      );
    }

    this.identity = await loadIdentityAsync();

    this.agent = await HttpAgent.create({
      host: this.getHost(),
      identity: this.identity,
    });

    // Fetch root key for local dev (required by PocketIC)
    if (this.config.network === "local") {
      await this.agent.fetchRootKey();
    }

    return this.agent;
  }

  /// Initialize an agent with a specific identity (used by setup flow before
  /// the identity file is written to the standard location).
  async initAgentWithIdentity(identity: Identity): Promise<HttpAgent> {
    this.identity = identity;
    this.cachedVaultActor = null;

    this.agent = await HttpAgent.create({
      host: this.getHost(),
      identity,
    });

    if (this.config.network === "local") {
      await this.agent.fetchRootKey();
    }

    return this.agent;
  }

  /// Get the principal of the current identity.
  getPrincipal(): Principal | null {
    return this.identity?.getPrincipal() ?? null;
  }

  /// Check if an identity is available (key file exists).
  hasIdentity(): boolean {
    return identityExists();
  }

  // -- Factory methods --

  /// Create a vault for the current user.
  async createVault(): Promise<{ ok: Principal } | { err: string }> {
    const agent = await this.getAgent();
    if (!this.config.factoryCanisterId) {
      return { err: "Factory canister ID not configured" };
    }

    const factory = Actor.createActor(factoryIdlFactory, {
      agent,
      canisterId: this.config.factoryCanisterId,
    });

    const result = (await factory.createVault()) as
      | { ok: Principal }
      | {
          err: { alreadyExists: null } | { insufficientCycles: null } | { creationFailed: string };
        };

    if ("ok" in result) {
      return { ok: result.ok };
    }

    const errVal = result.err;
    if ("alreadyExists" in errVal) return { err: "You already have a vault" };
    if ("insufficientCycles" in errVal) return { err: "Factory has insufficient cycles" };
    if ("creationFailed" in errVal)
      return { err: `Vault creation failed: ${errVal.creationFailed}` };
    return { err: "Unknown error" };
  }

  /// Look up the caller's vault.
  async getVault(): Promise<Principal | null> {
    const agent = await this.getAgent();
    if (!this.config.factoryCanisterId) return null;

    const factory = Actor.createActor(factoryIdlFactory, {
      agent,
      canisterId: this.config.factoryCanisterId,
    });

    const result = (await factory.getVault()) as [] | [Principal];
    return result.length > 0 ? (result[0] ?? null) : null;
  }

  /// Revoke Factory's controller access to the caller's vault.
  /// Makes the vault fully sovereign -- only the owner is a controller.
  async revokeFactoryController(): Promise<{ ok: null } | { err: string }> {
    const agent = await this.getAgent();
    if (!this.config.factoryCanisterId) {
      return { err: "Factory canister ID not configured" };
    }

    const factory = Actor.createActor(factoryIdlFactory, {
      agent,
      canisterId: this.config.factoryCanisterId,
    });

    const result = (await factory.revokeFactoryController()) as
      | { ok: null }
      | { err: { unauthorized: string } | { notFound: string } };

    if ("ok" in result) return { ok: null };
    const errVal = result.err;
    if ("unauthorized" in errVal) return { err: errVal.unauthorized };
    if ("notFound" in errVal) return { err: errVal.notFound };
    return { err: "Unknown error" };
  }

  /// Trigger upgrade of the caller's vault to the latest WASM.
  /// Requires that the Factory is still a controller of the vault.
  async upgradeMyVault(): Promise<{ ok: null } | { err: string }> {
    const agent = await this.getAgent();
    if (!this.config.factoryCanisterId) {
      return { err: "Factory canister ID not configured" };
    }

    const factory = Actor.createActor(factoryIdlFactory, {
      agent,
      canisterId: this.config.factoryCanisterId,
    });

    const result = (await factory.upgradeMyVault()) as
      | { ok: null }
      | { err: unknown };

    if ("ok" in result) return { ok: null };
    return { err: this.formatFactoryError(result.err) };
  }

  /// Get the latest vault WASM version from the Factory.
  async getLatestVaultVersion(): Promise<bigint> {
    const agent = await this.getAgent();
    if (!this.config.factoryCanisterId) return 0n;

    const factory = Actor.createActor(factoryIdlFactory, {
      agent,
      canisterId: this.config.factoryCanisterId,
    });

    return (await factory.getLatestVaultVersion()) as bigint;
  }

  // -- Vault methods --

  /// Store a memory entry.
  async store(
    key: string,
    category: string,
    content: Uint8Array,
    metadata: string,
    isEncrypted = false,
  ): Promise<{ ok: null } | { err: string }> {
    const actor = await this.getVaultActor();
    const result = (await actor.store(key, category, content, metadata, isEncrypted)) as
      | { ok: null }
      | { err: { unauthorized: null } | { invalidInput: string } };

    if ("ok" in result) return { ok: null };
    return { err: this.formatVaultError(result.err) };
  }

  /// Recall a specific memory. Unwraps Result from query.
  async recall(key: string): Promise<MemoryEntryData | null> {
    const actor = await this.getVaultActor();
    const result = (await actor.recall(key)) as
      | { ok: [] | [MemoryEntryData] }
      | { err: unknown };
    const opt = unwrapResult(result, "recall");
    return opt.length > 0 ? (opt[0] ?? null) : null;
  }

  /// Delete a memory.
  async delete(key: string): Promise<{ ok: null } | { err: string }> {
    const actor = await this.getVaultActor();
    const result = (await actor.delete(key)) as
      | { ok: null }
      | { err: { unauthorized: null } | { notFound: null } };

    if ("ok" in result) return { ok: null };
    return { err: this.formatVaultError(result.err) };
  }

  /// Bulk sync memories and sessions.
  async bulkSync(
    memories: Array<{
      key: string;
      category: string;
      content: Uint8Array;
      metadata: string;
      createdAt: bigint;
      updatedAt: bigint;
      isEncrypted: boolean;
    }>,
    sessions: Array<{
      sessionId: string;
      data: Uint8Array;
      startedAt: bigint;
      endedAt: bigint;
    }>,
  ): Promise<{ ok: SyncResultData } | { err: string }> {
    const actor = await this.getVaultActor();
    const result = (await actor.bulkSync(memories, sessions)) as
      | { ok: SyncResultData }
      | { err: { unauthorized: null } };

    if ("ok" in result) return { ok: result.ok };
    return { err: this.formatVaultError(result.err) };
  }

  /// Store a session.
  async storeSession(
    sessionId: string,
    data: Uint8Array,
    startedAt: bigint,
    endedAt: bigint,
  ): Promise<{ ok: null } | { err: string }> {
    const actor = await this.getVaultActor();
    const result = (await actor.storeSession(sessionId, data, startedAt, endedAt)) as
      | { ok: null }
      | { err: { unauthorized: null } | { invalidInput: string } };

    if ("ok" in result) return { ok: null };
    return { err: this.formatVaultError(result.err) };
  }

  /// Get vault stats. Unwraps Result from query.
  async getStats(): Promise<VaultStatsData> {
    const actor = await this.getVaultActor();
    const result = (await actor.getStats()) as { ok: VaultStatsData } | { err: unknown };
    return unwrapResult(result, "getStats");
  }

  /// Get dashboard data (composite query). Unwraps Result.
  async getDashboard(): Promise<DashboardDataResult> {
    const actor = await this.getVaultActor();
    const result = (await actor.getDashboard()) as { ok: DashboardDataResult } | { err: unknown };
    return unwrapResult(result, "getDashboard");
  }

  /// Get sync manifest (composite query). Unwraps Result.
  async getSyncManifest(): Promise<SyncManifestData> {
    const actor = await this.getVaultActor();
    const result = (await actor.getSyncManifest()) as { ok: SyncManifestData } | { err: unknown };
    return unwrapResult(result, "getSyncManifest");
  }

  /// Search memories by category/prefix (composite query). Unwraps Result.
  async recallRelevant(
    category: string | null,
    prefix: string | null,
    limit: number,
  ): Promise<MemoryEntryData[]> {
    const actor = await this.getVaultActor();
    const result = (await actor.recallRelevant(
      category ? [category] : [],
      prefix ? [prefix] : [],
      BigInt(limit),
    )) as { ok: MemoryEntryData[] } | { err: unknown };
    return unwrapResult(result, "recallRelevant");
  }

  /// Get paginated sessions (composite query). Unwraps Result.
  async getSessions(offset: number, limit: number): Promise<SessionEntryData[]> {
    const actor = await this.getVaultActor();
    const result = (await actor.getSessions(BigInt(offset), BigInt(limit))) as
      | { ok: SessionEntryData[] }
      | { err: unknown };
    return unwrapResult(result, "getSessions");
  }

  /// Get audit log (paginated). Unwraps Result.
  async getAuditLog(offset: number, limit: number): Promise<AuditEntryData[]> {
    const actor = await this.getVaultActor();
    const result = (await actor.getAuditLog(BigInt(offset), BigInt(limit))) as
      | { ok: AuditEntryData[] }
      | { err: unknown };
    return unwrapResult(result, "getAuditLog");
  }

  /// Get audit log size. Unwraps Result.
  async getAuditLogSize(): Promise<bigint> {
    const actor = await this.getVaultActor();
    const result = (await actor.getAuditLogSize()) as { ok: bigint } | { err: unknown };
    return unwrapResult(result, "getAuditLogSize");
  }

  /// Get categories. Unwraps Result.
  async getCategories(): Promise<string[]> {
    const actor = await this.getVaultActor();
    const result = (await actor.getCategories()) as { ok: string[] } | { err: unknown };
    return unwrapResult(result, "getCategories");
  }

  // -- VetKey methods (for encryption) --

  /// Request an encrypted vetKey from the canister. The canister proxies to the
  /// IC management canister's vetkd_derive_key API. The returned key is encrypted
  /// under the provided transport public key. Unwraps Result.
  async getEncryptedVetkey(transportPublicKey: Uint8Array): Promise<Uint8Array> {
    const actor = await this.getVaultActor();
    const result = (await actor.getEncryptedVetkey(transportPublicKey)) as
      | { ok: Uint8Array }
      | { err: unknown };
    return unwrapResult(result, "getEncryptedVetkey");
  }

  /// Get the vetKey verification key (derived public key) for this canister.
  /// Used to verify decrypted vetKeys. Unwraps Result.
  async getVetkeyVerificationKey(): Promise<Uint8Array> {
    const actor = await this.getVaultActor();
    const result = (await actor.getVetkeyVerificationKey()) as
      | { ok: Uint8Array }
      | { err: unknown };
    return unwrapResult(result, "getVetkeyVerificationKey");
  }

  /// Get vault version info. Unwraps Result.
  async getVaultVersion(): Promise<VaultVersionData> {
    const actor = await this.getVaultActor();
    const result = (await actor.getVaultVersion()) as
      | { ok: VaultVersionData }
      | { err: unknown };
    return unwrapResult(result, "getVaultVersion");
  }

  // -- Internal helpers --

  private async getAgent(): Promise<HttpAgent> {
    if (this.agent) return this.agent;
    return this.initAgent();
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any -- Actor.createActor returns untyped actor; methods accessed dynamically
  private async getVaultActor(): Promise<any> {
    if (!this.config.canisterId) {
      throw new Error("Vault canister ID not configured. Run `openclaw ic-memory setup` first.");
    }

    // Return cached actor if agent hasn't changed
    if (this.cachedVaultActor) return this.cachedVaultActor;

    const agent = await this.getAgent();
    this.cachedVaultActor = Actor.createActor(userVaultIdlFactory, {
      agent,
      canisterId: this.config.canisterId,
    });
    return this.cachedVaultActor;
  }

  private formatVaultError(
    err: { unauthorized: null } | { notFound: null } | { invalidInput: string } | { vetKeyError: string },
  ): string {
    if ("unauthorized" in err) return "Unauthorized: you are not the vault owner";
    if ("notFound" in err) return "Not found";
    if ("invalidInput" in err) return `Invalid input: ${err.invalidInput}`;
    if ("vetKeyError" in err) return `VetKey error: ${err.vetKeyError}`;
    return "Unknown error";
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any -- Factory error variants are dynamic
  private formatFactoryError(err: any): string {
    if (err && typeof err === "object") {
      if ("unauthorized" in err) return `Unauthorized: ${err.unauthorized}`;
      if ("notFound" in err) return `Not found: ${err.notFound}`;
      if ("alreadyExists" in err) return "Already exists";
      if ("insufficientCycles" in err) return "Insufficient cycles";
      if ("creationFailed" in err) return `Creation failed: ${err.creationFailed}`;
      if ("upgradeError" in err) return `Upgrade failed: ${err.upgradeError}`;
      if ("noWasmUploaded" in err) return "No vault WASM has been uploaded to the Factory yet";
    }
    return "Unknown error";
  }
}
