/// Differential sync logic for IC Memory Vault.
/// Compares local state with IC vault and syncs only what's changed.

import type { IcClient, SyncManifestData, SyncResultData } from "./ic-client.js";

export interface LocalMemory {
  key: string;
  category: string;
  content: string; // will be encoded to Uint8Array
  metadata: string;
  createdAt: number;
  updatedAt: number;
}

export interface LocalSession {
  sessionId: string;
  data: string; // will be encoded to Uint8Array
  startedAt: number;
  endedAt: number;
}

export interface SyncStatus {
  lastSyncAt: number;
  memoriesSynced: number;
  sessionsSynced: number;
  isConnected: boolean;
  error?: string;
}

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

/// Encode a string to Uint8Array for canister storage.
export function encodeContent(content: string): Uint8Array {
  return textEncoder.encode(content);
}

/// Decode Uint8Array from canister to string.
export function decodeContent(data: Uint8Array): string {
  return textDecoder.decode(data);
}

/// Determine which local memories need syncing by comparing with vault manifest.
export function computeSyncDelta(
  localMemories: LocalMemory[],
  manifest: SyncManifestData,
): {
  toSync: LocalMemory[];
  toSkip: LocalMemory[];
} {
  // Build a map of category checksums from the vault
  const vaultChecksums = new Map<string, string>();
  for (const [cat, checksum] of manifest.categoryChecksums) {
    vaultChecksums.set(cat, checksum);
  }

  // If the vault has no data at all, sync everything
  if (manifest.memoriesCount === 0n) {
    return { toSync: localMemories, toSkip: [] };
  }

  // Build local category checksums for comparison
  const localByCategory = new Map<string, LocalMemory[]>();
  for (const mem of localMemories) {
    const list = localByCategory.get(mem.category) ?? [];
    list.push(mem);
    localByCategory.set(mem.category, list);
  }

  const toSync: LocalMemory[] = [];
  const toSkip: LocalMemory[] = [];

  for (const mem of localMemories) {
    // If this category doesn't exist in the vault, it needs syncing
    const vaultChecksum = vaultChecksums.get(mem.category);
    if (!vaultChecksum) {
      toSync.push(mem);
      continue;
    }

    // If local entry is newer than vault's lastUpdated, sync it
    // The vault's bulkSync will handle per-key conflict resolution
    if (BigInt(mem.updatedAt) > manifest.lastUpdated) {
      toSync.push(mem);
    } else {
      toSkip.push(mem);
    }
  }

  return { toSync, toSkip };
}

/// Batch size for bulk sync calls (avoid exceeding message size limits).
const BATCH_SIZE = 100;

/// Perform a full sync of local memories and sessions to the IC vault.
export async function performSync(
  client: IcClient,
  localMemories: LocalMemory[],
  localSessions: LocalSession[],
  onProgress?: (msg: string) => void,
): Promise<{
  totalStored: number;
  totalSkipped: number;
  errors: string[];
}> {
  let totalStored = 0;
  let totalSkipped = 0;
  const allErrors: string[] = [];

  // Get current vault manifest for differential sync
  let manifest: SyncManifestData;
  try {
    manifest = await client.getSyncManifest();
  } catch (err) {
    // If vault is empty or unreachable, sync everything
    manifest = {
      lastUpdated: 0n,
      memoriesCount: 0n,
      sessionsCount: 0n,
      categoryChecksums: [],
    };
  }

  // Compute delta
  const { toSync } = computeSyncDelta(localMemories, manifest);

  if (toSync.length === 0 && localSessions.length === 0) {
    onProgress?.("Already in sync. Nothing to upload.");
    return { totalStored: 0, totalSkipped: localMemories.length, errors: [] };
  }

  onProgress?.(`Syncing ${toSync.length} memories and ${localSessions.length} sessions...`);

  // Batch sync memories
  for (let i = 0; i < toSync.length; i += BATCH_SIZE) {
    const batch = toSync.slice(i, i + BATCH_SIZE);

    const memoryInputs = batch.map((m) => ({
      key: m.key,
      category: m.category,
      content: encodeContent(m.content),
      metadata: m.metadata,
      createdAt: BigInt(m.createdAt),
      updatedAt: BigInt(m.updatedAt),
    }));

    // Only include sessions in the first batch
    const sessionInputs =
      i === 0
        ? localSessions.map((s) => ({
            sessionId: s.sessionId,
            data: encodeContent(s.data),
            startedAt: BigInt(s.startedAt),
            endedAt: BigInt(s.endedAt),
          }))
        : [];

    const result = await client.bulkSync(memoryInputs, sessionInputs);
    if ("ok" in result) {
      totalStored += Number(result.ok.stored);
      totalSkipped += Number(result.ok.skipped);
      allErrors.push(...result.ok.errors);
    } else {
      allErrors.push(result.err);
    }

    onProgress?.(
      `Batch ${Math.floor(i / BATCH_SIZE) + 1}: stored ${totalStored}, skipped ${totalSkipped}`,
    );
  }

  // If we had sessions but no memories, send sessions alone
  if (toSync.length === 0 && localSessions.length > 0) {
    const sessionInputs = localSessions.map((s) => ({
      sessionId: s.sessionId,
      data: encodeContent(s.data),
      startedAt: BigInt(s.startedAt),
      endedAt: BigInt(s.endedAt),
    }));

    const result = await client.bulkSync([], sessionInputs);
    if ("ok" in result) {
      totalStored += Number(result.ok.stored);
      totalSkipped += Number(result.ok.skipped);
      allErrors.push(...result.ok.errors);
    } else {
      allErrors.push(result.err);
    }
  }

  onProgress?.(
    `Sync complete: ${totalStored} stored, ${totalSkipped} skipped, ${allErrors.length} errors`,
  );

  return { totalStored, totalSkipped, errors: allErrors };
}

/// Restore all memories from the IC vault.
export async function restoreFromVault(
  client: IcClient,
  onProgress?: (msg: string) => void,
): Promise<{
  memories: LocalMemory[];
  sessions: LocalSession[];
}> {
  onProgress?.("Fetching dashboard from IC vault...");

  const dashboard = await client.getDashboard();
  const stats = dashboard.stats;

  onProgress?.(`Found ${stats.totalMemories} memories and ${stats.totalSessions} sessions`);

  // Fetch all memories by category
  const categories = await client.getCategories();
  const allMemories: LocalMemory[] = [];

  for (const cat of categories) {
    const entries = await client.recallRelevant(cat, null, 10000);
    for (const entry of entries) {
      allMemories.push({
        key: entry.key,
        category: entry.category,
        content: decodeContent(entry.content),
        metadata: entry.metadata,
        createdAt: Number(entry.createdAt),
        updatedAt: Number(entry.updatedAt),
      });
    }
    onProgress?.(`Fetched ${allMemories.length} memories (${cat})`);
  }

  // Sessions: for now we return what's in the dashboard
  const allSessions: LocalSession[] = dashboard.recentSessions.map((s) => ({
    sessionId: s.sessionId,
    data: decodeContent(s.data),
    startedAt: Number(s.startedAt),
    endedAt: Number(s.endedAt),
  }));

  onProgress?.(`Restore complete: ${allMemories.length} memories, ${allSessions.length} sessions`);

  return { memories: allMemories, sessions: allSessions };
}
