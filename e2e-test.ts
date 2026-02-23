#!/usr/bin/env npx tsx
/**
 * End-to-end test against IC mainnet.
 * Creates a vault, stores a memory, recalls it, checks stats/audit/dashboard,
 * deletes it, and verifies deletion.
 *
 * Usage: npx tsx e2e-test.ts
 *
 * Requires: IC identity already set up via `openclaw ic-memory setup`
 */

import { IcClient } from "./ic-client.js";
import { encodeContent, decodeContent } from "./sync.js";
import { identityExists, generateAndSaveIdentity, loadIdentityAsync } from "./identity.js";

const FACTORY_CANISTER_ID = "v7tpn-laaaa-aaaac-bcmdq-cai";

async function main() {
  const log = (msg: string) => console.log(`  [E2E] ${msg}`);
  const pass = (msg: string) => console.log(`  ✅ ${msg}`);
  const fail = (msg: string) => {
    console.error(`  ❌ ${msg}`);
    process.exit(1);
  };

  log("Starting E2E test against IC mainnet...\n");

  // -- Ensure identity exists --
  if (!identityExists()) {
    log("No IC identity found. Generating a new one...");
    await generateAndSaveIdentity();
    pass("Identity generated and saved to OS keychain");
  } else {
    log("Existing IC identity found.");
  }

  const identity = await loadIdentityAsync();

  // -- Create client --
  const client = new IcClient({
    factoryCanisterId: FACTORY_CANISTER_ID,
    canisterId: undefined as unknown as string, // will be set after vault creation
    network: "ic",
    autoSync: true,
    syncOnSessionEnd: true,
    syncOnAgentEnd: true,
  });

  await client.initAgentWithIdentity(identity);
  const principal = client.getPrincipal();
  log(`Identity principal: ${principal?.toText()}`);

  // -- Step 1: Create vault --
  log("\n--- Step 1: Create Vault ---");
  const createResult = await client.createVault();
  if ("err" in createResult) {
    // If vault already exists, look it up
    if (createResult.err === "You already have a vault") {
      log("Vault already exists, looking it up...");
      const existing = await client.getVault();
      if (!existing) fail("Vault exists but getVault returned null");
      (client as any).config.canisterId = existing!.toText();
      pass(`Vault found: ${existing!.toText()}`);
    } else {
      fail(`createVault failed: ${createResult.err}`);
    }
  } else {
    const vaultId = createResult.ok.toText();
    (client as any).config.canisterId = vaultId;
    pass(`Vault created: ${vaultId}`);
  }

  // -- Step 2: Store a memory --
  log("\n--- Step 2: Store Memory ---");
  const testKey = `e2e-test-${Date.now()}`;
  const testContent = "This is an E2E test memory stored on IC mainnet.";
  const testCategory = "e2e-test";
  const testMetadata = JSON.stringify({ test: true, timestamp: Date.now() });

  const storeResult = await client.store(
    testKey,
    testCategory,
    encodeContent(testContent),
    testMetadata,
  );
  if ("err" in storeResult) fail(`store failed: ${storeResult.err}`);
  pass(`Memory stored: ${testKey}`);

  // -- Step 3: Recall the memory (QUERY -- this was broken before!) --
  log("\n--- Step 3: Recall Memory (query) ---");
  const recalled = await client.recall(testKey);
  if (!recalled) fail("recall returned null");
  if (recalled!.key !== testKey) fail(`recall key mismatch: ${recalled!.key} !== ${testKey}`);
  const decodedContent = decodeContent(recalled!.content);
  if (decodedContent !== testContent) fail(`content mismatch: ${decodedContent} !== ${testContent}`);
  if (recalled!.category !== testCategory) fail(`category mismatch`);
  pass(`Memory recalled: key=${recalled!.key}, content="${decodedContent}"`);

  // -- Step 4: Get stats (QUERY) --
  log("\n--- Step 4: Get Stats (query) ---");
  const stats = await client.getStats();
  if (stats.totalMemories < 1n) fail(`totalMemories is ${stats.totalMemories}, expected >= 1`);
  pass(`Stats: ${stats.totalMemories} memories, ${stats.totalSessions} sessions, ${stats.bytesUsed} bytes, ${stats.cycleBalance} cycles`);

  // -- Step 5: Get dashboard (COMPOSITE QUERY) --
  log("\n--- Step 5: Get Dashboard (composite query) ---");
  const dashboard = await client.getDashboard();
  if (dashboard.stats.totalMemories < 1n) fail("dashboard totalMemories < 1");
  if (dashboard.recentMemories.length < 1) fail("dashboard has no recent memories");
  pass(`Dashboard: ${dashboard.recentMemories.length} recent memories, ${dashboard.recentSessions.length} recent sessions`);

  // -- Step 6: Get categories (QUERY) --
  log("\n--- Step 6: Get Categories (query) ---");
  const categories = await client.getCategories();
  if (!categories.includes(testCategory)) fail(`categories don't include ${testCategory}`);
  pass(`Categories: [${categories.join(", ")}]`);

  // -- Step 7: recallRelevant (COMPOSITE QUERY) --
  log("\n--- Step 7: Recall Relevant (composite query) ---");
  const relevant = await client.recallRelevant(testCategory, null, 100);
  if (relevant.length < 1) fail("recallRelevant returned 0 entries");
  const found = relevant.find((m) => m.key === testKey);
  if (!found) fail(`recallRelevant didn't return ${testKey}`);
  pass(`recallRelevant: ${relevant.length} entries in category "${testCategory}"`);

  // -- Step 8: Get sync manifest (COMPOSITE QUERY) --
  log("\n--- Step 8: Get Sync Manifest (composite query) ---");
  const manifest = await client.getSyncManifest();
  if (manifest.memoriesCount < 1n) fail("manifest memoriesCount < 1");
  pass(`Manifest: ${manifest.memoriesCount} memories, ${manifest.sessionsCount} sessions, ${manifest.categoryChecksums.length} categories`);

  // -- Step 9: Get audit log (QUERY) --
  log("\n--- Step 9: Get Audit Log (query) ---");
  const auditSize = await client.getAuditLogSize();
  if (auditSize < 1n) fail("audit log is empty");
  const auditEntries = await client.getAuditLog(0, 10);
  if (auditEntries.length < 1) fail("getAuditLog returned 0 entries");
  pass(`Audit log: ${auditSize} entries, first action: ${JSON.stringify(Object.keys(auditEntries[0].action)[0])}`);

  // -- Step 10: Store and recall a session --
  log("\n--- Step 10: Store Session ---");
  const sessionId = `e2e-session-${Date.now()}`;
  const sessionData = JSON.stringify({ test: true, messages: ["hello", "world"] });
  const now = BigInt(Date.now()) * 1_000_000n; // nanoseconds
  const sessionResult = await client.storeSession(sessionId, encodeContent(sessionData), now - 60_000_000_000n, now);
  if ("err" in sessionResult) fail(`storeSession failed: ${sessionResult.err}`);
  pass(`Session stored: ${sessionId}`);

  // -- Step 11: Get sessions (COMPOSITE QUERY) --
  log("\n--- Step 11: Get Sessions (composite query) ---");
  const sessions = await client.getSessions(0, 100);
  if (sessions.length < 1) fail("getSessions returned 0 entries");
  const foundSession = sessions.find((s) => s.sessionId === sessionId);
  if (!foundSession) fail(`getSessions didn't return ${sessionId}`);
  pass(`Sessions: ${sessions.length} total`);

  // -- Step 12: Delete the test memory --
  log("\n--- Step 12: Delete Memory ---");
  const deleteResult = await client.delete(testKey);
  if ("err" in deleteResult) fail(`delete failed: ${deleteResult.err}`);
  pass(`Memory deleted: ${testKey}`);

  // -- Step 13: Verify deletion --
  log("\n--- Step 13: Verify Deletion ---");
  // Wait briefly for the delete update to propagate to query replicas.
  // IC query calls can hit stale replicas immediately after an update.
  await new Promise((r) => setTimeout(r, 2000));
  const afterDelete = await client.recall(testKey);
  if (afterDelete !== null) fail("memory still exists after deletion");
  pass("Memory confirmed deleted");

  // -- Done --
  console.log("\n  ========================================");
  console.log("  ✅ ALL 13 E2E TESTS PASSED ON IC MAINNET");
  console.log("  ========================================\n");
}

main().catch((err) => {
  console.error("\n  ❌ E2E test failed:", err.message || err);
  process.exit(1);
});
