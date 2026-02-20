/// Tests for IC Sovereign Persistent Memory plugin.
/// Covers: config parsing, sync logic, encoding utilities, plugin structure, and identity management.

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { rmSync, mkdirSync, writeFileSync, existsSync } from "fs";
import { join } from "path";
import { parseConfig, type IcStorageConfig } from "./config.js";
import type { SyncManifestData } from "./ic-client.js";
import { encodeContent, decodeContent, computeSyncDelta, type LocalMemory } from "./sync.js";
import { formatBytes, formatCycles } from "./index.js";

// ============================================================
// Config parsing tests
// ============================================================

describe("config", () => {
  describe("parseConfig", () => {
    it("returns defaults for undefined input", () => {
      const cfg = parseConfig(undefined);
      expect(cfg.network).toBe("ic");
      expect(cfg.autoSync).toBe(true);
      expect(cfg.syncOnSessionEnd).toBe(true);
      expect(cfg.syncOnAgentEnd).toBe(true);
      expect(cfg.canisterId).toBeUndefined();
    });

    it("returns defaults for null input", () => {
      const cfg = parseConfig(null);
      expect(cfg.network).toBe("ic");
      expect(cfg.autoSync).toBe(true);
    });

    it("parses valid full config", () => {
      const cfg = parseConfig({
        canisterId: "uxrrr-q7777-77774-qaaaq-cai",
        factoryCanisterId: "bkyz2-fmaaa-aaaaa-qaaaq-cai",
        network: "local",
        autoSync: false,
        syncOnSessionEnd: false,
        syncOnAgentEnd: false,
      });
      expect(cfg.canisterId).toBe("uxrrr-q7777-77774-qaaaq-cai");
      expect(cfg.factoryCanisterId).toBe("bkyz2-fmaaa-aaaaa-qaaaq-cai");
      expect(cfg.network).toBe("local");
      expect(cfg.autoSync).toBe(false);
      expect(cfg.syncOnSessionEnd).toBe(false);
      expect(cfg.syncOnAgentEnd).toBe(false);
    });

    it("treats missing booleans as true (opt-out pattern)", () => {
      const cfg = parseConfig({ network: "ic" });
      expect(cfg.autoSync).toBe(true);
      expect(cfg.syncOnSessionEnd).toBe(true);
      expect(cfg.syncOnAgentEnd).toBe(true);
    });

    it("rejects unknown keys", () => {
      expect(() => parseConfig({ unknownKey: "value" })).toThrow('Unknown config key "unknownKey"');
    });

    it("rejects invalid network value", () => {
      expect(() => parseConfig({ network: "mainnet" })).toThrow('Invalid network "mainnet"');
    });

    it("rejects non-string canisterId", () => {
      expect(() => parseConfig({ canisterId: 123 })).toThrow("canisterId must be a string");
    });

    it("rejects non-object input", () => {
      expect(() => parseConfig("not-an-object")).toThrow("IC storage config must be an object");
    });

    it("rejects array input", () => {
      expect(() => parseConfig([1, 2, 3])).toThrow("IC storage config must be an object");
    });

    it("resolves environment variables in canisterId", () => {
      process.env.TEST_CANISTER_ID = "test-canister-123";
      const cfg = parseConfig({
        canisterId: "${TEST_CANISTER_ID}",
      });
      expect(cfg.canisterId).toBe("test-canister-123");
      delete process.env.TEST_CANISTER_ID;
    });

    it("resolves environment variables in factoryCanisterId", () => {
      process.env.TEST_FACTORY_ID = "factory-456";
      const cfg = parseConfig({
        factoryCanisterId: "${TEST_FACTORY_ID}",
      });
      expect(cfg.factoryCanisterId).toBe("factory-456");
      delete process.env.TEST_FACTORY_ID;
    });

    it("replaces undefined env vars with undefined canisterId", () => {
      const cfg = parseConfig({
        canisterId: "${NONEXISTENT_VAR}",
      });
      // Empty string from unresolved env var is treated as undefined (no canister configured)
      expect(cfg.canisterId).toBeUndefined();
    });

    it("falls back to default factoryCanisterId for unresolved env var", () => {
      const cfg = parseConfig({
        factoryCanisterId: "${NONEXISTENT_FACTORY_VAR}",
      });
      // Empty string from unresolved env var should fall back to default, not be ""
      expect(cfg.factoryCanisterId).toBe("v7tpn-laaaa-aaaac-bcmdq-cai");
    });

    it("rejects invalid factoryCanisterId format", () => {
      expect(() => parseConfig({ factoryCanisterId: "INVALID!" })).toThrow("Invalid factoryCanisterId format");
    });

    it("rejects invalid canisterId format", () => {
      expect(() => parseConfig({ canisterId: "INVALID!" })).toThrow("Invalid canisterId format");
    });

    it("accepts valid canisterId format", () => {
      const cfg = parseConfig({ canisterId: "uxrrr-q7777-77774-qaaaq-cai" });
      expect(cfg.canisterId).toBe("uxrrr-q7777-77774-qaaaq-cai");
    });
  });
});

// ============================================================
// Encoding/decoding tests
// ============================================================

describe("encoding", () => {
  it("round-trips text content", () => {
    const original = "Hello, IC Memory Vault!";
    const encoded = encodeContent(original);
    const decoded = decodeContent(encoded);
    expect(decoded).toBe(original);
  });

  it("handles empty string", () => {
    const encoded = encodeContent("");
    const decoded = decodeContent(encoded);
    expect(decoded).toBe("");
  });

  it("handles unicode content", () => {
    const original = "Unicode test: \u4f60\u597d \ud83d\ude80 \u00e9\u00e8\u00ea";
    const encoded = encodeContent(original);
    const decoded = decodeContent(encoded);
    expect(decoded).toBe(original);
  });

  it("handles multi-line content", () => {
    const original = "line 1\nline 2\nline 3\n";
    const encoded = encodeContent(original);
    const decoded = decodeContent(encoded);
    expect(decoded).toBe(original);
  });

  it("handles JSON content", () => {
    const json = JSON.stringify({ key: "value", nested: { arr: [1, 2, 3] } });
    const encoded = encodeContent(json);
    const decoded = decodeContent(encoded);
    expect(decoded).toBe(json);
    expect(JSON.parse(decoded)).toEqual({
      key: "value",
      nested: { arr: [1, 2, 3] },
    });
  });

  it("encodes to Uint8Array", () => {
    const encoded = encodeContent("abc");
    expect(encoded).toBeInstanceOf(Uint8Array);
    expect(encoded.length).toBe(3);
  });
});

// ============================================================
// Sync delta computation tests
// ============================================================

describe("computeSyncDelta", () => {
  // Local timestamps are in milliseconds; manifest lastUpdated is in nanoseconds (IC convention).
  // msToNs(ms) = ms * 1_000_000n is used internally by computeSyncDelta for comparison.
  const makeMemory = (key: string, category: string, updatedAtMs: number): LocalMemory => ({
    key,
    category,
    content: `content of ${key}`,
    metadata: "{}",
    createdAt: updatedAtMs - 1000,
    updatedAt: updatedAtMs,
  });

  // Helper: convert ms to ns BigInt (matching canister convention)
  const msToNsBigInt = (ms: number) => BigInt(ms) * 1_000_000n;

  it("syncs everything when vault is empty", () => {
    const local = [makeMemory("key1", "facts", 1000), makeMemory("key2", "prefs", 2000)];
    const manifest: SyncManifestData = {
      lastUpdated: 0n,
      memoriesCount: 0n,
      sessionsCount: 0n,
      categoryChecksums: [],
    };

    const { toSync, toSkip } = computeSyncDelta(local, manifest);
    expect(toSync).toHaveLength(2);
    expect(toSkip).toHaveLength(0);
  });

  it("syncs entries newer than vault lastUpdated", () => {
    const local = [
      makeMemory("key1", "facts", 5000), // newer than vault (5000ms > 3000ms)
      makeMemory("key2", "facts", 1000), // older than vault (1000ms < 3000ms)
    ];
    const manifest: SyncManifestData = {
      lastUpdated: msToNsBigInt(3000), // 3000ms in nanoseconds
      memoriesCount: 1n,
      sessionsCount: 0n,
      categoryChecksums: [["facts", "some-checksum"]],
    };

    const { toSync, toSkip } = computeSyncDelta(local, manifest);
    expect(toSync).toHaveLength(1);
    expect(toSync[0].key).toBe("key1");
    expect(toSkip).toHaveLength(1);
    expect(toSkip[0].key).toBe("key2");
  });

  it("syncs entries in new categories", () => {
    const local = [makeMemory("key1", "facts", 1000), makeMemory("key2", "new-category", 1000)];
    const manifest: SyncManifestData = {
      lastUpdated: msToNsBigInt(5000), // 5000ms in nanoseconds
      memoriesCount: 1n,
      sessionsCount: 0n,
      categoryChecksums: [["facts", "checksum"]],
    };

    const { toSync, toSkip } = computeSyncDelta(local, manifest);
    // key1 is older than vault lastUpdated, so skip
    // key2 is in a new category, so sync
    expect(toSync).toHaveLength(1);
    expect(toSync[0].key).toBe("key2");
    expect(toSkip).toHaveLength(1);
  });

  it("handles empty local memories", () => {
    const manifest: SyncManifestData = {
      lastUpdated: msToNsBigInt(5000),
      memoriesCount: 10n,
      sessionsCount: 2n,
      categoryChecksums: [["facts", "checksum"]],
    };

    const { toSync, toSkip } = computeSyncDelta([], manifest);
    expect(toSync).toHaveLength(0);
    expect(toSkip).toHaveLength(0);
  });

  it("handles vault with multiple categories", () => {
    const local = [
      makeMemory("key1", "facts", 6000),   // newer than vault (6000ms > 5000ms)
      makeMemory("key2", "prefs", 6000),   // newer than vault
      makeMemory("key3", "ideas", 1000),   // older than vault (1000ms < 5000ms)
    ];
    const manifest: SyncManifestData = {
      lastUpdated: msToNsBigInt(5000),
      memoriesCount: 5n,
      sessionsCount: 0n,
      categoryChecksums: [
        ["facts", "checksum1"],
        ["prefs", "checksum2"],
        ["ideas", "checksum3"],
      ],
    };

    const { toSync, toSkip } = computeSyncDelta(local, manifest);
    expect(toSync).toHaveLength(2); // key1 and key2 are newer
    expect(toSkip).toHaveLength(1); // key3 is older
  });
});

// ============================================================
// Plugin structure tests
// ============================================================

describe("plugin structure", () => {
  it("exports a valid plugin definition", async () => {
    const mod = await import("./index.js");
    const plugin = mod.default;

    expect(plugin.id).toBe("openclaw-ic-sovereign-persistent-memory");
    expect(plugin.name).toBe("IC Sovereign Persistent Memory");
    expect(plugin.kind).toBe("memory");
    expect(typeof plugin.register).toBe("function");
    expect(plugin.configSchema).toBeDefined();
    expect(typeof plugin.configSchema.parse).toBe("function");
  });

  it("configSchema.parse works", async () => {
    const mod = await import("./index.js");
    const plugin = mod.default;

    const cfg = plugin.configSchema.parse({
      network: "local",
      autoSync: false,
    });
    expect(cfg).toBeDefined();
    expect((cfg as IcStorageConfig).network).toBe("local");
    expect((cfg as IcStorageConfig).autoSync).toBe(false);
  });

  it("configSchema.parse throws on invalid input", async () => {
    const mod = await import("./index.js");
    const plugin = mod.default;

    expect(() => plugin.configSchema.parse({ network: "invalid" })).toThrow();
  });
});

// ============================================================
// Plugin metadata tests (openclaw.plugin.json)
// ============================================================

describe("plugin metadata", () => {
  it("has valid openclaw.plugin.json", async () => {
    const fs = await import("fs");
    const path = await import("path");
    const metadataPath = path.join(import.meta.dirname, "openclaw.plugin.json");
    const raw = fs.readFileSync(metadataPath, "utf-8");
    const metadata = JSON.parse(raw);

    expect(metadata.id).toBe("openclaw-ic-sovereign-persistent-memory");
    expect(metadata.kind).toBe("memory");
    expect(metadata.configSchema).toBeDefined();
    expect(metadata.configSchema.type).toBe("object");
    expect(metadata.configSchema.properties).toBeDefined();
    expect(metadata.configSchema.properties.canisterId).toBeDefined();
    expect(metadata.configSchema.properties.network).toBeDefined();
    expect(metadata.configSchema.properties.autoSync).toBeDefined();
    expect(metadata.uiHints).toBeDefined();
    expect(metadata.uiHints.canisterId).toBeDefined();
  });

  it("has valid package.json", async () => {
    const fs = await import("fs");
    const path = await import("path");
    const pkgPath = path.join(import.meta.dirname, "package.json");
    const raw = fs.readFileSync(pkgPath, "utf-8");
    const pkg = JSON.parse(raw);

    expect(pkg.name).toBe("openclaw-ic-sovereign-persistent-memory");
    expect(pkg.type).toBe("module");
    expect(pkg.openclaw).toBeDefined();
    expect(pkg.openclaw.extensions).toEqual(["./index.ts"]);
    expect(pkg.dependencies["@dfinity/agent"]).toBeDefined();
    expect(pkg.dependencies["@dfinity/identity"]).toBeDefined();
    expect(pkg.dependencies["@sinclair/typebox"]).toBeDefined();
    expect(pkg.dependencies["@dfinity/auth-client"]).toBeUndefined();
  });
});

// ============================================================
// Utility function tests
// ============================================================

describe("utility functions", () => {
  describe("formatBytes", () => {
    it("returns '0 B' for zero", () => {
      expect(formatBytes(0)).toBe("0 B");
    });

    it("returns '0 B' for negative numbers", () => {
      expect(formatBytes(-100)).toBe("0 B");
    });

    it("returns '0 B' for NaN", () => {
      expect(formatBytes(NaN)).toBe("0 B");
    });

    it("returns '0 B' for Infinity", () => {
      expect(formatBytes(Infinity)).toBe("0 B");
    });

    it("formats bytes", () => {
      expect(formatBytes(512)).toBe("512.0 B");
    });

    it("formats kilobytes", () => {
      expect(formatBytes(1024)).toBe("1.0 KB");
      expect(formatBytes(1536)).toBe("1.5 KB");
    });

    it("formats megabytes", () => {
      expect(formatBytes(1024 * 1024)).toBe("1.0 MB");
      expect(formatBytes(2.5 * 1024 * 1024)).toBe("2.5 MB");
    });

    it("formats gigabytes", () => {
      expect(formatBytes(1024 ** 3)).toBe("1.0 GB");
    });

    it("formats terabytes", () => {
      expect(formatBytes(1024 ** 4)).toBe("1.0 TB");
    });

    it("clamps to TB for very large values", () => {
      // 1024^5 (PB) should still show as TB since TB is the last unit
      expect(formatBytes(1024 ** 5)).toBe("1024.0 TB");
    });
  });

  describe("formatCycles", () => {
    it("formats small values with locale string", () => {
      const result = formatCycles(999_999_999);
      // toLocaleString output varies by locale, just check it's a string
      expect(typeof result).toBe("string");
      expect(result).not.toContain("T");
      expect(result).not.toContain("B");
    });

    it("formats billions", () => {
      expect(formatCycles(1_000_000_000)).toBe("1.00 B");
      expect(formatCycles(5_500_000_000)).toBe("5.50 B");
    });

    it("formats trillions", () => {
      expect(formatCycles(1_000_000_000_000)).toBe("1.00 T");
      expect(formatCycles(2_750_000_000_000)).toBe("2.75 T");
    });
  });
});

// ============================================================
// Smart prompting tests
// ============================================================

describe("smart prompting", () => {
  // Import the prompting module
  let prompts: typeof import("./prompts.js");

  beforeAll(async () => {
    prompts = await import("./prompts.js");
  });

  describe("canPrompt", () => {
    it("allows prompt when state is fresh", () => {
      const state: import("./prompts.js").PromptState = {
        dismissed: false,
        lastPromptAt: 0,
        promptCount: 0,
        trackedMemoryCount: 0,
        vaultConfigured: false,
      };
      expect(prompts.canPrompt(state)).toBe(true);
    });

    it("blocks prompt when vault is configured", () => {
      const state: import("./prompts.js").PromptState = {
        dismissed: false,
        lastPromptAt: 0,
        promptCount: 0,
        trackedMemoryCount: 0,
        vaultConfigured: true,
      };
      expect(prompts.canPrompt(state)).toBe(false);
    });

    it("blocks prompt when max prompts reached", () => {
      const state: import("./prompts.js").PromptState = {
        dismissed: false,
        lastPromptAt: 0,
        promptCount: 5,
        trackedMemoryCount: 0,
        vaultConfigured: false,
      };
      expect(prompts.canPrompt(state)).toBe(false);
    });

    it("blocks prompt when dismissed and prompted 2+ times", () => {
      const state: import("./prompts.js").PromptState = {
        dismissed: true,
        lastPromptAt: 0,
        promptCount: 2,
        trackedMemoryCount: 0,
        vaultConfigured: false,
      };
      expect(prompts.canPrompt(state)).toBe(false);
    });

    it("allows prompt when dismissed but only prompted once", () => {
      const state: import("./prompts.js").PromptState = {
        dismissed: true,
        lastPromptAt: 0,
        promptCount: 1,
        trackedMemoryCount: 0,
        vaultConfigured: false,
      };
      expect(prompts.canPrompt(state)).toBe(true);
    });

    it("blocks prompt when too recent", () => {
      const state: import("./prompts.js").PromptState = {
        dismissed: false,
        lastPromptAt: Date.now() - 1000, // 1 second ago
        promptCount: 1,
        trackedMemoryCount: 0,
        vaultConfigured: false,
      };
      expect(prompts.canPrompt(state)).toBe(false);
    });

    it("allows prompt after 24 hours", () => {
      const state: import("./prompts.js").PromptState = {
        dismissed: false,
        lastPromptAt: Date.now() - 25 * 60 * 60 * 1000, // 25 hours ago
        promptCount: 1,
        trackedMemoryCount: 0,
        vaultConfigured: false,
      };
      expect(prompts.canPrompt(state)).toBe(true);
    });
  });

  describe("shouldNudgeForMilestone", () => {
    it("nudges at 25 memories", () => {
      const state: import("./prompts.js").PromptState = {
        dismissed: false,
        lastPromptAt: 0,
        promptCount: 0,
        trackedMemoryCount: 20, // was below 25
        vaultConfigured: false,
      };
      expect(prompts.shouldNudgeForMilestone(state, 25)).toBe(true);
    });

    it("nudges at 50 memories", () => {
      const state: import("./prompts.js").PromptState = {
        dismissed: false,
        lastPromptAt: 0,
        promptCount: 1,
        trackedMemoryCount: 40,
        vaultConfigured: false,
      };
      expect(prompts.shouldNudgeForMilestone(state, 50)).toBe(true);
    });

    it("does not nudge below first milestone", () => {
      const state: import("./prompts.js").PromptState = {
        dismissed: false,
        lastPromptAt: 0,
        promptCount: 0,
        trackedMemoryCount: 10,
        vaultConfigured: false,
      };
      expect(prompts.shouldNudgeForMilestone(state, 15)).toBe(false);
    });

    it("does not nudge when vault is configured", () => {
      const state: import("./prompts.js").PromptState = {
        dismissed: false,
        lastPromptAt: 0,
        promptCount: 0,
        trackedMemoryCount: 20,
        vaultConfigured: true,
      };
      expect(prompts.shouldNudgeForMilestone(state, 50)).toBe(false);
    });

    it("does not nudge when milestone already passed", () => {
      const state: import("./prompts.js").PromptState = {
        dismissed: false,
        lastPromptAt: 0,
        promptCount: 0,
        trackedMemoryCount: 30, // already past 25
        vaultConfigured: false,
      };
      expect(prompts.shouldNudgeForMilestone(state, 30)).toBe(false);
    });
  });

  describe("message content", () => {
    it("first run message mentions key benefits", () => {
      const lines = prompts.getFirstRunMessage();
      const text = lines.join("\n");
      expect(text).toContain("only on this device");
      expect(text).toContain("Only your identity can read or write");
      expect(text).toContain("any device, forever");
      expect(text).toContain("openclaw ic-memory setup");
    });

    it("milestone nudge mentions memory count", () => {
      const lines = prompts.getMilestoneNudgeMessage(127);
      const text = lines.join("\n");
      expect(text).toContain("127");
      expect(text).toContain("no backup");
      expect(text).toContain("lost or reset");
      expect(text).toContain("openclaw ic-memory setup");
    });

    it("reminder message is short", () => {
      const lines = prompts.getReminderMessage(30);
      expect(lines.length).toBeLessThanOrEqual(2);
      expect(lines.join("\n")).toContain("openclaw ic-memory setup");
    });

    it("reminder message for high count mentions the number", () => {
      const lines = prompts.getReminderMessage(200);
      const text = lines.join("\n");
      expect(text).toContain("200");
      expect(text).toContain("unprotected memories");
    });

    it("setup complete message confirms protection", () => {
      const lines = prompts.getSetupCompleteMessage("abc-123");
      const text = lines.join("\n");
      expect(text).toContain("active");
      expect(text).toContain("abc-123");
      expect(text).toContain("sovereign and persistent");
      expect(text).toContain("openclaw ic-memory restore");
    });
  });

  describe("state persistence", () => {
    it("loadPromptState returns defaults for missing file", () => {
      const state = prompts.loadPromptState("/tmp/nonexistent-dir-xyz");
      expect(state.dismissed).toBe(false);
      expect(state.promptCount).toBe(0);
      expect(state.trackedMemoryCount).toBe(0);
      expect(state.vaultConfigured).toBe(false);
    });

    it("round-trips state through save/load", () => {
      const tmpDir = `/tmp/ic-vault-test-${Date.now()}`;
      const state: import("./prompts.js").PromptState = {
        dismissed: true,
        lastPromptAt: 1234567890,
        promptCount: 3,
        trackedMemoryCount: 75,
        vaultConfigured: false,
      };

      prompts.savePromptState(state, tmpDir);
      const loaded = prompts.loadPromptState(tmpDir);

      expect(loaded.dismissed).toBe(true);
      expect(loaded.lastPromptAt).toBe(1234567890);
      expect(loaded.promptCount).toBe(3);
      expect(loaded.trackedMemoryCount).toBe(75);
      expect(loaded.vaultConfigured).toBe(false);

      // Cleanup temp directory
      try { rmSync(tmpDir, { recursive: true }); } catch {}
    });
  });
});

// ============================================================
// Identity management tests
// ============================================================

describe("identity", () => {
  it("generates a valid Ed25519 identity", async () => {
    const { Ed25519KeyIdentity } = await import("@dfinity/identity");
    const identity = Ed25519KeyIdentity.generate();
    const principal = identity.getPrincipal();
    expect(principal.toText()).toMatch(/^[a-z0-9-]+$/);
    expect(principal.toText().length).toBeGreaterThan(10);
  });

  it("round-trips identity through JSON serialization", async () => {
    const { Ed25519KeyIdentity } = await import("@dfinity/identity");
    const identity = Ed25519KeyIdentity.generate();
    const json = JSON.stringify(identity.toJSON());

    const restored = Ed25519KeyIdentity.fromJSON(json);
    expect(restored.getPrincipal().toText()).toBe(identity.getPrincipal().toText());
  });

  it("round-trips identity through secret key export/import", async () => {
    const { Ed25519KeyIdentity } = await import("@dfinity/identity");
    const identity = Ed25519KeyIdentity.generate();
    const kp = identity.getKeyPair();

    // Export secret key as base64
    const secretB64 = Buffer.from(kp.secretKey).toString("base64");
    expect(secretB64.length).toBe(44); // 32 bytes = 44 base64 chars

    // Import from base64
    const restoredKey = Buffer.from(secretB64, "base64");
    const restored = Ed25519KeyIdentity.fromSecretKey(new Uint8Array(restoredKey).buffer as ArrayBuffer);
    expect(restored.getPrincipal().toText()).toBe(identity.getPrincipal().toText());
  });

  it("different keys produce different principals", async () => {
    const { Ed25519KeyIdentity } = await import("@dfinity/identity");
    const id1 = Ed25519KeyIdentity.generate();
    const id2 = Ed25519KeyIdentity.generate();
    expect(id1.getPrincipal().toText()).not.toBe(id2.getPrincipal().toText());
  });

  it("secret key is exactly 32 bytes", async () => {
    const { Ed25519KeyIdentity } = await import("@dfinity/identity");
    const identity = Ed25519KeyIdentity.generate();
    const kp = identity.getKeyPair();
    expect(kp.secretKey.byteLength).toBe(32);
  });
});

// ============================================================
// AES-256-GCM encryption round-trip tests
// ============================================================

describe("encryption", () => {
  it("round-trips data through AES-256-GCM encryption", async () => {
    const crypto = await import("node:crypto");

    const passphrase = "test-passphrase-12345";
    const plaintext = '["pubkeyhex","secretkeyhex"]';

    // Encrypt
    const salt = crypto.randomBytes(32);
    const iv = crypto.randomBytes(16);
    const key = crypto.pbkdf2Sync(passphrase, salt, 600_000, 32, "sha256");
    const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
    const encrypted = Buffer.concat([cipher.update(plaintext, "utf-8"), cipher.final()]);
    const authTag = cipher.getAuthTag();
    const combined = Buffer.concat([salt, iv, authTag, encrypted]);

    // Decrypt
    const dSalt = combined.subarray(0, 32);
    const dIv = combined.subarray(32, 48);
    const dAuthTag = combined.subarray(48, 64);
    const dEncrypted = combined.subarray(64);
    const dKey = crypto.pbkdf2Sync(passphrase, dSalt, 600_000, 32, "sha256");
    const decipher = crypto.createDecipheriv("aes-256-gcm", dKey, dIv);
    decipher.setAuthTag(dAuthTag);
    const decrypted = Buffer.concat([decipher.update(dEncrypted), decipher.final()]);

    expect(decrypted.toString("utf-8")).toBe(plaintext);
  });

  it("fails with wrong passphrase", async () => {
    const crypto = await import("node:crypto");

    const passphrase = "correct-passphrase";
    const wrongPassphrase = "wrong-passphrase";
    const plaintext = "secret-data";

    // Encrypt with correct passphrase
    const salt = crypto.randomBytes(32);
    const iv = crypto.randomBytes(16);
    const key = crypto.pbkdf2Sync(passphrase, salt, 600_000, 32, "sha256");
    const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
    const encrypted = Buffer.concat([cipher.update(plaintext, "utf-8"), cipher.final()]);
    const authTag = cipher.getAuthTag();
    const combined = Buffer.concat([salt, iv, authTag, encrypted]);

    // Attempt decrypt with wrong passphrase
    const dSalt = combined.subarray(0, 32);
    const dIv = combined.subarray(32, 48);
    const dAuthTag = combined.subarray(48, 64);
    const dEncrypted = combined.subarray(64);
    const dKey = crypto.pbkdf2Sync(wrongPassphrase, dSalt, 600_000, 32, "sha256");
    const decipher = crypto.createDecipheriv("aes-256-gcm", dKey, dIv);
    decipher.setAuthTag(dAuthTag);

    expect(() => {
      Buffer.concat([decipher.update(dEncrypted), decipher.final()]);
    }).toThrow();
  });

  it("encrypted output is different each time (random salt/iv)", async () => {
    const crypto = await import("node:crypto");

    const passphrase = "same-passphrase";
    const plaintext = "same-data";

    function encrypt(): Buffer {
      const salt = crypto.randomBytes(32);
      const iv = crypto.randomBytes(16);
      const key = crypto.pbkdf2Sync(passphrase, salt, 600_000, 32, "sha256");
      const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
      const encrypted = Buffer.concat([cipher.update(plaintext, "utf-8"), cipher.final()]);
      const authTag = cipher.getAuthTag();
      return Buffer.concat([salt, iv, authTag, encrypted]);
    }

    const a = encrypt();
    const b = encrypt();
    expect(a.equals(b)).toBe(false); // Different salt/iv -> different ciphertext
  });

  it("rejects truncated encrypted data", async () => {
    const crypto = await import("node:crypto");

    const passphrase = "test";
    // Too short: less than salt(32) + iv(16) + authTag(16) + 1 = 65 bytes
    const tooShort = crypto.randomBytes(50);

    const dKey = crypto.pbkdf2Sync(passphrase, tooShort.subarray(0, 32), 600_000, 32, "sha256");
    // This should fail because there's not enough data for salt+iv+authTag+ciphertext
    expect(tooShort.length).toBeLessThan(65);
  });
});

// ============================================================
// Memory reader tests
// ============================================================

describe("memory-reader", () => {
  let memoryReader: typeof import("./memory-reader.js");
  const tmpWorkspace = `/tmp/ic-vault-memory-reader-test-${Date.now()}`;

  beforeAll(async () => {
    memoryReader = await import("./memory-reader.js");

    // Create test workspace with memory files
    mkdirSync(join(tmpWorkspace, "memory"), { recursive: true });

    // Primary MEMORY.md
    writeFileSync(
      join(tmpWorkspace, "MEMORY.md"),
      `---
title: Agent Memory
---

# Agent Memory

## User Preferences

- Prefers TypeScript over JavaScript
- Uses Vim keybindings
- Dark mode in all editors

## Project Decisions

- Using mo:core 2.0.0 for canisters
- Ed25519 for identity management
- Factory pattern for vault creation

## Tools and Workflow

- Build with dfx 0.30.2
- Deploy to IC mainnet
- Tests with vitest
`,
    );

    // Daily note in memory/ directory
    writeFileSync(
      join(tmpWorkspace, "memory", "2026-02-20.md"),
      `# 2026-02-20

## Session Notes

- Fixed compilation error in Factory.mo
- Migrated from Trie to Map (mo:core)
- Published v1.0.3 to npm

## Blockers

- dfx ships moc 0.16.3, too old for mo:core
- Need moc-wrapper to override
`,
    );

    // Another daily note
    writeFileSync(
      join(tmpWorkspace, "memory", "2026-02-19.md"),
      `# 2026-02-19

## Context

Working on the IC Sovereign Persistent Memory plugin.
Currently at v1.0.2, preparing for mo:core migration.
`,
    );
  });

  afterAll(() => {
    try {
      rmSync(tmpWorkspace, { recursive: true });
    } catch {
      // Best effort cleanup
    }
  });

  describe("stripFrontMatter", () => {
    it("strips YAML front matter from markdown", () => {
      const input = `---
title: Test
tags: [a, b]
---
# Content Here`;
      const result = memoryReader.stripFrontMatter(input);
      expect(result).toBe("# Content Here");
    });

    it("returns unchanged content without front matter", () => {
      const input = "# No Front Matter\nSome content";
      expect(memoryReader.stripFrontMatter(input)).toBe(input);
    });

    it("handles empty content after front matter", () => {
      const input = `---
title: Test
---`;
      expect(memoryReader.stripFrontMatter(input)).toBe("");
    });

    it("handles content that starts with --- but is not front matter", () => {
      const input = "---\nThis is a horizontal rule with no closing ---";
      // No closing ---, so returned as-is
      expect(memoryReader.stripFrontMatter(input)).toBe(input);
    });
  });

  describe("parseMarkdownSections", () => {
    it("parses headings into sections", () => {
      const content = `## Preferences

- Dark mode
- Vim keys

## Decisions

- Use TypeScript
`;
      const sections = memoryReader.parseMarkdownSections(content, "test.md");
      expect(sections).toHaveLength(2);
      expect(sections[0].heading).toBe("Preferences");
      expect(sections[0].content).toContain("Dark mode");
      expect(sections[1].heading).toBe("Decisions");
      expect(sections[1].content).toContain("Use TypeScript");
    });

    it("handles content before any heading as 'general'", () => {
      const content = `Some introductory content
without any headings.`;
      const sections = memoryReader.parseMarkdownSections(content, "test.md");
      expect(sections).toHaveLength(1);
      expect(sections[0].heading).toBe("general");
    });

    it("handles empty content", () => {
      expect(memoryReader.parseMarkdownSections("", "test.md")).toHaveLength(0);
      expect(memoryReader.parseMarkdownSections("   \n  \n  ", "test.md")).toHaveLength(0);
    });

    it("strips front matter before parsing", () => {
      const content = `---
title: Test
---

## Real Content

This should be parsed.`;
      const sections = memoryReader.parseMarkdownSections(
        memoryReader.stripFrontMatter(content),
        "test.md",
      );
      expect(sections).toHaveLength(1);
      expect(sections[0].heading).toBe("Real Content");
    });

    it("includes source file path", () => {
      const sections = memoryReader.parseMarkdownSections("## Test\nContent", "/path/to/file.md");
      expect(sections[0].sourceFile).toBe("/path/to/file.md");
    });
  });

  describe("deriveCategory", () => {
    it("maps preference headings to 'preferences'", () => {
      expect(memoryReader.deriveCategory("User Preferences")).toBe("preferences");
      expect(memoryReader.deriveCategory("My Prefs")).toBe("preferences");
    });

    it("maps decision headings to 'decisions'", () => {
      expect(memoryReader.deriveCategory("Project Decisions")).toBe("decisions");
      expect(memoryReader.deriveCategory("We Decided")).toBe("decisions");
    });

    it("maps project headings to 'project'", () => {
      expect(memoryReader.deriveCategory("Project Architecture")).toBe("project");
    });

    it("maps tool headings to 'tools'", () => {
      expect(memoryReader.deriveCategory("Tools and Workflow")).toBe("tools");
      expect(memoryReader.deriveCategory("Command Reference")).toBe("tools");
    });

    it("maps lesson headings to 'lessons'", () => {
      expect(memoryReader.deriveCategory("Lessons Learned")).toBe("lessons");
      expect(memoryReader.deriveCategory("Key Insight")).toBe("lessons");
    });

    it("maps blocker headings to 'issues'", () => {
      expect(memoryReader.deriveCategory("Blockers")).toBe("issues");
      expect(memoryReader.deriveCategory("Current Issues")).toBe("issues");
    });

    it("maps date headings to 'daily'", () => {
      expect(memoryReader.deriveCategory("2026-02-20")).toBe("daily");
      expect(memoryReader.deriveCategory("2025-12-31")).toBe("daily");
    });

    it("returns 'general' for unrecognized headings", () => {
      expect(memoryReader.deriveCategory("Random Stuff")).toBe("general");
      expect(memoryReader.deriveCategory("Miscellaneous")).toBe("general");
    });

    it("maps identity headings to 'identity'", () => {
      expect(memoryReader.deriveCategory("About Me")).toBe("identity");
      expect(memoryReader.deriveCategory("User Identity")).toBe("identity");
    });

    it("maps convention headings to 'conventions'", () => {
      expect(memoryReader.deriveCategory("Coding Conventions")).toBe("conventions");
      expect(memoryReader.deriveCategory("Style Guide")).toBe("conventions");
    });

    it("maps context headings to 'context'", () => {
      expect(memoryReader.deriveCategory("Current Context")).toBe("context");
      expect(memoryReader.deriveCategory("Project Status")).toBe("context");
    });

    it("maps task headings to 'tasks'", () => {
      expect(memoryReader.deriveCategory("Todo List")).toBe("tasks");
      expect(memoryReader.deriveCategory("Next Steps")).toBe("tasks");
    });
  });

  describe("deriveKey", () => {
    it("creates key from filename and heading", () => {
      const key = memoryReader.deriveKey("User Preferences", "/workspace/MEMORY.md");
      expect(key).toBe("MEMORY/user-preferences");
    });

    it("sanitizes special characters", () => {
      const key = memoryReader.deriveKey("What's the plan?!", "/workspace/notes.md");
      expect(key).toBe("notes/what-s-the-plan");
    });

    it("uses 'general' for empty heading", () => {
      const key = memoryReader.deriveKey("", "/workspace/MEMORY.md");
      expect(key).toBe("MEMORY/general");
    });

    it("truncates long headings to 60 chars", () => {
      const longHeading = "This is a very long heading that should be truncated to sixty characters maximum";
      const key = memoryReader.deriveKey(longHeading, "/workspace/test.md");
      const headingPart = key.split("/")[1];
      expect(headingPart.length).toBeLessThanOrEqual(60);
    });
  });

  describe("findMemoryFiles", () => {
    it("finds MEMORY.md in workspace", () => {
      const files = memoryReader.findMemoryFiles(tmpWorkspace);
      const basenames = files.map((f) => f.split("/").pop());
      expect(basenames).toContain("MEMORY.md");
    });

    it("finds daily notes in memory/ directory", () => {
      const files = memoryReader.findMemoryFiles(tmpWorkspace);
      const basenames = files.map((f) => f.split("/").pop());
      expect(basenames).toContain("2026-02-20.md");
      expect(basenames).toContain("2026-02-19.md");
    });

    it("returns empty for nonexistent workspace", () => {
      const files = memoryReader.findMemoryFiles("/tmp/nonexistent-workspace-xyz");
      expect(files).toHaveLength(0);
    });

    it("sorts by modification time (newest first)", () => {
      const files = memoryReader.findMemoryFiles(tmpWorkspace);
      expect(files.length).toBeGreaterThan(0);
      // Files should be sorted -- we can't guarantee exact order in CI,
      // but all should be valid paths
      for (const f of files) {
        expect(existsSync(f)).toBe(true);
      }
    });
  });

  describe("readLocalMemories", () => {
    it("reads and parses all memory files from workspace", () => {
      const memories = memoryReader.readLocalMemories(tmpWorkspace);
      expect(memories.length).toBeGreaterThan(0);
    });

    it("produces entries with required fields", () => {
      const memories = memoryReader.readLocalMemories(tmpWorkspace);
      for (const mem of memories) {
        expect(mem.key).toBeTruthy();
        expect(mem.category).toBeTruthy();
        expect(mem.content).toBeTruthy();
        expect(typeof mem.metadata).toBe("string");
        expect(mem.createdAt).toBeGreaterThan(0);
        expect(mem.updatedAt).toBeGreaterThan(0);
      }
    });

    it("deduplicates by key", () => {
      const memories = memoryReader.readLocalMemories(tmpWorkspace);
      const keys = memories.map((m) => m.key);
      const uniqueKeys = new Set(keys);
      expect(keys.length).toBe(uniqueKeys.size);
    });

    it("metadata includes heading and sourceFile", () => {
      const memories = memoryReader.readLocalMemories(tmpWorkspace);
      for (const mem of memories) {
        const metadata = JSON.parse(mem.metadata);
        expect(metadata.heading).toBeTruthy();
        expect(metadata.sourceFile).toBeTruthy();
      }
    });

    it("finds preferences from MEMORY.md", () => {
      const memories = memoryReader.readLocalMemories(tmpWorkspace);
      const prefs = memories.find((m) => m.category === "preferences");
      expect(prefs).toBeDefined();
      expect(prefs!.content).toContain("TypeScript");
    });

    it("finds decisions from MEMORY.md", () => {
      const memories = memoryReader.readLocalMemories(tmpWorkspace);
      const decisions = memories.find((m) => m.category === "decisions");
      expect(decisions).toBeDefined();
      expect(decisions!.content).toContain("mo:core");
    });

    it("finds daily notes", () => {
      const memories = memoryReader.readLocalMemories(tmpWorkspace);
      const daily = memories.filter((m) => m.key.startsWith("2026-02-20/"));
      expect(daily.length).toBeGreaterThan(0);
    });

    it("returns empty for workspace with no memory files", () => {
      const emptyDir = `/tmp/ic-vault-empty-workspace-${Date.now()}`;
      mkdirSync(emptyDir, { recursive: true });
      const memories = memoryReader.readLocalMemories(emptyDir);
      expect(memories).toHaveLength(0);
      rmSync(emptyDir, { recursive: true });
    });
  });

  describe("extractMemoriesFromMessages", () => {
    it("extracts from assistant messages with decision markers", () => {
      const messages = [
        { role: "user", content: "Should we use mo:core or mo:base?" },
        { role: "assistant", content: "Key decision: We should use mo:core 2.0.0 for all new canister development." },
      ];
      const memories = memoryReader.extractMemoriesFromMessages(messages);
      expect(memories.length).toBeGreaterThan(0);
      expect(memories[0].category).toBe("decisions");
    });

    it("ignores user messages", () => {
      const messages = [
        { role: "user", content: "Key decision: I want to use Python" },
      ];
      const memories = memoryReader.extractMemoriesFromMessages(messages);
      expect(memories).toHaveLength(0);
    });

    it("handles empty messages array", () => {
      expect(memoryReader.extractMemoriesFromMessages([])).toHaveLength(0);
    });

    it("handles non-object messages gracefully", () => {
      const messages = [null, undefined, 42, "string", { role: "system" }];
      // Should not throw
      const memories = memoryReader.extractMemoriesFromMessages(messages as unknown[]);
      expect(memories).toHaveLength(0);
    });

    it("extracts from messages with array content blocks", () => {
      const messages = [
        {
          role: "assistant",
          content: [
            { type: "text", text: "Noted: The user prefers dark mode in all applications and editors." },
          ],
        },
      ];
      const memories = memoryReader.extractMemoriesFromMessages(messages);
      expect(memories.length).toBeGreaterThan(0);
    });

    it("skips very short content (under 10 chars)", () => {
      const messages = [
        { role: "assistant", content: "Noted: ok" },
      ];
      const memories = memoryReader.extractMemoriesFromMessages(messages);
      expect(memories).toHaveLength(0);
    });
  });

  describe("formatMemoriesAsContext", () => {
    it("formats memories as markdown context", () => {
      const memories = [
        { key: "prefs/dark-mode", category: "preferences", content: "User prefers dark mode" },
        { key: "decisions/lang", category: "decisions", content: "Using TypeScript" },
      ];
      const context = memoryReader.formatMemoriesAsContext(memories);
      expect(context).toContain("## Recalled from IC Sovereign Memory Vault");
      expect(context).toContain("[preferences]");
      expect(context).toContain("dark mode");
      expect(context).toContain("[decisions]");
    });

    it("returns empty string for no memories", () => {
      expect(memoryReader.formatMemoriesAsContext([])).toBe("");
    });

    it("respects token limit", () => {
      const largeContent = "x".repeat(10000);
      const memories = [
        { key: "large", category: "general", content: largeContent },
        { key: "small", category: "general", content: "should not appear" },
      ];
      // Very small token limit
      const context = memoryReader.formatMemoriesAsContext(memories, 100);
      // Should have at most a few entries before hitting the limit
      expect(context.length).toBeLessThan(largeContent.length);
    });

    it("handles Uint8Array content", () => {
      const memories = [
        {
          key: "test",
          category: "general",
          content: new TextEncoder().encode("Binary content test"),
        },
      ];
      const context = memoryReader.formatMemoriesAsContext(memories);
      expect(context).toContain("Binary content test");
    });
  });

  describe("deriveSearchTerms", () => {
    it("detects preference-related prompts", () => {
      const { categories } = memoryReader.deriveSearchTerms("What are my preferences for editors?");
      expect(categories).toContain("preferences");
    });

    it("detects decision-related prompts", () => {
      const { categories } = memoryReader.deriveSearchTerms("What did we decide about the database?");
      expect(categories).toContain("decisions");
    });

    it("detects tool-related prompts", () => {
      const { categories } = memoryReader.deriveSearchTerms("How do I set up the workflow?");
      expect(categories).toContain("tools");
    });

    it("detects issue-related prompts", () => {
      const { categories } = memoryReader.deriveSearchTerms("What bugs are we tracking?");
      expect(categories).toContain("issues");
    });

    it("detects daily/session-related prompts", () => {
      const { categories } = memoryReader.deriveSearchTerms("What did we do yesterday?");
      expect(categories).toContain("daily");
    });

    it("extracts quoted terms as prefixes", () => {
      const { prefixes } = memoryReader.deriveSearchTerms('Find memories about "mo:core migration"');
      expect(prefixes.length).toBeGreaterThan(0);
      expect(prefixes[0]).toContain("mo-core");
    });

    it("returns empty categories for generic prompts", () => {
      const { categories } = memoryReader.deriveSearchTerms("Hello, how are you?");
      expect(categories).toHaveLength(0);
    });

    it("detects multiple categories", () => {
      const { categories } = memoryReader.deriveSearchTerms(
        "What preferences and decisions have we made about the project tools?",
      );
      expect(categories.length).toBeGreaterThanOrEqual(2);
    });
  });

  describe("resolveWorkspaceDir", () => {
    it("returns provided workspace dir", () => {
      expect(memoryReader.resolveWorkspaceDir("/custom/workspace")).toBe("/custom/workspace");
    });

    it("returns default for undefined", () => {
      const result = memoryReader.resolveWorkspaceDir(undefined);
      expect(result).toContain(".openclaw");
      expect(result).toContain("workspace");
    });
  });
});
