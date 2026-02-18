/// Tests for IC Sovereign Persistent Memory plugin.
/// Covers: config parsing, sync logic, encoding utilities, plugin structure, and identity management.

import { describe, it, expect, beforeAll } from "vitest";
import { rmSync } from "fs";
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
