/**
 * End-to-end encryption test against IC mainnet.
 * Proves vetKeys work end-to-end: derive key -> encrypt -> store -> recall -> decrypt -> verify.
 *
 * This test uses a real vault canister on IC mainnet and real vetKey derivation
 * from the IC management canister. It verifies that:
 * 1. VaultCrypto can derive a vetKey from the vault canister
 * 2. Content encrypted client-side stores correctly with isEncrypted=true
 * 3. Recalled encrypted content decrypts to the original plaintext
 * 4. Unencrypted (plaintext) entries still work alongside encrypted ones
 * 5. VaultCrypto.isEncryptedContent() correctly identifies encrypted blobs
 * 6. restoreFromVault correctly decrypts encrypted entries
 *
 * Usage: npx vitest run e2e-encryption-test.ts
 *
 * Requires: IC identity already set up via `openclaw ic-memory setup`
 *
 * Note: This test uses vitest instead of a standalone tsx script because
 * @dfinity/vetkeys is an ESM-only package that tsx cannot resolve correctly
 * (CJS interop issue). Vitest uses Vite's module resolution which handles
 * ESM-only packages properly.
 */

import { describe, it, expect } from "vitest";
import { IcClient } from "./ic-client.js";
import { VaultCrypto } from "./vault-crypto.js";
import { encodeContent, decodeContent, restoreFromVault } from "./sync.js";
import { identityExists, generateAndSaveIdentity, loadIdentityAsync } from "./identity.js";

const FACTORY_CANISTER_ID = "v7tpn-laaaa-aaaac-bcmdq-cai";

// These are real IC mainnet tests — they take 30-60 seconds due to update calls.
// Set a generous timeout per test.
const IC_TIMEOUT = 60_000;

describe("vetKeys E2E Encryption (IC Mainnet)", () => {
  // Shared state across test steps (sequential execution required)
  let client: IcClient;
  let vaultCrypto: InstanceType<typeof VaultCrypto>;
  let testKey: string;
  let plaintextKey: string;
  const testContent = "This is a secret memory encrypted with vetKeys on IC mainnet!";
  const plaintextContent = "This is an unencrypted memory stored alongside encrypted ones.";

  it("connects to IC mainnet and finds vault", async () => {
    // Ensure identity exists
    if (!identityExists()) {
      await generateAndSaveIdentity();
    }

    const identity = await loadIdentityAsync();

    client = new IcClient({
      factoryCanisterId: FACTORY_CANISTER_ID,
      canisterId: undefined as unknown as string,
      network: "ic",
      autoSync: true,
      syncOnSessionEnd: true,
      syncOnAgentEnd: true,
    });

    await client.initAgentWithIdentity(identity);
    const principal = client.getPrincipal();
    expect(principal).not.toBeNull();

    // Ensure vault exists
    const createResult = await client.createVault();
    if ("err" in createResult) {
      expect(createResult.err).toBe("You already have a vault");
      const existing = await client.getVault();
      expect(existing).not.toBeNull();
      (client as any).config.canisterId = existing!.toText();
    } else {
      (client as any).config.canisterId = createResult.ok.toText();
    }

    // Verify vault supports encryption
    const version = await client.getVaultVersion();
    expect(version.supportsEncryption).toBe(true);
  }, IC_TIMEOUT);

  it("derives vetKey from IC management canister", async () => {
    const principal = client.getPrincipal();

    vaultCrypto = new VaultCrypto(
      {
        getEncryptedVetkey: (tpk: Uint8Array) => client.getEncryptedVetkey(tpk),
        getVetkeyVerificationKey: () => client.getVetkeyVerificationKey(),
      },
      principal!.toUint8Array(),
    );

    await vaultCrypto.ensureReady();
    expect(vaultCrypto.isReady).toBe(true);
  }, IC_TIMEOUT);

  it("encrypts and stores a memory with isEncrypted=true", async () => {
    testKey = `e2e-encrypted-${Date.now()}`;
    const testCategory = "e2e-encryption-test";
    const testMetadata = JSON.stringify({ encrypted: true, timestamp: Date.now() });

    const plainBytes = encodeContent(testContent);
    const encryptedBytes = await vaultCrypto.encrypt(plainBytes);

    // Verify IC GCMv2 header
    expect(VaultCrypto.isEncryptedContent(encryptedBytes)).toBe(true);
    // Encrypted should be larger than plaintext (header + nonce + tag overhead)
    expect(encryptedBytes.byteLength).toBeGreaterThan(plainBytes.byteLength);

    const storeResult = await client.store(testKey, testCategory, encryptedBytes, testMetadata, true);
    expect(storeResult).toHaveProperty("ok");
  }, IC_TIMEOUT);

  it("recalls memory and verifies isEncrypted flag and opaque ciphertext", async () => {
    // Allow query replica propagation
    await new Promise((r) => setTimeout(r, 2000));

    const recalled = await client.recall(testKey);
    expect(recalled).not.toBeNull();
    expect(recalled!.isEncrypted).toBe(true);

    // Raw ciphertext should NOT decode to plaintext
    const rawText = decodeContent(recalled!.content);
    expect(rawText).not.toBe(testContent);
    expect(rawText).not.toContain("secret");
    expect(rawText).not.toContain("vetKeys");
  }, IC_TIMEOUT);

  it("decrypts recalled content and verifies it matches original", async () => {
    const recalled = await client.recall(testKey);
    expect(recalled).not.toBeNull();

    const decryptedBytes = await vaultCrypto.decrypt(recalled!.content);
    const decryptedText = decodeContent(decryptedBytes);
    expect(decryptedText).toBe(testContent);
  }, IC_TIMEOUT);

  it("stores plaintext memory alongside encrypted (dual-mode)", async () => {
    plaintextKey = `e2e-plaintext-${Date.now()}`;
    const ptBytes = encodeContent(plaintextContent);

    const ptResult = await client.store(plaintextKey, "e2e-encryption-test", ptBytes, "{}", false);
    expect(ptResult).toHaveProperty("ok");

    // Allow query replica propagation
    await new Promise((r) => setTimeout(r, 2000));

    const recalledPt = await client.recall(plaintextKey);
    expect(recalledPt).not.toBeNull();
    expect(recalledPt!.isEncrypted).toBe(false);
    expect(decodeContent(recalledPt!.content)).toBe(plaintextContent);
  }, IC_TIMEOUT);

  it("restoreFromVault decrypts encrypted entries and preserves plaintext", async () => {
    const restored = await restoreFromVault(client, undefined, vaultCrypto);

    // Find our encrypted test memory
    const restoredEncrypted = restored.memories.find((m) => m.key === testKey);
    expect(restoredEncrypted).toBeDefined();
    expect(restoredEncrypted!.content).toBe(testContent);

    // Find our plaintext memory
    const restoredPlaintext = restored.memories.find((m) => m.key === plaintextKey);
    expect(restoredPlaintext).toBeDefined();
    expect(restoredPlaintext!.content).toBe(plaintextContent);
  }, IC_TIMEOUT);

  it("ensureReady() is idempotent (cached, instant)", async () => {
    const start = Date.now();
    await vaultCrypto.ensureReady();
    const elapsed = Date.now() - start;
    expect(elapsed).toBeLessThan(100);
    expect(vaultCrypto.isReady).toBe(true);
  });

  it("cleans up test data", async () => {
    const del1 = await client.delete(testKey);
    expect(del1).toHaveProperty("ok");
    const del2 = await client.delete(plaintextKey);
    expect(del2).toHaveProperty("ok");
  }, IC_TIMEOUT);

  it("destroy() clears key material", () => {
    vaultCrypto.destroy();
    expect(vaultCrypto.isReady).toBe(false);
  });
});
