/// Client-side encryption/decryption for IC Sovereign Persistent Memory.
/// Uses vetKeys (Verifiably Encrypted Threshold Keys) for key derivation
/// and AES-256-GCM via WebCrypto for content encryption.
///
/// Security model:
/// - All encryption/decryption happens client-side (never in the canister)
/// - The canister only facilitates vetKey derivation via the IC management canister
/// - Node providers see only ciphertext in canister memory
/// - The vetKey is derived once per session and cached in process memory (never disk)
/// - A fresh TransportSecretKey is used for each vetKey request

import {
  TransportSecretKey,
  EncryptedVetKey,
  DerivedPublicKey,
  VetKey,
} from "@dfinity/vetkeys";

/// Domain separator for AES-256-GCM key derivation from the vetKey.
/// Must be unique to our application and usage context.
const DOMAIN_SEPARATOR = "openclaw-ic-sovereign-memory-v1";

/// Ciphertext header for format identification and versioning.
/// Format: [8-byte header "IC GCMv2"] [12-byte nonce] [AES-GCM ciphertext + 16-byte tag]
const CIPHERTEXT_HEADER = new TextEncoder().encode("IC GCMv2");
const HEADER_SIZE = 8;
const NONCE_SIZE = 12;
const TAG_SIZE = 16; // AES-GCM authentication tag

/// Interface for the canister calls needed by VaultCrypto.
/// Decoupled from IcClient to allow testing with mocks.
export interface VetKeyProvider {
  getEncryptedVetkey(transportPublicKey: Uint8Array): Promise<Uint8Array>;
  getVetkeyVerificationKey(): Promise<Uint8Array>;
}

/**
 * Client-side encryption engine for vault memory content.
 *
 * Lifecycle:
 * 1. Call `ensureReady()` once per session — derives the vetKey (~1-2s IC update call)
 * 2. Use `encrypt()` / `decrypt()` freely — pure local crypto, instant
 * 3. Key is cached in memory for the process lifetime
 *
 * The vetKey is a BLS12-381 signature that serves as cryptographic key material.
 * We derive an AES-256-GCM key from it using HKDF (via the @dfinity/vetkeys SDK).
 */
export class VaultCrypto {
  private provider: VetKeyProvider;
  private ownerPrincipalBytes: Uint8Array;
  private cachedAesKey: CryptoKey | null = null;
  private cachedVetKeyBytes: Uint8Array | null = null;
  private derivationPromise: Promise<void> | null = null;

  /**
   * @param provider - Interface to the canister's vetKey endpoints
   * @param ownerPrincipalBytes - The vault owner's principal as raw bytes
   *   (from Principal.toUint8Array()). Used as the `input` parameter in
   *   vetkd_derive_key to bind the derived key to this specific owner.
   */
  constructor(provider: VetKeyProvider, ownerPrincipalBytes: Uint8Array) {
    this.provider = provider;
    this.ownerPrincipalBytes = ownerPrincipalBytes;
  }

  /// Whether the crypto engine is ready (vetKey derived and AES key cached).
  get isReady(): boolean {
    return this.cachedAesKey !== null;
  }

  /**
   * Derive the vetKey from the canister and cache the AES-256-GCM key.
   * This makes one IC update call (~1-2 seconds). Subsequent calls are no-ops.
   *
   * Flow:
   * 1. Generate a fresh ephemeral TransportSecretKey
   * 2. Send transport public key to canister's getEncryptedVetkey
   * 3. Canister proxies to IC management canister's vetkd_derive_key
   * 4. IC returns vetKey encrypted under our transport key
   * 5. We decrypt with transport secret key + verify against derived public key
   * 6. Derive AES-256-GCM key from vetKey using HKDF with domain separator
   * 7. Cache AES key in memory
   */
  async ensureReady(): Promise<void> {
    if (this.cachedAesKey) return;
    if (this.derivationPromise) {
      // Another call is already deriving — await the same promise
      // instead of busy-wait polling. If it fails, fall through and retry.
      try {
        await this.derivationPromise;
      } catch {
        // First derivation failed — fall through to retry below
      }
      if (this.cachedAesKey) return;
    }

    this.derivationPromise = this._deriveKey();
    try {
      await this.derivationPromise;
    } finally {
      this.derivationPromise = null;
    }
  }

  private async _deriveKey(): Promise<void> {
    try {
      // 1. Generate fresh ephemeral transport key pair
      const tsk = TransportSecretKey.random();
      const transportPublicKey = tsk.publicKeyBytes();

      // 2-4. Request encrypted vetKey from canister (IC update call)
      const [encryptedKeyBytes, verificationKeyBytes] = await Promise.all([
        this.provider.getEncryptedVetkey(transportPublicKey),
        this.provider.getVetkeyVerificationKey(),
      ]);

      // 5. Decrypt and verify the vetKey
      const encryptedKey = EncryptedVetKey.deserialize(encryptedKeyBytes);
      const dpk = DerivedPublicKey.deserialize(verificationKeyBytes);

      // The `input` must match what the canister passed to vetkd_derive_key.
      // The canister uses Principal.toBlob(caller), so we use the owner's principal bytes.
      const vetKey = encryptedKey.decryptAndVerify(
        tsk,
        dpk,
        this.ownerPrincipalBytes,
      );

      this.cachedVetKeyBytes = vetKey.serialize();

      // 6. Derive AES-256-GCM key from vetKey using HKDF
      const rawKeyBytes = vetKey.deriveSymmetricKey(DOMAIN_SEPARATOR, 32);

      // 7. Import as non-exportable WebCrypto key
      this.cachedAesKey = await crypto.subtle.importKey(
        "raw",
        rawKeyBytes,
        { name: "AES-GCM", length: 256 },
        false, // not extractable
        ["encrypt", "decrypt"],
      );

      // Zero out raw key bytes now that they've been imported into WebCrypto.
      // Defense-in-depth: prevents key material from lingering on the JS heap.
      rawKeyBytes.fill(0);
    } catch (e) {
      // Re-throw so the caller sees the error; _deriveKey's promise rejects
      throw e;
    }
  }

  /**
   * Encrypt plaintext content using AES-256-GCM.
   *
   * Output format: [8-byte header "IC GCMv2"] [12-byte random nonce] [ciphertext + 16-byte tag]
   *
   * @param plaintext - Content to encrypt (string or bytes)
   * @returns Encrypted ciphertext blob
   * @throws If ensureReady() hasn't been called
   */
  async encrypt(plaintext: Uint8Array | string): Promise<Uint8Array> {
    if (!this.cachedAesKey) {
      throw new Error("VaultCrypto not ready. Call ensureReady() first.");
    }

    const plaintextBytes =
      typeof plaintext === "string" ? new TextEncoder().encode(plaintext) : plaintext;

    // Generate random 12-byte nonce (IV)
    const nonce = crypto.getRandomValues(new Uint8Array(NONCE_SIZE));

    // Encrypt with AES-256-GCM (includes 16-byte auth tag automatically)
    const ciphertextWithTag = new Uint8Array(
      await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: nonce, tagLength: TAG_SIZE * 8 },
        this.cachedAesKey,
        plaintextBytes,
      ),
    );

    // Assemble: header + nonce + ciphertext+tag
    const result = new Uint8Array(HEADER_SIZE + NONCE_SIZE + ciphertextWithTag.byteLength);
    result.set(CIPHERTEXT_HEADER, 0);
    result.set(nonce, HEADER_SIZE);
    result.set(ciphertextWithTag, HEADER_SIZE + NONCE_SIZE);

    return result;
  }

  /**
   * Decrypt ciphertext content using AES-256-GCM.
   *
   * @param ciphertext - Encrypted content (with header + nonce + ciphertext+tag)
   * @returns Decrypted plaintext bytes
   * @throws If format is invalid, key is wrong, or data is tampered
   */
  async decrypt(ciphertext: Uint8Array): Promise<Uint8Array> {
    if (!this.cachedAesKey) {
      throw new Error("VaultCrypto not ready. Call ensureReady() first.");
    }

    // Validate minimum size: header(8) + nonce(12) + tag(16) = 36 bytes minimum
    if (ciphertext.byteLength < HEADER_SIZE + NONCE_SIZE + TAG_SIZE) {
      throw new Error("Ciphertext too short to contain header, nonce, and authentication tag");
    }

    // Verify header
    const header = ciphertext.subarray(0, HEADER_SIZE);
    for (let i = 0; i < HEADER_SIZE; i++) {
      if (header[i] !== CIPHERTEXT_HEADER[i]) {
        throw new Error("Invalid ciphertext header — expected 'IC GCMv2'");
      }
    }

    // Extract nonce and ciphertext+tag
    const nonce = ciphertext.subarray(HEADER_SIZE, HEADER_SIZE + NONCE_SIZE);
    const ciphertextWithTag = ciphertext.subarray(HEADER_SIZE + NONCE_SIZE);

    // Decrypt and verify authentication tag
    try {
      const plaintext = new Uint8Array(
        await crypto.subtle.decrypt(
          { name: "AES-GCM", iv: nonce, tagLength: TAG_SIZE * 8 },
          this.cachedAesKey,
          ciphertextWithTag,
        ),
      );
      return plaintext;
    } catch {
      throw new Error("Decryption failed: authentication tag verification failed or wrong key");
    }
  }

  /**
   * Check if a blob looks like encrypted content (has the IC GCMv2 header).
   * This is used for dual-mode storage during migration.
   */
  static isEncryptedContent(content: Uint8Array): boolean {
    if (content.byteLength < HEADER_SIZE) return false;
    for (let i = 0; i < HEADER_SIZE; i++) {
      if (content[i] !== CIPHERTEXT_HEADER[i]) return false;
    }
    return true;
  }

  /// Clear cached key material. Call on process exit for defense-in-depth.
  destroy(): void {
    this.cachedAesKey = null;
    if (this.cachedVetKeyBytes) {
      // Zero out the cached key bytes
      this.cachedVetKeyBytes.fill(0);
      this.cachedVetKeyBytes = null;
    }
  }
}
