/// IC Identity management for CLI environments.
/// Stores Ed25519KeyIdentity in the OS keychain (macOS Keychain, Linux Secret Service).
/// Falls back to AES-256-GCM encrypted file when keychain is unavailable.
///
/// Security properties:
/// - Primary: OS keychain -- encrypted by login password, optional biometric (Touch ID)
/// - Fallback: AES-256-GCM encrypted file with user passphrase (PBKDF2-derived key)
/// - No plaintext key file on disk during normal operation
/// - Secret key never passed as CLI argument (stdin only for import)
/// - Secure delete: overwrite before unlink

import { Ed25519KeyIdentity } from "@dfinity/identity";
import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import { execSync } from "node:child_process";
import * as readline from "node:readline";

// -- Constants --

const KEYCHAIN_SERVICE = "ic-sovereign-memory";
const KEYCHAIN_ACCOUNT = "default";

/// Directory for the fallback encrypted file.
const IDENTITY_DIR = path.join(os.homedir(), ".openclaw", "extensions", "openclaw-ic-sovereign-persistent-memory");

/// Encrypted identity file name (used when keychain is unavailable).
const ENCRYPTED_IDENTITY_FILE = "ic-identity.enc";

// AES-256-GCM encryption parameters
const PBKDF2_ITERATIONS = 600_000; // OWASP recommendation for PBKDF2-SHA256
const PBKDF2_KEYLEN = 32; // 256 bits
const PBKDF2_DIGEST = "sha256";
const AES_ALGORITHM = "aes-256-gcm";
const SALT_LENGTH = 32;
const IV_LENGTH = 16;
const AUTH_TAG_LENGTH = 16;

// -- Storage backend detection --

type StorageBackend = "keychain" | "encrypted-file";

/// Detect the best available storage backend.
function detectBackend(): StorageBackend {
  if (process.platform === "darwin") {
    try {
      execSync("which security", { stdio: "pipe" });
      return "keychain";
    } catch {
      // security CLI not available
    }
  }

  if (process.platform === "linux") {
    try {
      execSync("which secret-tool", { stdio: "pipe" });
      return "keychain";
    } catch {
      // secret-tool not available
    }
  }

  // Windows or no keychain available -- fall back to encrypted file
  return "encrypted-file";
}

// -- OS Keychain operations --

/// Store a secret in the OS keychain.
function keychainStore(secret: string): void {
  if (process.platform === "darwin") {
    // macOS: use `security` CLI
    // -U flag: update if exists, create if not
    // -T "" : allow any application to access (no prompt on read)
    execSync(
      `security add-generic-password -a "${KEYCHAIN_ACCOUNT}" -s "${KEYCHAIN_SERVICE}" -w "${escapeShellArg(secret)}" -U`,
      { stdio: "pipe" },
    );
    return;
  }

  if (process.platform === "linux") {
    // Linux: use `secret-tool` (GNOME Keyring / KDE Wallet via libsecret)
    // secret-tool reads the secret from stdin
    execSync(
      `printf '%s' "${escapeShellArg(secret)}" | secret-tool store --label="IC Sovereign Memory" service "${KEYCHAIN_SERVICE}" account "${KEYCHAIN_ACCOUNT}"`,
      { stdio: "pipe", shell: "/bin/sh" },
    );
    return;
  }

  throw new Error(`Keychain not supported on platform: ${process.platform}`);
}

/// Retrieve a secret from the OS keychain. Returns null if not found.
function keychainLoad(): string | null {
  try {
    if (process.platform === "darwin") {
      const result = execSync(
        `security find-generic-password -a "${KEYCHAIN_ACCOUNT}" -s "${KEYCHAIN_SERVICE}" -w`,
        { stdio: "pipe", encoding: "utf-8" },
      );
      return result.trim();
    }

    if (process.platform === "linux") {
      const result = execSync(
        `secret-tool lookup service "${KEYCHAIN_SERVICE}" account "${KEYCHAIN_ACCOUNT}"`,
        { stdio: "pipe", encoding: "utf-8" },
      );
      return result.trim();
    }
  } catch {
    // Not found or keychain error
    return null;
  }

  return null;
}

/// Delete a secret from the OS keychain.
function keychainDelete(): boolean {
  try {
    if (process.platform === "darwin") {
      execSync(
        `security delete-generic-password -a "${KEYCHAIN_ACCOUNT}" -s "${KEYCHAIN_SERVICE}"`,
        { stdio: "pipe" },
      );
      return true;
    }

    if (process.platform === "linux") {
      execSync(
        `secret-tool clear service "${KEYCHAIN_SERVICE}" account "${KEYCHAIN_ACCOUNT}"`,
        { stdio: "pipe" },
      );
      return true;
    }
  } catch {
    return false;
  }

  return false;
}

/// Check if a keychain entry exists.
function keychainExists(): boolean {
  return keychainLoad() !== null;
}

// -- Encrypted file operations --

/// Get the path to the encrypted identity file.
function getEncryptedFilePath(): string {
  return path.join(IDENTITY_DIR, ENCRYPTED_IDENTITY_FILE);
}

/// Encrypt a secret with AES-256-GCM using a passphrase.
function encryptWithPassphrase(secret: string, passphrase: string): Buffer {
  const salt = crypto.randomBytes(SALT_LENGTH);
  const iv = crypto.randomBytes(IV_LENGTH);
  const key = crypto.pbkdf2Sync(passphrase, salt, PBKDF2_ITERATIONS, PBKDF2_KEYLEN, PBKDF2_DIGEST);

  const cipher = crypto.createCipheriv(AES_ALGORITHM, key, iv);
  const encrypted = Buffer.concat([cipher.update(secret, "utf-8"), cipher.final()]);
  const authTag = cipher.getAuthTag();

  // Format: salt (32) + iv (16) + authTag (16) + encrypted (variable)
  return Buffer.concat([salt, iv, authTag, encrypted]);
}

/// Decrypt a secret from AES-256-GCM encrypted buffer.
function decryptWithPassphrase(data: Buffer, passphrase: string): string {
  if (data.length < SALT_LENGTH + IV_LENGTH + AUTH_TAG_LENGTH + 1) {
    throw new Error("Encrypted identity file is corrupted (too short).");
  }

  const salt = data.subarray(0, SALT_LENGTH);
  const iv = data.subarray(SALT_LENGTH, SALT_LENGTH + IV_LENGTH);
  const authTag = data.subarray(SALT_LENGTH + IV_LENGTH, SALT_LENGTH + IV_LENGTH + AUTH_TAG_LENGTH);
  const encrypted = data.subarray(SALT_LENGTH + IV_LENGTH + AUTH_TAG_LENGTH);

  const key = crypto.pbkdf2Sync(passphrase, salt, PBKDF2_ITERATIONS, PBKDF2_KEYLEN, PBKDF2_DIGEST);

  const decipher = crypto.createDecipheriv(AES_ALGORITHM, key, iv);
  decipher.setAuthTag(authTag);

  try {
    const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
    return decrypted.toString("utf-8");
  } catch {
    throw new Error(
      "Failed to decrypt identity file. Wrong passphrase, or the file is corrupted.",
    );
  }
}

/// Prompt the user for a passphrase (hidden input).
function promptPassphrase(prompt: string): Promise<string> {
  return new Promise((resolve) => {
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stderr, // Use stderr so stdout stays clean for piping
      terminal: true,
    });

    // Attempt to hide input (works on most terminals)
    if (process.stdin.isTTY) {
      process.stderr.write(prompt);
      // The readline mute trick: temporarily set output to /dev/null
      const origWrite = process.stderr.write.bind(process.stderr);
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (process.stderr as any).write = (chunk: any, ...args: any[]) => {
        // Only suppress the echoed characters, not our prompts
        if (typeof chunk === "string" && chunk !== prompt && chunk !== "\n") {
          return true;
        }
        return origWrite(chunk, ...args);
      };

      rl.question("", (answer) => {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        (process.stderr as any).write = origWrite;
        process.stderr.write("\n");
        rl.close();
        resolve(answer);
      });
    } else {
      // Non-TTY: just read a line (no hiding possible)
      rl.question(prompt, (answer) => {
        rl.close();
        resolve(answer);
      });
    }
  });
}

// -- Secure utilities --

/// Escape a string for safe use in shell commands.
/// Prevents shell injection by escaping single quotes.
function escapeShellArg(s: string): string {
  // Replace any existing backslashes, then double-quotes
  return s.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
}

/// Overwrite a file with random bytes before deleting (best-effort secure delete).
function secureDelete(filePath: string): void {
  if (!fs.existsSync(filePath)) return;

  try {
    const stat = fs.statSync(filePath);
    const randomData = crypto.randomBytes(stat.size);
    fs.writeFileSync(filePath, randomData, { mode: 0o600 });
    fs.writeFileSync(filePath, Buffer.alloc(stat.size, 0), { mode: 0o600 });
  } catch {
    // Best effort -- if overwrite fails, still try to delete
  }

  fs.unlinkSync(filePath);
}

/// Ensure a directory exists with restrictive permissions.
function ensureSecureDir(dirPath: string): void {
  fs.mkdirSync(dirPath, { recursive: true, mode: 0o700 });
  // Explicitly set permissions (recursive mkdir may not apply mode to existing dirs)
  try {
    fs.chmodSync(dirPath, 0o700);
  } catch {
    // Best effort -- some filesystems don't support chmod
  }
}

// -- Public API --

/// Get the identity storage path for display purposes.
export function getIdentityPath(): string {
  const backend = detectBackend();
  if (backend === "keychain") {
    return process.platform === "darwin"
      ? `macOS Keychain (service: ${KEYCHAIN_SERVICE})`
      : `Secret Service (service: ${KEYCHAIN_SERVICE})`;
  }
  return getEncryptedFilePath();
}

/// Check if an identity exists in any storage backend.
export function identityExists(): boolean {
  if (detectBackend() === "keychain") {
    return keychainExists();
  }
  return fs.existsSync(getEncryptedFilePath());
}

/// Load an existing identity. Tries keychain first, then encrypted file.
/// For encrypted file, prompts for passphrase if needed.
export function loadIdentity(): Ed25519KeyIdentity {
  return loadIdentitySync();
}

/// Synchronous identity load (keychain or cached passphrase).
function loadIdentitySync(): Ed25519KeyIdentity {
  const backend = detectBackend();

  if (backend === "keychain") {
    const jsonStr = keychainLoad();
    if (!jsonStr) {
      throw new Error(
        "No IC identity found in OS keychain. Run `openclaw ic-memory setup` to create one.",
      );
    }
    return parseIdentityJson(jsonStr);
  }

  // Encrypted file backend
  const filePath = getEncryptedFilePath();
  if (!fs.existsSync(filePath)) {
    throw new Error(
      "No IC identity found. Run `openclaw ic-memory setup` to create one.",
    );
  }

  // For sync load, check if we have a cached passphrase
  if (!cachedPassphrase) {
    throw new Error(
      "Identity is encrypted. Call loadIdentityAsync() for interactive passphrase prompt.",
    );
  }

  const encrypted = fs.readFileSync(filePath);
  const jsonStr = decryptWithPassphrase(encrypted, cachedPassphrase);
  return parseIdentityJson(jsonStr);
}

/// Cached passphrase for the encrypted file backend (lives in memory only).
let cachedPassphrase: string | null = null;

/// Async identity load (prompts for passphrase if needed).
export async function loadIdentityAsync(): Promise<Ed25519KeyIdentity> {
  const backend = detectBackend();

  if (backend === "keychain") {
    const jsonStr = keychainLoad();
    if (!jsonStr) {
      throw new Error(
        "No IC identity found in OS keychain. Run `openclaw ic-memory setup` to create one.",
      );
    }
    return parseIdentityJson(jsonStr);
  }

  // Encrypted file backend
  const filePath = getEncryptedFilePath();
  if (!fs.existsSync(filePath)) {
    throw new Error(
      "No IC identity found. Run `openclaw ic-memory setup` to create one.",
    );
  }

  if (!cachedPassphrase) {
    cachedPassphrase = await promptPassphrase("  Enter identity passphrase: ");
  }

  const encrypted = fs.readFileSync(filePath);
  const jsonStr = decryptWithPassphrase(encrypted, cachedPassphrase);
  return parseIdentityJson(jsonStr);
}

/// Parse an identity from its JSON string representation.
function parseIdentityJson(jsonStr: string): Ed25519KeyIdentity {
  let json: unknown;
  try {
    json = JSON.parse(jsonStr);
  } catch {
    throw new Error("Identity data is corrupted (invalid JSON).");
  }

  try {
    return Ed25519KeyIdentity.fromJSON(JSON.stringify(json));
  } catch (err) {
    throw new Error(
      `Identity data contains invalid key material: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
}

/// Generate a new Ed25519 identity and save it.
/// Uses keychain if available, encrypted file otherwise.
/// For encrypted file, prompts for a passphrase.
export async function generateAndSaveIdentity(): Promise<Ed25519KeyIdentity> {
  if (identityExists()) {
    throw new Error(
      "Identity already exists. Delete it first if you want to generate a new one " +
      "(WARNING: you will lose access to your vault).",
    );
  }

  const identity = Ed25519KeyIdentity.generate();
  const jsonStr = JSON.stringify(identity.toJSON());
  const backend = detectBackend();

  if (backend === "keychain") {
    keychainStore(jsonStr);
  } else {
    // Prompt for passphrase (with confirmation)
    const passphrase = await promptPassphrase("  Create a passphrase for your identity: ");
    if (passphrase.length < 8) {
      throw new Error("Passphrase must be at least 8 characters.");
    }
    const confirm = await promptPassphrase("  Confirm passphrase: ");
    if (passphrase !== confirm) {
      throw new Error("Passphrases do not match.");
    }

    ensureSecureDir(IDENTITY_DIR);
    const encrypted = encryptWithPassphrase(jsonStr, passphrase);
    fs.writeFileSync(getEncryptedFilePath(), encrypted, { mode: 0o600 });

    // Cache the passphrase for this session
    cachedPassphrase = passphrase;
  }

  return identity;
}

/// Import an identity from a base64-encoded secret key string.
/// This is the cross-device import flow.
export async function importIdentityFromKey(secretKeyBase64: string): Promise<Ed25519KeyIdentity> {
  if (identityExists()) {
    throw new Error(
      "Identity already exists. Delete it first if you want to import a different one " +
      "(WARNING: this device will lose its current identity).",
    );
  }

  let secretKeyBytes: Uint8Array;
  try {
    const buf = Buffer.from(secretKeyBase64, "base64");
    if (buf.length !== 32) {
      throw new Error(`Expected 32 bytes, got ${buf.length}`);
    }
    secretKeyBytes = new Uint8Array(buf);
  } catch (err) {
    throw new Error(
      `Invalid identity key. Expected a 44-character base64 string (32-byte Ed25519 secret key). ${err instanceof Error ? err.message : ""}`.trim(),
    );
  }

  const identity = Ed25519KeyIdentity.fromSecretKey(secretKeyBytes);
  const jsonStr = JSON.stringify(identity.toJSON());
  const backend = detectBackend();

  if (backend === "keychain") {
    keychainStore(jsonStr);
  } else {
    const passphrase = await promptPassphrase("  Create a passphrase for your identity: ");
    if (passphrase.length < 8) {
      throw new Error("Passphrase must be at least 8 characters.");
    }
    const confirm = await promptPassphrase("  Confirm passphrase: ");
    if (passphrase !== confirm) {
      throw new Error("Passphrases do not match.");
    }

    ensureSecureDir(IDENTITY_DIR);
    const encrypted = encryptWithPassphrase(jsonStr, passphrase);
    fs.writeFileSync(getEncryptedFilePath(), encrypted, { mode: 0o600 });
    cachedPassphrase = passphrase;
  }

  return identity;
}

/// Export the current identity as a base64-encoded secret key string.
export function exportIdentity(): { secretKeyBase64: string; principal: string } {
  const identity = loadIdentity();
  const kp = identity.getKeyPair();
  const secretKeyBase64 = Buffer.from(kp.secretKey).toString("base64");
  return {
    secretKeyBase64,
    principal: identity.getPrincipal().toText(),
  };
}

/// Delete the identity from all storage backends.
/// This is destructive and irreversible.
export function deleteIdentity(): void {
  // Delete from keychain
  keychainDelete();

  // Secure-delete encrypted file if it exists
  const encPath = getEncryptedFilePath();
  if (fs.existsSync(encPath)) {
    secureDelete(encPath);
  }

  // Clear cached passphrase
  cachedPassphrase = null;
}

/// Read a line from stdin (for import-identity).
/// The key is never passed as a CLI argument to avoid shell history leaks.
export async function readKeyFromStdin(): Promise<string> {
  // If stdin is a TTY, prompt interactively (hidden input)
  if (process.stdin.isTTY) {
    return promptPassphrase("  Paste your identity key: ");
  }

  // If stdin is piped, read the first line
  return new Promise((resolve, reject) => {
    let data = "";
    process.stdin.setEncoding("utf-8");
    process.stdin.on("data", (chunk) => {
      data += chunk;
    });
    process.stdin.on("end", () => {
      const key = data.trim();
      if (!key) {
        reject(new Error("No identity key provided on stdin."));
      } else {
        resolve(key);
      }
    });
    process.stdin.on("error", (err) => {
      reject(new Error(`Failed to read from stdin: ${err.message}`));
    });
    process.stdin.resume();
  });
}
