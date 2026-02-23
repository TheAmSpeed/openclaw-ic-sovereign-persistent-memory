# IC Sovereign Persistent Memory

**Sovereign, encrypted, persistent AI memory on the Internet Computer.**

Your OpenClaw AI memories live in a personal canister (smart contract) that only you control. In v2.0.0, all memory content is **end-to-end encrypted** using IC vetKeys -- not even the IC subnet node operators can read your data.

No cloud accounts. No third-party servers. No seed phrases. Just your identity and your encrypted data.

## Install

```bash
openclaw plugins install openclaw-ic-sovereign-persistent-memory
```

Then create your vault:

```bash
openclaw ic-memory setup
```

That's it. A new Ed25519 identity is generated and stored in your OS keychain, and a personal vault canister is deployed on the Internet Computer in about 10 seconds. No browser needed.

## Why

OpenClaw stores your AI memories locally. That's great for privacy and speed. But local-only has problems:

- **New laptop?** Memories gone.
- **Reinstall?** Memories gone.
- **Multiple machines?** Memories fragmented.
- **Disk failure?** Memories gone.

This plugin gives you persistent, sovereign, encrypted backup -- and solves the three common ways OpenClaw memory fails:

| Feature | How it works |
|---|---|
| **End-to-end encryption** | All memory content is encrypted client-side using AES-256-GCM via IC vetKeys before upload. The canister only stores ciphertext. Not even subnet node operators can read your data. |
| **Smart Memory Recall** | Before every conversation, relevant memories are automatically loaded from your IC vault, decrypted, and injected as context. The agent remembers across sessions and devices without you asking. |
| **Auto-Capture** | Memories from local files (`MEMORY.md`, `memory/*.md`) and conversations are automatically synced to your IC vault. No manual steps. |
| **Compaction-Proof** | Before context compaction can destroy memories, they're saved to your IC vault. Compaction can no longer cause memory loss. |
| **Sovereign ownership** | Your vault is a personal canister. Only your Ed25519 identity principal can read or write it. Not even the factory deployer has access. |
| **Vault upgrades** | When a new vault version is available, upgrade with a single command. Your data is preserved via Enhanced Orthogonal Persistence. |
| **Differential sync** | Only changed entries are uploaded. Sync is fast and bandwidth-efficient. |
| **Cross-device restore** | Run `openclaw ic-memory restore` on any device to pull all your memories down. |
| **Immutable audit log** | Every operation is recorded with IC consensus-verified timestamps. The log is append-only and tamper-proof. |
| **No seed phrases** | Authentication uses an Ed25519 key pair stored in your OS keychain (macOS Keychain / Linux Secret Service). No browser, no passwords to remember. |

## Architecture

```
Local Device                          Internet Computer (IC)
+------------------+                  +---------------------+
|  OpenClaw        |  encrypt +       |  Factory Canister   |
|  Memory system   |  bulkSync()     |  v7tpn-laaaa-...    |
|  (local store)   | --------------> |  Creates user vaults|
+------------------+                  |  Pushes upgrades    |
        |                             +---------------------+
        |                                     |
        v                              createVault()
+------------------+                          |
|  IC Plugin       |   recall() +             v
|  Differential    |   decrypt        +---------------------+
|  sync engine     | <-------------- |  Your Vault         |
+------------------+                  |  (Personal Canister)|
        |                             |  Encrypted storage  |
        v                             |  vetKey endpoints   |
+------------------+                  |  EOP persistence    |
|  VaultCrypto     |                  |  Audit log          |
|  AES-256-GCM via |  vetKey derive   +---------------------+
|  IC vetKeys      | <-------------- |  IC vetKD API       |
+------------------+                  +---------------------+
        |
        v
+------------------+
|  OS Keychain     |
|  Ed25519 identity|
|  (or AES-256-GCM |
|   encrypted file)|
+------------------+
```

- **IC is the persistent backup.** The vault syncs in the background. If the IC is unreachable, nothing breaks -- it syncs on reconnect.
- **End-to-end encryption.** Memories are encrypted client-side using AES-256-GCM with a symmetric key derived from IC vetKeys (BLS12-381 threshold key derivation). The canister only stores ciphertext. Decryption happens client-side. Key derivation uses `test_key_1` (dev) or `key_1` (production).
- **Identity in OS keychain.** Your Ed25519 private key is stored in macOS Keychain or Linux Secret Service. Fallback: AES-256-GCM encrypted file with passphrase.
- **Enhanced Orthogonal Persistence (EOP)** means your data survives canister upgrades automatically. No migration scripts.
- **Vault upgrades.** The Factory canister can push new WASM to user vaults. Users can trigger their own upgrade via `openclaw ic-memory upgrade-vault`, or the admin can push upgrades to all vaults.

## Commands

### CLI

```bash
openclaw ic-memory setup            # Generate identity + create vault
openclaw ic-memory status           # Show vault stats (memories, sessions, cycles)
openclaw ic-memory sync             # Sync local memory files to IC vault
openclaw ic-memory restore          # Restore all data from IC to local
openclaw ic-memory audit            # Show immutable audit log
openclaw ic-memory export-identity  # Export identity for cross-device use
openclaw ic-memory import-identity  # Import identity from another device (stdin)
openclaw ic-memory migrate-encrypt  # Encrypt existing plaintext memories in vault
openclaw ic-memory upgrade-vault    # Upgrade vault to latest version (with confirmation)
openclaw ic-memory revoke           # Revoke Factory controller (full sovereignty)
openclaw ic-memory delete-identity  # Delete identity from this device (destructive)
```

### Agent Tools

The plugin registers these tools for the AI agent to use directly:

| Tool | Description |
|---|---|
| `vault_sync` | Sync local memories to IC vault (differential) |
| `vault_recall` | Recall a specific memory by key, or search by category/prefix |
| `vault_restore` | Full restore from IC vault to local |
| `vault_status` | Show vault stats: memory count, sessions, cycle balance |
| `vault_audit` | Show immutable audit log with consensus timestamps |

## Configuration

After setup, config lives in your OpenClaw settings under `plugins.entries.openclaw-ic-sovereign-persistent-memory.config`:

| Key | Default | Description |
|---|---|---|
| `canisterId` | *(set by setup)* | Your vault canister ID |
| `factoryCanisterId` | `v7tpn-laaaa-aaaac-bcmdq-cai` | Factory canister (pre-configured) |
| `network` | `ic` | `ic` for mainnet, `local` for development |
| `autoSync` | `true` | Auto-sync memories in background |
| `syncOnSessionEnd` | `true` | Sync session data when session ends |
| `syncOnAgentEnd` | `true` | Sync new memories when conversation ends |

Environment variables are supported: `canisterId: "${MY_CANISTER_ID}"` resolves at runtime.

## Security Model

- **Identity storage**: Ed25519 private key in OS keychain (macOS Keychain / Linux Secret Service). Fallback: AES-256-GCM encrypted file with PBKDF2-derived key (600,000 iterations).
- **Caller verification**: Every call to your vault is cryptographically signed. The IC verifies `msg.caller` matches the vault owner before any code runs.
- **Principal isolation**: Knowing someone's principal ID is useless without their Ed25519 private key.
- **No plaintext keys on disk**: Keys are in the OS keychain (encrypted by login password). The encrypted file fallback never stores plaintext.
- **Import safety**: `import-identity` reads from stdin (hidden input), never from CLI arguments (avoids shell history leaks).
- **Secure delete**: When an identity is removed, the key file is overwritten with random bytes, then zeros, before unlinking.
- **End-to-end encryption**: Memory content is encrypted with AES-256-GCM using a key derived from IC vetKeys. The ciphertext format is `[8-byte header "IC GCMv2"] [12-byte nonce] [ciphertext + 16-byte tag]`. Domain separator: `"openclaw-ic-sovereign-memory-v1"`.
- **Dual-mode storage**: v2 supports both encrypted and plaintext entries. Existing plaintext memories continue to work. Use `openclaw ic-memory migrate-encrypt` to encrypt them.
- **Factory isolation**: The factory canister cannot read, modify, or delete your vault data. After creation, you can revoke the factory's controller access entirely.
- **Immutable audit**: Every store, delete, sync, and upgrade is logged with consensus-verified timestamps. The log is append-only.

## Cross-Device Setup

To use your vault on another device:

**On your current device:**

```bash
openclaw ic-memory export-identity
```

This prints your secret key (base64). Store it securely (password manager, encrypted note).

**On the new device:**

```bash
openclaw ic-memory import-identity
```

Paste the key when prompted (input is hidden, never passed as a CLI argument). Then run setup to detect your existing vault:

```bash
openclaw ic-memory setup
```

Or restore all data directly:

```bash
openclaw ic-memory restore
```

## Cost

| Item | Cost |
|---|---|
| Vault creation | ~$1.56 (one-time, 1.2T cycles from pre-funded pool) |
| Storage | ~$0.54/year for typical usage (100 MB) |
| Query calls (reads) | Free |
| Update calls (writes) | Minimal cycle cost per operation |
| vetKey derivation | ~10B cycles per session (once per session, cached) |

## Deployed Canisters

These canisters are live on IC mainnet:

| Canister | ID | Purpose |
|---|---|---|
| Factory | `v7tpn-laaaa-aaaac-bcmdq-cai` | Creates user vault canisters |
| Reference Vault | `uv4nx-jqaaa-aaaac-bcmeq-cai` | First deployed user vault |

## Development

```bash
git clone https://github.com/TheAmSpeed/openclaw-ic-sovereign-persistent-memory.git
cd openclaw-ic-sovereign-persistent-memory
npm install
npm test
```

### Local IC Development

To test against a local IC replica:

1. Install [dfx](https://internetcomputer.org/docs/current/developer-docs/getting-started/install/)
2. Start a local replica: `dfx start --background`
3. Deploy canisters: `cd canister && dfx deploy`
4. Set `network: "local"` in your plugin config

### Project Structure

```
index.ts                    Plugin entry point (tools, hooks, CLI, service)
config.ts                   Config types and parser
ic-client.ts                @dfinity/agent wrapper (canister calls, IDL definitions)
identity.ts                 Ed25519 identity management (keychain, encrypted file)
vault-crypto.ts             AES-256-GCM encryption via IC vetKeys
memory-reader.ts            Local memory file reader/parser
sync.ts                     Differential sync engine (with encryption support)
prompts.ts                  Smart adoption messaging
index.test.ts               Unit tests (149 tests)
e2e-test.ts                 E2E test against IC mainnet (13 tests)
e2e-encryption.test.ts      vetKeys encryption E2E test (10 tests)
openclaw.plugin.json        Plugin manifest
skills/ic-storage/          Bundled skill (SKILL.md)
canister/                   Motoko canister source (Factory + UserVault)
```

## Known Limitations

- Memory extraction from conversation messages uses pattern matching on known markers (e.g. "Key decision:", "Noted:", "Preference:"). Memories without these patterns are still captured from local memory files (`MEMORY.md`, `memory/*.md`).
- The `vault_delete` agent tool is intentionally omitted. Deletion is available via the canister API for advanced users, but the agent encourages an append-friendly workflow.
- Audit log entries are capped at 100,000 with FIFO eviction of the oldest 10% when full.
- Smart recall searches by category/prefix matching against the user's prompt. Very short or ambiguous prompts may not trigger targeted recall (a broad recall of recent memories is used as fallback).

## License

MIT
