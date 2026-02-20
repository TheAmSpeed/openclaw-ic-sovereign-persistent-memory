---
name: ic-storage
description: Sovereign, persistent AI memory storage on the Internet Computer (IC Sovereign Persistent Memory).
metadata:
  {
    "openclaw":
      {
        "emoji": "🏛️",
        "skillKey": "ic-storage",
        "requires": { "config": ["plugins.entries.openclaw-ic-sovereign-persistent-memory.enabled"] },
      },
  }
---

# IC Sovereign Persistent Memory

IC Sovereign Persistent Memory gives you sovereign, persistent AI memory storage on the Internet Computer. Your memories are stored in a personal canister (smart contract) that only you control. Data persists across devices, sessions, and app reinstalls.

## Key Concepts

- **Vault**: Your personal canister on the Internet Computer. Only your Ed25519 identity can read or write it.
- **Identity**: An Ed25519 key pair stored in your OS keychain (macOS Keychain / Linux Secret Service). Fallback: AES-256-GCM encrypted file with passphrase. No browser or seed phrases required.
- **Sync**: Memories sync to your vault via differential comparison (only changed entries are uploaded). If the IC is unreachable, nothing breaks -- it syncs on reconnect.
- **Audit Log**: Every operation is recorded in an immutable, consensus-verified log. No one (not even you) can modify past entries.
- **Factory**: A shared canister that creates personal vaults. Each vault is a separate canister with its own cycle balance.

## Setup

To create your identity and vault, run:

```bash
openclaw ic-memory setup
```

This does three things (no browser needed):
1. Generates an Ed25519 key pair and stores it in your OS keychain
2. Checks if you already have a vault on the IC
3. If not, creates a new personal vault canister via the Factory

After setup, configure your vault ID:

```bash
openclaw config set plugins.entries.openclaw-ic-sovereign-persistent-memory.config.canisterId "<your-vault-id>"
```

The setup command prints the exact command to run.

## Available Commands

### CLI Commands

```bash
openclaw ic-memory setup            # Generate identity + create vault
openclaw ic-memory status           # Show vault stats (memories, sessions, cycles)
openclaw ic-memory sync             # Sync local memory files to IC vault
openclaw ic-memory restore          # Restore all data from IC to local
openclaw ic-memory audit            # Show immutable audit log
openclaw ic-memory export-identity  # Export identity key for cross-device use
openclaw ic-memory import-identity  # Import identity from another device (reads from stdin)
openclaw ic-memory revoke           # Revoke Factory controller (full sovereignty)
openclaw ic-memory delete-identity  # Delete identity from this device (destructive)
```

### Agent Tools

The following tools are available to the AI agent:

- **vault_sync** -- Sync local memories to IC vault (differential, only uploads changes)
- **vault_recall** -- Recall a specific memory by key, or search by category/prefix
- **vault_restore** -- Full restore from IC vault (use on new device or after data loss)
- **vault_status** -- Show vault stats: memory count, session count, cycle balance, categories
- **vault_audit** -- Show the immutable audit log with consensus-verified timestamps

Note: Deletion is available via the canister API for advanced users but is intentionally not exposed as an agent tool to encourage an append-friendly workflow.

## How It Works

1. **Smart Recall (before every conversation)**: When you start talking, the plugin analyzes your prompt, searches your IC vault for relevant memories (by category and keyword), and injects them as context before the agent starts thinking. The agent now remembers your preferences, decisions, and project context across sessions and devices.

2. **Auto-Capture (after every conversation)**: When a conversation ends, the plugin reads your local memory files (`MEMORY.md`, `memory/*.md`) and extracts memory-worthy content from conversation messages. Everything is synced to your IC vault automatically.

3. **Compaction Protection (before context compaction)**: Before OpenClaw compacts your context window (which can destroy unwritten memories), the plugin saves all current memories to your IC vault. This prevents the most common cause of "OpenClaw forgot something."

4. Each sync uses differential comparison via a SyncManifest -- only changed entries are uploaded.
5. The vault canister uses Enhanced Orthogonal Persistence (EOP) for automatic data persistence across canister upgrades.
6. Every write goes through IC consensus (replicated across multiple nodes), making the audit log tamper-proof.

## Cross-Device Setup

To use your vault on a new device:

**On your current device:**

```bash
openclaw ic-memory export-identity
```

This prints your secret key (base64). Store it securely (password manager, encrypted note).

**On the new device:**

```bash
openclaw ic-memory import-identity
```

Paste the key when prompted (input is hidden). The identity is saved to the OS keychain on the new device. Then run `openclaw ic-memory setup` to detect your existing vault, or restore all data:

```bash
openclaw ic-memory restore
```

**Security note:** The import command reads the key from stdin, never as a CLI argument (avoids shell history leaks).

## Configuration

Config lives under `plugins.entries.openclaw-ic-sovereign-persistent-memory.config`:

| Key                 | Default          | Description                               |
| ------------------- | ---------------- | ----------------------------------------- |
| `canisterId`        | (set by setup)   | Your vault canister ID                    |
| `factoryCanisterId` | (pre-configured) | Factory canister for vault creation       |
| `network`           | `ic`             | `ic` for mainnet, `local` for development |
| `autoSync`          | `true`           | Auto-sync memories in background          |
| `syncOnSessionEnd`  | `true`           | Sync session data when session ends       |
| `syncOnAgentEnd`    | `true`           | Sync new memories when conversation ends  |

## Security

- **Identity storage**: Ed25519 private key stored in OS keychain (macOS Keychain / Linux Secret Service). Fallback: AES-256-GCM encrypted file with PBKDF2-derived key (600,000 iterations).
- **Caller verification**: Every call to your vault is cryptographically signed. The IC verifies `msg.caller` matches the vault owner before any code runs.
- **Principal isolation**: Knowing someone's principal ID is useless without their Ed25519 private key.
- **No plaintext keys on disk**: Keys are in the OS keychain (encrypted by login password). The encrypted file fallback never stores plaintext.
- **Import safety**: `import-identity` reads from stdin (hidden input), never from CLI arguments (avoids shell history leaks).
- **Secure delete**: When an identity is removed, the key file is overwritten with random bytes, then zeros, before unlinking.
- **Immutable audit**: Every store, delete, and sync is logged with consensus-verified timestamps. The log is append-only.

## Cost

- Vault creation: ~$1.56 (one-time, 1.2T cycles from pre-funded pool)
- Storage: ~$0.54/year for typical usage (100 MB)
- All query calls (reads): free
- Update calls (writes): minimal cycle cost per operation
