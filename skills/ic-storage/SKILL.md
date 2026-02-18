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

- **Vault**: Your personal canister on the Internet Computer. Only you can read/write it.
- **Sync**: Local memories auto-sync to your vault in the background. If the IC is unreachable, nothing breaks -- it syncs on reconnect.
- **Audit Log**: Every operation is recorded in an immutable, consensus-verified log. No one (not even you) can modify past entries.
- **Internet Identity**: Authentication via Google, Apple, Microsoft, or passkey. No seed phrases or wallet setup required.

## Setup

To create your vault, run:

```bash
openclaw ic-memory setup
```

This opens Internet Identity 2.0 in your browser. After authenticating, a personal vault canister is created for you on the IC.

## Available Commands

### CLI Commands

```bash
openclaw ic-memory setup     # Authenticate + create vault
openclaw ic-memory status    # Show vault stats (memories, sessions, cycles)
openclaw ic-memory sync      # Manual sync to IC
openclaw ic-memory restore   # Restore all data from IC to local
openclaw ic-memory audit     # Show immutable audit log
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

1. Your local AI memories (SQLite/LanceDB) remain the primary store for instant reads/writes.
2. The IC vault syncs in the background as a persistent backup.
3. Each sync uses differential comparison -- only changed entries are uploaded.
4. The vault canister uses Enhanced Orthogonal Persistence (EOP) for automatic data persistence across canister upgrades.
5. Every write goes through IC consensus (replicated across multiple nodes), making the audit log tamper-proof.

## Cross-Device Restore

To restore memories on a new device:

```bash
openclaw ic-memory restore
```

This authenticates with Internet Identity, finds your vault, and downloads all memories and sessions.

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

- Every call to your vault is cryptographically signed.
- The IC verifies `msg.caller` before your canister code runs.
- Knowing someone's principal ID is useless without their private key.
- Private keys never leave your device (WebAuthn/passkey hardware-backed).
- The vault is controlled by your Internet Identity principal -- no one else can access it.

## Cost

- Vault creation: ~$1.56 (one-time, 1.2T cycles from pre-funded pool)
- Storage: ~$0.54/year for typical usage (100 MB)
- All query calls (reads): free
- Update calls (writes): minimal cycle cost per operation
