# IC Sovereign Persistent Memory

**Sovereign, persistent AI memory on the Internet Computer.**

Your OpenClaw AI memories live in a personal canister (smart contract) that only you control. They persist across devices, sessions, and reinstalls -- forever.

No cloud accounts. No third-party servers. No seed phrases. Just your identity and your data.

## Install

```bash
openclaw plugins install openclaw-ic-sovereign-persistent-memory
```

Then create your vault:

```bash
openclaw ic-memory setup
```

That's it. Internet Identity opens in your browser, you sign in (Google, Apple, Microsoft, or passkey), and a personal vault canister is deployed on the Internet Computer in about 10 seconds.

## Why

OpenClaw stores your AI memories locally. That's great for privacy and speed. But local-only has problems:

- **New laptop?** Memories gone.
- **Reinstall?** Memories gone.
- **Multiple machines?** Memories fragmented.
- **Disk failure?** Memories gone.

This plugin gives you persistent, sovereign backup:

| Feature | How it works |
|---|---|
| **Sovereign ownership** | Your vault is a personal canister. Only your Internet Identity principal can read or write it. Not even the factory deployer has access. |
| **Differential sync** | Only changed entries are uploaded. Sync is fast and bandwidth-efficient. |
| **Cross-device restore** | Run `openclaw ic-memory restore` on any device to pull all your memories down. |
| **Immutable audit log** | Every operation is recorded with IC consensus-verified timestamps. The log is append-only and tamper-proof. |
| **No seed phrases** | Authentication uses Internet Identity 2.0 (WebAuthn/passkey). Sign in with Google, Apple, Microsoft, or a hardware key. |
| **Auto-sync** | Memories sync automatically when conversations end. No manual steps required. |

## Architecture

```
Local Device                          Internet Computer (IC)
+------------------+                  +---------------------+
|  OpenClaw        |                  |  Factory Canister   |
|  (SQLite/LanceDB)|   bulkSync()    |  v7tpn-laaaa-...    |
|  Primary store   | --------------> |  Creates user vaults|
|  for reads/writes|                  +---------------------+
+------------------+                          |
        |                              createVault()
        |                                     |
        v                                     v
+------------------+                  +---------------------+
|  IC Plugin       |   recall()       |  Your Vault         |
|  Differential    | <-------------- |  (Personal Canister)|
|  sync engine     |                  |  Owner-only access  |
+------------------+                  |  EOP persistence    |
                                      |  Audit log          |
                                      +---------------------+
```

- **Local remains primary.** Reads and writes happen against SQLite/LanceDB for instant performance.
- **IC is the persistent backup.** The vault syncs in the background. If the IC is unreachable, nothing breaks -- it syncs on reconnect.
- **Enhanced Orthogonal Persistence (EOP)** means your data survives canister upgrades automatically. No migration scripts.

## Commands

### CLI

```bash
openclaw ic-memory setup     # Authenticate + create vault
openclaw ic-memory status    # Show vault stats (memories, sessions, cycles)
openclaw ic-memory sync      # Manual sync to IC
openclaw ic-memory restore   # Restore all data from IC to local
openclaw ic-memory audit     # Show immutable audit log
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

After setup, config lives in your OpenClaw settings under `plugins.entries.ic-sovereign-persistent-memory.config`:

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

- Every call to your vault is cryptographically signed by your identity.
- The IC runtime verifies `msg.caller` before your canister code executes.
- Knowing someone's principal ID is useless without their private key.
- Private keys never leave your device (WebAuthn/passkey, hardware-backed).
- The vault canister's `owner` field is set at creation and enforced on every update call.
- The factory canister cannot read, modify, or delete your vault data.

## Cost

| Item | Cost |
|---|---|
| Vault creation | ~$1.56 (one-time, 1.2T cycles from pre-funded pool) |
| Storage | ~$0.54/year for typical usage (100 MB) |
| Query calls (reads) | Free |
| Update calls (writes) | Minimal cycle cost per operation |

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
index.ts              Plugin entry point (tools, hooks, CLI, service)
config.ts             Config types and parser
ic-client.ts          @dfinity/agent wrapper (auth, canister calls)
sync.ts               Differential sync engine
prompts.ts            Smart adoption messaging
index.test.ts         Test suite
openclaw.plugin.json  Plugin manifest
skills/ic-storage/    Bundled skill (SKILL.md)
canister/             Motoko canister source (Factory + UserVault)
```

## Known Limitations

- Auto-sync hooks (`session_end`, `agent_end`) are wired but pending Phase 2 integration with OpenClaw's `MemorySearchManager` to pull actual local memories. Manual sync via `vault_sync` tool or `openclaw ic-memory sync` works now.
- The `vault_delete` agent tool is intentionally omitted. Deletion is available via the canister API for advanced users, but the agent encourages an append-friendly workflow.
- Audit log entries are capped at 100,000 with FIFO eviction of the oldest 10% when full.

## License

MIT
