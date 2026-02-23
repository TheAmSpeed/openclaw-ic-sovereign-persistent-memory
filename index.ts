/// IC Sovereign Persistent Memory -- OpenClaw plugin for sovereign, persistent AI memory on the Internet Computer.
/// Your memories live in a personal canister that only you control -- across devices, forever.

import { Type } from "@sinclair/typebox";
import type { AnyAgentTool, OpenClawPluginApi } from "openclaw/plugin-sdk";
import { parseConfig, icStorageConfigSchema, type IcStorageConfig } from "./config.js";
import { IcClient } from "./ic-client.js";
import { VaultCrypto } from "./vault-crypto.js";
import {
  identityExists,
  generateAndSaveIdentity,
  importIdentityFromKey,
  exportIdentity,
  deleteIdentity,
  getIdentityPath,
  readKeyFromStdin,
  loadIdentityAsync,
} from "./identity.js";
import {
  loadPromptState,
  savePromptState,
  canPrompt,
  shouldNudgeForMilestone,
  getFirstRunMessage,
  getMilestoneNudgeMessage,
  getReminderMessage,
  getSetupCompleteMessage,
} from "./prompts.js";
import { performSync, restoreFromVault, decodeContent, type LocalMemory } from "./sync.js";
import {
  readLocalMemories,
  extractMemoriesFromMessages,
  formatMemoriesAsContext,
  deriveSearchTerms,
} from "./memory-reader.js";

const icStoragePlugin = {
      id: "openclaw-ic-sovereign-persistent-memory",
  name: "IC Sovereign Persistent Memory",
  description:
    "Sovereign, persistent AI memory on the Internet Computer. " +
    "Your memories live in a personal canister that only you control -- across devices, forever.",
  kind: "memory" as const,
  configSchema: icStorageConfigSchema,

  register(api: OpenClawPluginApi) {
    let cfg: IcStorageConfig;
    try {
      cfg = parseConfig(api.pluginConfig);
    } catch (err) {
      api.logger.error(
        `IC Memory Vault: invalid config: ${err instanceof Error ? err.message : String(err)}`,
      );
      return;
    }

    let client: IcClient | null = null;
    let crypto: VaultCrypto | null = null;

    // Lazy-init the IC client
    function getClient(): IcClient {
      if (!client) {
        client = new IcClient(cfg);
      }
      return client;
    }

    // Lazy-init and derive the vetKey encryption engine.
    // First call makes two IC update calls (~2-3 seconds). Subsequent calls are instant.
    async function getCrypto(): Promise<VaultCrypto> {
      if (crypto?.isReady) return crypto;

      const ic = getClient();
      // Ensure the agent is initialized so we have the principal
      await ic.initAgent();
      const principal = ic.getPrincipal();
      if (!principal) {
        throw new Error("No IC identity available for encryption. Run `openclaw ic-memory setup` first.");
      }

      if (!crypto) {
        crypto = new VaultCrypto(ic, principal.toUint8Array());
      }
      await crypto.ensureReady();
      return crypto;
    }

    // -- Tools --

    // vault_sync: push local memories to IC vault
    api.registerTool(
      {
        name: "vault_sync",
        label: "IC Vault Sync",
        description:
          "Sync local memories and sessions to the IC Memory Vault. " +
          "Uses differential sync to only upload what has changed.",
        parameters: Type.Object({
          memories: Type.Optional(
            Type.Array(
              Type.Object({
                key: Type.String({ description: "Memory key" }),
                category: Type.String({ description: "Memory category" }),
                content: Type.String({ description: "Memory content" }),
                metadata: Type.Optional(Type.String({ description: "JSON metadata" })),
              }),
            ),
          ),
        }),
        async execute(_toolCallId, params) {
          try {
            const nowMs = Date.now(); // milliseconds (Number-safe; converted to ns at canister boundary)
            const localMemories: LocalMemory[] = (params.memories ?? []).map(
              (m: { key: string; category: string; content: string; metadata?: string }) => ({
                key: m.key,
                category: m.category,
                content: m.content,
                metadata: m.metadata ?? "{}",
                createdAt: nowMs,
                updatedAt: nowMs,
              }),
            );

            const vaultCrypto = await getCrypto().catch(() => undefined);
            const result = await performSync(getClient(), localMemories, [], undefined, vaultCrypto);
            return {
              content: [
                {
                  type: "text" as const,
                  text: `Sync complete: ${result.totalStored} stored, ${result.totalSkipped} skipped.${
                    result.errors.length > 0 ? ` Errors: ${result.errors.join(", ")}` : ""
                  }`,
                },
              ],
            };
          } catch (err) {
            return {
              content: [
                {
                  type: "text" as const,
                  text: `Sync failed: ${err instanceof Error ? err.message : String(err)}`,
                },
              ],
            };
          }
        },
      } as AnyAgentTool,
      { name: "vault_sync" },
    );

    // vault_recall: pull specific memory from IC vault
    api.registerTool(
      {
        name: "vault_recall",
        label: "IC Vault Recall",
        description:
          "Recall a specific memory from the IC Memory Vault by key, " +
          "or search by category and prefix.",
        parameters: Type.Object({
          key: Type.Optional(Type.String({ description: "Exact memory key to recall" })),
          category: Type.Optional(Type.String({ description: "Filter by category" })),
          prefix: Type.Optional(Type.String({ description: "Filter by key prefix" })),
          limit: Type.Optional(
            Type.Number({ description: "Max results (default 10)", minimum: 1, maximum: 100 }),
          ),
        }),
        async execute(_toolCallId, params) {
          try {
            const ic = getClient();

            // Initialize decryption if needed
            const decryptEntry = async (content: Uint8Array, isEncrypted: boolean): Promise<string> => {
              if (!isEncrypted) return decodeContent(content);
              try {
                const vaultCrypto = await getCrypto();
                const plain = await vaultCrypto.decrypt(content);
                return decodeContent(plain);
              } catch {
                return "[encrypted -- decryption failed]";
              }
            };

            // Exact key recall
            if (params.key) {
              const entry = await ic.recall(params.key);
              if (!entry) {
                return {
                  content: [
                    { type: "text" as const, text: `No memory found for key "${params.key}"` },
                  ],
                };
              }
              const contentText = await decryptEntry(entry.content, entry.isEncrypted);
              return {
                content: [
                  {
                    type: "text" as const,
                    text: `[${entry.category}] ${entry.key}: ${contentText}`,
                  },
                ],
                details: {
                  key: entry.key,
                  category: entry.category,
                  metadata: entry.metadata,
                },
              };
            }

            // Search by category/prefix
            const entries = await ic.recallRelevant(
              params.category ?? null,
              params.prefix ?? null,
              params.limit ?? 10,
            );

            if (entries.length === 0) {
              return {
                content: [
                  { type: "text" as const, text: "No matching memories found in IC vault." },
                ],
              };
            }

            const textParts: string[] = [];
            for (const e of entries) {
              const contentText = await decryptEntry(e.content, e.isEncrypted);
              textParts.push(`[${e.category}] ${e.key}: ${contentText}`);
            }
            const text = textParts.join("\n");

            return {
              content: [{ type: "text" as const, text }],
              details: { count: entries.length },
            };
          } catch (err) {
            return {
              content: [
                {
                  type: "text" as const,
                  text: `Recall failed: ${err instanceof Error ? err.message : String(err)}`,
                },
              ],
            };
          }
        },
      } as AnyAgentTool,
      { name: "vault_recall" },
    );

    // vault_restore: full restore from IC vault to local
    api.registerTool(
      {
        name: "vault_restore",
        label: "IC Vault Restore",
        description:
          "Restore all memories and sessions from the IC Memory Vault. " +
          "Use this to recover data on a new device or after local data loss.",
        parameters: Type.Object({}),
        async execute() {
          try {
            const vaultCrypto = await getCrypto().catch(() => undefined);
            const result = await restoreFromVault(getClient(), undefined, vaultCrypto);
            return {
              content: [
                {
                  type: "text" as const,
                  text: `Restored ${result.memories.length} memories and ${result.sessions.length} sessions from IC vault.`,
                },
              ],
              details: {
                memoriesCount: result.memories.length,
                sessionsCount: result.sessions.length,
                categories: [...new Set(result.memories.map((m) => m.category))],
              },
            };
          } catch (err) {
            return {
              content: [
                {
                  type: "text" as const,
                  text: `Restore failed: ${err instanceof Error ? err.message : String(err)}`,
                },
              ],
            };
          }
        },
      } as AnyAgentTool,
      { name: "vault_restore" },
    );

    // vault_status: show vault stats, cycles, sync status
    api.registerTool(
      {
        name: "vault_status",
        label: "IC Vault Status",
        description: "Show IC Memory Vault status: memories, sessions, cycle balance, categories.",
        parameters: Type.Object({}),
        async execute() {
          try {
            const dashboard = await getClient().getDashboard();
            const s = dashboard.stats;
            const text = [
              `IC Memory Vault Status`,
              `  Memories:  ${s.totalMemories}`,
              `  Sessions:  ${s.totalSessions}`,
              `  Categories: ${s.categories.join(", ") || "(none)"}`,
              `  Storage:   ${formatBytes(Number(s.bytesUsed))}`,
              `  Cycles:    ${formatCycles(Number(s.cycleBalance))}`,
              `  Last sync: ${s.lastUpdated === 0n ? "never" : new Date(Number(s.lastUpdated / 1_000_000n)).toISOString()}`,
            ].join("\n");

            return {
              content: [{ type: "text" as const, text }],
              details: {
                totalMemories: Number(s.totalMemories),
                totalSessions: Number(s.totalSessions),
                bytesUsed: Number(s.bytesUsed),
                cycleBalance: Number(s.cycleBalance),
              },
            };
          } catch (err) {
            return {
              content: [
                {
                  type: "text" as const,
                  text: `Status check failed: ${err instanceof Error ? err.message : String(err)}`,
                },
              ],
            };
          }
        },
      } as AnyAgentTool,
      { name: "vault_status" },
    );

    // vault_audit: show immutable audit log
    api.registerTool(
      {
        name: "vault_audit",
        label: "IC Vault Audit",
        description:
          "Show the immutable audit log from the IC Memory Vault. " +
          "Every operation is recorded with consensus-verified timestamps.",
        parameters: Type.Object({
          offset: Type.Optional(
            Type.Number({ description: "Start offset (default 0)", minimum: 0 }),
          ),
          limit: Type.Optional(
            Type.Number({ description: "Max entries (default 20)", minimum: 1, maximum: 100 }),
          ),
        }),
        async execute(_toolCallId, params) {
          try {
            const ic = getClient();
            const [entries, totalSize] = await Promise.all([
              ic.getAuditLog(params.offset ?? 0, params.limit ?? 20),
              ic.getAuditLogSize(),
            ]);

            if (entries.length === 0) {
              return {
                content: [{ type: "text" as const, text: "Audit log is empty." }],
              };
            }

            const lines = entries.map((e) => {
              const action = Object.keys(e.action)[0];
              const key = e.key.length > 0 ? e.key[0] : "-";
              const cat = e.category.length > 0 ? e.category[0] : "-";
              const details = e.details.length > 0 ? e.details[0] : "";
              const ts = new Date(Number(e.timestamp / 1_000_000n)).toISOString();
              return `${ts} [${action}] key=${key} cat=${cat} ${details}`.trim();
            });

            const text = [`Audit Log (${entries.length} of ${totalSize} total):`, ...lines].join(
              "\n",
            );

            return {
              content: [{ type: "text" as const, text }],
              details: { totalEntries: Number(totalSize), shown: entries.length },
            };
          } catch (err) {
            return {
              content: [
                {
                  type: "text" as const,
                  text: `Audit log failed: ${err instanceof Error ? err.message : String(err)}`,
                },
              ],
            };
          }
        },
      } as AnyAgentTool,
      { name: "vault_audit" },
    );

    // -- Hooks --

    // Load prompt state for smart adoption messaging
    let promptState = loadPromptState();

    // Mark as configured if canisterId is present
    if (cfg.canisterId) {
      if (!promptState.vaultConfigured) {
        promptState.vaultConfigured = true;
        savePromptState(promptState);
      }
    }

    // Gateway start: first-run prompt or periodic reminder
    api.on("gateway_start", async () => {
      if (cfg.canisterId) {
        // Vault is configured -- show confirmation on first run after setup
        if (promptState.vaultConfigured && promptState.promptCount === 0) {
          for (const line of getSetupCompleteMessage(cfg.canisterId)) {
            api.logger.info(line);
          }
        }
        return;
      }

      // No vault configured -- show adoption prompt if appropriate
      promptState = loadPromptState(); // reload in case another process updated
      if (!canPrompt(promptState)) return;

      const messages =
        promptState.promptCount === 0
          ? getFirstRunMessage()
          : getReminderMessage(promptState.trackedMemoryCount);

      for (const line of messages) {
        api.logger.info(line);
      }

      promptState.promptCount += 1;
      promptState.lastPromptAt = Date.now();
      savePromptState(promptState);
    });

    // Smart Memory Recall: inject relevant IC vault memories before agent starts.
    // This solves the "OpenClaw forgets" problem by pre-loading relevant context
    // from the IC vault into every conversation -- surviving compaction, session resets,
    // and working across devices.
    api.on("before_agent_start", async (event, ctx) => {
      if (!cfg.canisterId) return;
      if (!identityExists()) return;

      const prompt = (event as { prompt?: string }).prompt;
      if (!prompt) return;

      try {
        const ic = getClient();
        const { categories, prefixes } = deriveSearchTerms(prompt);

        // Recall relevant memories from IC vault
        const recalled: Array<{ key: string; category: string; content: Uint8Array; isEncrypted: boolean }> = [];
        const RECALL_LIMIT = 10;

        if (categories.length > 0) {
          // Search by matched categories
          for (const category of categories.slice(0, 3)) {
            const prefix = prefixes.length > 0 ? prefixes[0] : null;
            const entries = await ic.recallRelevant(category, prefix, RECALL_LIMIT);
            recalled.push(...entries);
          }
        } else {
          // Broad recall -- get recent memories across all categories
          const entries = await ic.recallRelevant(null, null, RECALL_LIMIT);
          recalled.push(...entries);
        }

        if (recalled.length === 0) return;

        // Decrypt encrypted entries if any
        const hasEncrypted = recalled.some((m) => m.isEncrypted);
        let vaultCrypto: VaultCrypto | null = null;
        if (hasEncrypted) {
          try {
            vaultCrypto = await getCrypto();
          } catch (err) {
            api.logger.error(
              `IC Sovereign Memory: failed to derive decryption key: ${err instanceof Error ? err.message : String(err)}`,
            );
            // Continue with plaintext entries only
          }
        }

        // Deduplicate by key and decrypt encrypted entries
        const seen = new Set<string>();
        const decrypted: Array<{ key: string; category: string; content: Uint8Array }> = [];
        for (const m of recalled) {
          if (seen.has(m.key)) continue;
          seen.add(m.key);

          let content = m.content;
          if (m.isEncrypted && vaultCrypto?.isReady) {
            try {
              content = await vaultCrypto.decrypt(content);
            } catch {
              // Skip entries we can't decrypt (key mismatch, corruption)
              continue;
            }
          } else if (m.isEncrypted) {
            // Can't decrypt -- skip encrypted entries when crypto isn't available
            continue;
          }
          decrypted.push({ key: m.key, category: m.category, content });
        }

        const context = formatMemoriesAsContext(decrypted);
        if (!context) return;

        return { prependContext: context };
      } catch (err) {
        // Fail silently -- recall is best-effort. The agent should still work
        // even if the IC vault is temporarily unreachable.
        api.logger.error(
          `IC Sovereign Memory: recall failed: ${err instanceof Error ? err.message : String(err)}`,
        );
      }
    });

    // Auto-sync on session end: read local memory files and sync to IC vault.
    // session_end provides sessionId, messageCount, and durationMs (no messages or workspaceDir),
    // so we read from the default workspace path.
    if (cfg.syncOnSessionEnd) {
      api.on("session_end", async (_event) => {
        if (!cfg.canisterId) return;
        if (!identityExists()) return;
        try {
          const localMemories = readLocalMemories();
          const vaultCrypto = await getCrypto().catch(() => undefined);
          await performSync(getClient(), localMemories, [], undefined, vaultCrypto);
        } catch (err) {
          api.logger.error(
            `IC Sovereign Memory: session_end sync failed: ${err instanceof Error ? err.message : String(err)}`,
          );
        }
      });
    }

    // Pre-Compaction Memory Flush: save memories to IC vault BEFORE compaction destroys context.
    // This directly addresses Failure Mode 3 from the OpenClaw memory problem:
    // compaction summarizes/removes older messages, and anything not yet saved to disk is lost.
    api.on("before_compaction", async (event, ctx) => {
      if (!cfg.canisterId) return;
      if (!identityExists()) return;

      try {
        const typedEvent = event as {
          messages?: unknown[];
          sessionFile?: string;
          messageCount?: number;
        };
        const workspaceDir = (ctx as { workspaceDir?: string }).workspaceDir;

        // Strategy: Read local memory files (which may have been updated by OpenClaw's
        // memoryFlush) AND extract memories from conversation messages.
        const localMemories = readLocalMemories(workspaceDir ?? undefined);

        // Also extract from conversation messages if available
        const messageMemories = typedEvent.messages
          ? extractMemoriesFromMessages(typedEvent.messages)
          : [];

        const allMemories = [...localMemories, ...messageMemories];

        if (allMemories.length === 0) return;

        const vaultCrypto = await getCrypto().catch(() => undefined);
        await performSync(getClient(), allMemories, [], undefined, vaultCrypto);
      } catch (err) {
        api.logger.error(
          `IC Sovereign Memory: before_compaction sync failed: ${err instanceof Error ? err.message : String(err)}`,
        );
      }
    });

    // Agent end: track memory count for milestone nudges + auto-capture and sync.
    // Reads local memory files and extracts memories from conversation messages,
    // then syncs everything to the IC vault.
    api.on("agent_end", async (event) => {
      // Track memory growth for milestone nudges (even if vault isn't configured)
      promptState = loadPromptState();
      const previousCount = promptState.trackedMemoryCount;
      promptState.trackedMemoryCount = previousCount + 1; // approximate: 1 conversation ~ 1 memory

      // Check if we should show a milestone nudge
      if (
        !cfg.canisterId &&
        shouldNudgeForMilestone(
          { ...promptState, trackedMemoryCount: previousCount },
          previousCount + 1,
        )
      ) {
        const messages = getMilestoneNudgeMessage(promptState.trackedMemoryCount);
        for (const line of messages) {
          api.logger.info(line);
        }
        promptState.promptCount += 1;
        promptState.lastPromptAt = Date.now();
      }

      savePromptState(promptState);

      // Auto-capture and sync: read local memory files + extract from conversation messages.
      if (cfg.canisterId && cfg.syncOnAgentEnd && identityExists()) {
        try {
          const typedEvent = event as {
            messages?: unknown[];
          };

          // Read local memory files (MEMORY.md, memory/*.md)
          const localMemories = readLocalMemories();

          // Extract additional memories from the conversation messages
          const messageMemories = typedEvent.messages
            ? extractMemoriesFromMessages(typedEvent.messages)
            : [];

          const allMemories = [...localMemories, ...messageMemories];

          const vaultCrypto = await getCrypto().catch(() => undefined);
          await performSync(getClient(), allMemories, [], undefined, vaultCrypto);
        } catch (err) {
          api.logger.error(
            `IC Sovereign Memory: agent_end sync failed: ${err instanceof Error ? err.message : String(err)}`,
          );
        }
      }
    });

    // -- CLI Commands --

    api.registerCli(
      ({ program }) => {
        const vault = program
          .command("ic-memory")
          .description(
            "IC Sovereign Persistent Memory -- your memories, your canister, your control",
          );

        vault
          .command("setup")
          .description("Create your sovereign memory vault on the Internet Computer")
          .action(async () => {
            try {
              console.log("");
              console.log("  IC Sovereign Persistent Memory -- Setup");
              console.log("  ----------------------------------------");
              console.log("");

              // Step 1: Identity
              console.log("  Step 1/3: Identity");
              let identity;
              if (identityExists()) {
                identity = await loadIdentityAsync();
                console.log(`  Existing identity found.`);
              } else {
                identity = await generateAndSaveIdentity();
                console.log("  Generated new IC identity.");
                console.log(`  Stored in: ${getIdentityPath()}`);
              }
              const principal = identity.getPrincipal();
              console.log(`  Principal: ${principal.toText()}`);
              console.log("");

              // Step 2: Check for existing vault
              console.log("  Step 2/3: Checking for existing vault...");
              const ic = getClient();
              await ic.initAgentWithIdentity(identity);
              const existingVault = await ic.getVault();
              if (existingVault) {
                console.log(`  You already have a vault: ${existingVault.toText()}`);
                console.log("");
                console.log("  To connect this device, add to your OpenClaw config:");
                console.log(`    openclaw config set plugins.entries.openclaw-ic-sovereign-persistent-memory.config.canisterId "${existingVault.toText()}"`);
                console.log("");
                return;
              }

              // Step 3: Create vault
              console.log("  Step 3/3: Creating your sovereign vault...");
              console.log("  This deploys a personal canister on the Internet Computer.");
              console.log("  It takes about 10 seconds.");
              console.log("");
              const result = await ic.createVault();
              if ("ok" in result) {
                console.log("  Vault created successfully.");
                console.log("");
                console.log(`  Vault ID:    ${result.ok.toText()}`);
                console.log(`  Network:     IC Mainnet`);
                console.log(`  Owner:       ${principal.toText()}`);
                console.log(`  Controller:  You (sovereign -- only you can upgrade or delete)`);
                console.log("");
                console.log("  Add to your OpenClaw config:");
                console.log(`    openclaw config set plugins.entries.openclaw-ic-sovereign-persistent-memory.config.canisterId "${result.ok.toText()}"`);
                console.log("");
                console.log("  Your AI memories are now sovereign and persistent.");
                console.log("  They live on the Internet Computer and follow you across devices.");
                console.log("");
              } else {
                console.error(`  Setup failed: ${result.err}`);
                console.error("");
                console.error("  Common issues:");
                console.error("  - 'You already have a vault' -- run `openclaw ic-memory status` to see it");
                console.error("  - 'Factory has insufficient cycles' -- please open an issue on GitHub");
                console.error("");
              }
            } catch (err) {
              const msg = err instanceof Error ? err.message : String(err);
              console.error("");
              console.error(`  Setup failed: ${msg}`);
              console.error("");
              console.error("  Troubleshooting:");
              console.error("  - Check your internet connection");
              console.error("  - Try again -- IC mainnet can be temporarily slow");
              console.error("  - File an issue: https://github.com/TheAmSpeed/openclaw-ic-sovereign-persistent-memory/issues");
              console.error("");
            }
          });

        vault
          .command("status")
          .description("Show your vault status and statistics")
          .action(async () => {
            try {
              const dashboard = await getClient().getDashboard();
              const s = dashboard.stats;
              console.log("");
              console.log("  IC Sovereign Persistent Memory -- Status");
              console.log("  ----------------------------------------");
              console.log(`  Memories:    ${s.totalMemories}`);
              console.log(`  Sessions:    ${s.totalSessions}`);
              console.log(`  Categories:  ${s.categories.join(", ") || "(none)"}`);
              console.log(`  Storage:     ${formatBytes(Number(s.bytesUsed))}`);
              console.log(`  Cycles:      ${formatCycles(Number(s.cycleBalance))}`);
              console.log(
                `  Last sync:   ${s.lastUpdated === 0n ? "never" : new Date(Number(s.lastUpdated / 1_000_000n)).toISOString()}`,
              );

              // Show encryption status
              const encryptedCount = dashboard.recentMemories.filter((m) => m.isEncrypted).length;
              const totalRecent = dashboard.recentMemories.length;
              if (totalRecent > 0) {
                const encPct = Math.round((encryptedCount / totalRecent) * 100);
                console.log(`  Encryption: ${encPct}% of recent entries encrypted`);
              }

              if (dashboard.recentMemories.length > 0) {
                console.log("");
                console.log("  Recent memories:");
                for (const m of dashboard.recentMemories.slice(0, 5)) {
                  if (m.isEncrypted) {
                    console.log(`    [${m.category}] ${m.key}: [encrypted]`);
                  } else {
                    const preview = decodeContent(m.content).slice(0, 60);
                    console.log(`    [${m.category}] ${m.key}: ${preview}${preview.length >= 60 ? "..." : ""}`);
                  }
                }
              }
              console.log("");
            } catch (err) {
              console.error(`  Status failed: ${err instanceof Error ? err.message : String(err)}`);
            }
          });

        vault
          .command("sync")
          .description("Manually sync local memories to your IC vault")
          .action(async () => {
            try {
              console.log("");
              console.log("  Syncing local memories to IC vault...");

              // Read all local OpenClaw memory files
              const localMemories = readLocalMemories();
              console.log(`  Found ${localMemories.length} memory entries from local files`);

              if (localMemories.length === 0) {
                console.log("");
                console.log("  No local memories found to sync.");
                console.log("  Memory files are stored in ~/.openclaw/workspace/MEMORY.md");
                console.log("  and ~/.openclaw/workspace/memory/*.md");
                console.log("");
                return;
              }

              let vaultCrypto: VaultCrypto | undefined;
              try {
                console.log("  Initializing end-to-end encryption...");
                vaultCrypto = await getCrypto();
                console.log("  Encryption ready.");
              } catch (err) {
                console.log(`  Warning: encryption unavailable (${err instanceof Error ? err.message : String(err)})`);
                console.log("  Syncing without encryption (plaintext).");
              }

              const result = await performSync(getClient(), localMemories, [], (msg) =>
                console.log(`    ${msg}`),
              vaultCrypto);
              console.log("");
              console.log(`  Done: ${result.totalStored} stored, ${result.totalSkipped} unchanged`);
              if (result.errors.length > 0) {
                console.log(`  Errors: ${result.errors.join(", ")}`);
              }
              console.log("");
            } catch (err) {
              console.error(`  Sync failed: ${err instanceof Error ? err.message : String(err)}`);
            }
          });

        vault
          .command("restore")
          .description("Restore all memories from your IC vault to this device")
          .action(async () => {
            try {
              console.log("");
              console.log("  Restoring from IC vault...");
              let vaultCrypto: VaultCrypto | undefined;
              try {
                console.log("  Initializing end-to-end encryption...");
                vaultCrypto = await getCrypto();
                console.log("  Encryption ready.");
              } catch (err) {
                console.log(`  Warning: decryption unavailable (${err instanceof Error ? err.message : String(err)})`);
                console.log("  Restoring plaintext entries only.");
              }

              const result = await restoreFromVault(getClient(), (msg) => console.log(`    ${msg}`), vaultCrypto);
              console.log("");
              console.log(`  Restored ${result.memories.length} memories and ${result.sessions.length} sessions`);
              console.log("  Your sovereign memories are now available on this device.");
              console.log("");
            } catch (err) {
              console.error(`  Restore failed: ${err instanceof Error ? err.message : String(err)}`);
            }
          });

        vault
          .command("audit")
          .description("Show the immutable audit log of all vault operations")
          .option("--offset <n>", "Start offset", "0")
          .option("--limit <n>", "Max entries", "20")
          .action(async (opts) => {
            try {
              const ic = getClient();
              const offset = parseInt(opts.offset, 10);
              const limit = parseInt(opts.limit, 10);
              if (isNaN(offset) || offset < 0) {
                console.error("  Invalid offset. Must be a non-negative number.");
                return;
              }
              if (isNaN(limit) || limit < 1) {
                console.error("  Invalid limit. Must be a positive number.");
                return;
              }
              const entries = await ic.getAuditLog(offset, limit);
              const total = await ic.getAuditLogSize();

              console.log("");
              console.log(`  Audit Log (${entries.length} of ${total} entries)`);
              console.log("  Every operation is recorded with consensus-verified timestamps.");
              console.log("");
              for (const e of entries) {
                const action = Object.keys(e.action)[0];
                const key = e.key.length > 0 ? e.key[0] : "-";
                const ts = new Date(Number(e.timestamp / 1_000_000n)).toISOString();
                const details = e.details.length > 0 ? ` ${e.details[0]}` : "";
                console.log(`    ${ts}  [${action}]  key=${key}${details}`);
              }
              console.log("");
            } catch (err) {
              console.error(`  Audit failed: ${err instanceof Error ? err.message : String(err)}`);
            }
          });

        vault
          .command("export-identity")
          .description("Export your IC identity for use on another device")
          .action(() => {
            try {
              const { secretKeyBase64, principal } = exportIdentity();
              console.log("");
              console.log("  IC Sovereign Persistent Memory -- Export Identity");
              console.log("  -------------------------------------------------");
              console.log("");
              console.log(`  Principal: ${principal}`);
              console.log("");
              console.log("  Your identity key (keep this secret!):");
              console.log("");
              console.log(`    ${secretKeyBase64}`);
              console.log("");
              console.log("  To import on another device, run:");
              console.log("    openclaw ic-memory import-identity");
              console.log("  Then paste the key above when prompted.");
              console.log("");
              console.log("  Or pipe it directly (no shell history):");
              console.log(`    echo "${secretKeyBase64}" | openclaw ic-memory import-identity`);
              console.log("");
              console.log("  WARNING: Anyone with this key has full control of your vault.");
              console.log("  Store it securely (password manager, encrypted note, etc.).");
              console.log("");
            } catch (err) {
              console.error(`  Export failed: ${err instanceof Error ? err.message : String(err)}`);
            }
          });

        vault
          .command("import-identity")
          .description("Import an IC identity from another device (reads key from stdin)")
          .action(async () => {
            try {
              console.log("");
              console.log("  IC Sovereign Persistent Memory -- Import Identity");
              console.log("  -------------------------------------------------");
              console.log("");

              const key = await readKeyFromStdin();
              const identity = await importIdentityFromKey(key);
              const principal = identity.getPrincipal();
              console.log("");
              console.log(`  Identity imported successfully.`);
              console.log(`  Principal: ${principal.toText()}`);
              console.log(`  Stored in: ${getIdentityPath()}`);
              console.log("");
              console.log("  You can now access your vault from this device.");
              console.log("  Run `openclaw ic-memory status` to verify.");
              console.log("");
            } catch (err) {
              console.error(`  Import failed: ${err instanceof Error ? err.message : String(err)}`);
            }
          });
        vault
          .command("revoke")
          .description("Revoke Factory controller access -- make your vault fully sovereign")
          .action(async () => {
            try {
              console.log("");
              console.log("  IC Sovereign Persistent Memory -- Revoke Factory Controller");
              console.log("  -----------------------------------------------------------");
              console.log("");
              console.log("  This removes the Factory canister as a controller of your vault.");
              console.log("  After this, ONLY your identity can control (upgrade, delete) your vault.");
              console.log("");
              console.log("  WARNING: This is irreversible. The Factory will no longer be able to");
              console.log("  assist with vault recovery or upgrades.");
              console.log("");

              const result = await getClient().revokeFactoryController();
              if ("ok" in result) {
                console.log("  Factory controller access revoked successfully.");
                console.log("  Your vault is now fully sovereign -- only you control it.");
                console.log("");
              } else {
                console.error(`  Revoke failed: ${result.err}`);
                console.error("");
              }
            } catch (err) {
              console.error(`  Revoke failed: ${err instanceof Error ? err.message : String(err)}`);
            }
          });

        vault
          .command("migrate-encrypt")
          .description("Encrypt existing plaintext memories in your vault (one-time migration)")
          .action(async () => {
            try {
              console.log("");
              console.log("  IC Sovereign Persistent Memory -- Encrypt Existing Memories");
              console.log("  -----------------------------------------------------------");
              console.log("");
              console.log("  This will read all plaintext memories from your vault,");
              console.log("  encrypt them client-side using vetKeys, and write them back.");
              console.log("  After migration, node providers cannot read your memory content.");
              console.log("");

              if (!cfg.canisterId) {
                console.error("  No vault configured. Run `openclaw ic-memory setup` first.");
                return;
              }
              if (!identityExists()) {
                console.error("  No IC identity found. Run `openclaw ic-memory setup` first.");
                return;
              }

              const ic = getClient();

              // Check vault version supports encryption
              let supportsEncryption = false;
              try {
                const versionInfo = await ic.getVaultVersion();
                supportsEncryption = versionInfo.supportsEncryption;
              } catch {
                // v1 vault doesn't have getVaultVersion
              }
              if (!supportsEncryption) {
                console.error("  Your vault does not support encryption (v1).");
                console.error("  Run `openclaw ic-memory upgrade-vault` first to upgrade to v2.");
                console.log("");
                return;
              }

              const dashboard = await ic.getDashboard();
              const totalMemories = Number(dashboard.stats.totalMemories);

              if (totalMemories === 0) {
                console.log("  Your vault is empty. Nothing to migrate.");
                console.log("");
                return;
              }

              // Count unencrypted entries
              const categories = await ic.getCategories();
              let plaintextCount = 0;
              let encryptedCount = 0;
              const allPlaintextEntries: Array<{
                key: string;
                category: string;
                content: Uint8Array;
                metadata: string;
                createdAt: bigint;
                updatedAt: bigint;
              }> = [];

              for (const cat of categories) {
                const entries = await ic.recallRelevant(cat, null, totalMemories);
                for (const entry of entries) {
                  if (entry.isEncrypted) {
                    encryptedCount++;
                  } else {
                    plaintextCount++;
                    allPlaintextEntries.push(entry);
                  }
                }
              }

              console.log(`  Found ${plaintextCount} plaintext and ${encryptedCount} already encrypted.`);

              if (plaintextCount === 0) {
                console.log("  All memories are already encrypted. Nothing to do.");
                console.log("");
                return;
              }

              // Confirm
              console.log("");
              console.log(`  Will encrypt ${plaintextCount} plaintext entries.`);
              console.log("");

              const readline = await import("node:readline");
              const rl = readline.createInterface({
                input: process.stdin,
                output: process.stdout,
              });

              const answer = await new Promise<string>((resolve) => {
                rl.question("  Proceed? (y/N): ", (ans) => {
                  rl.close();
                  resolve(ans);
                });
              });

              if (answer.trim().toLowerCase() !== "y") {
                console.log("");
                console.log("  Migration cancelled.");
                console.log("");
                return;
              }

              // Initialize encryption
              console.log("");
              console.log("  Deriving encryption key from IC vetKeys...");
              const vaultCrypto = await getCrypto();
              console.log("  Encryption ready.");

              // Encrypt and re-upload in batches
              let migrated = 0;
              const BATCH = 50;
              for (let i = 0; i < allPlaintextEntries.length; i += BATCH) {
                const batch = allPlaintextEntries.slice(i, i + BATCH);
                const encryptedInputs = [];

                for (const entry of batch) {
                  const encrypted = await vaultCrypto.encrypt(entry.content);
                  encryptedInputs.push({
                    key: entry.key,
                    category: entry.category,
                    content: encrypted,
                    metadata: entry.metadata,
                    createdAt: entry.createdAt,
                    // Bump updatedAt by 1 nanosecond so bulkSync accepts the update.
                    // bulkSync uses strict > comparison, so same timestamp = skip.
                    updatedAt: entry.updatedAt + 1n,
                    isEncrypted: true,
                  });
                }

                const result = await ic.bulkSync(encryptedInputs, []);
                if ("ok" in result) {
                  migrated += Number(result.ok.stored);
                } else {
                  console.error(`  Batch error: ${result.err}`);
                }
                console.log(`  Encrypted ${migrated}/${plaintextCount} entries...`);
              }

              // Post-migration verification: re-check how many remain plaintext
              let remainingPlaintext = 0;
              for (const cat of categories) {
                const entries = await ic.recallRelevant(cat, null, totalMemories);
                for (const entry of entries) {
                  if (!entry.isEncrypted) remainingPlaintext++;
                }
              }

              console.log("");
              console.log(`  Migration complete: ${migrated} entries encrypted.`);
              if (remainingPlaintext > 0) {
                console.log(`  WARNING: ${remainingPlaintext} entries still plaintext (batch errors during migration).`);
                console.log("  Run `openclaw ic-memory migrate-encrypt` again to retry.");
              } else {
                console.log("  All entries are now encrypted.");
              }
              console.log("  Your vault data is now protected by end-to-end encryption.");
              console.log("  Node providers can no longer read your memory content.");
              console.log("");
            } catch (err) {
              console.error(`  Migration failed: ${err instanceof Error ? err.message : String(err)}`);
            }
          });

        vault
          .command("upgrade-vault")
          .description("Upgrade your vault canister to the latest version")
          .action(async () => {
            try {
              console.log("");
              console.log("  IC Sovereign Persistent Memory -- Vault Upgrade");
              console.log("  -----------------------------------------------");
              console.log("");

              if (!cfg.canisterId) {
                console.error("  No vault configured. Run `openclaw ic-memory setup` first.");
                return;
              }
              if (!identityExists()) {
                console.error("  No IC identity found. Run `openclaw ic-memory setup` first.");
                return;
              }

              const ic = getClient();

              // Check current vault version
              console.log("  Checking vault version...");
              let vaultVersion: bigint;
              try {
                const versionInfo = await ic.getVaultVersion();
                vaultVersion = versionInfo.version;
                console.log(`  Current vault version: ${vaultVersion}`);
              } catch {
                // Vault may be on v1 which doesn't have getVaultVersion
                vaultVersion = 1n;
                console.log("  Current vault version: 1 (pre-encryption)");
              }

              // Check latest version from Factory
              const latestVersion = await ic.getLatestVaultVersion();
              console.log(`  Latest available version: ${latestVersion}`);

              if (latestVersion === 0n) {
                console.log("");
                console.log("  No vault WASM has been uploaded to the Factory yet.");
                console.log("  The admin must upload the latest WASM before upgrades are available.");
                console.log("");
                return;
              }

              if (vaultVersion >= latestVersion) {
                console.log("");
                console.log("  Your vault is already up to date.");
                console.log("");
                return;
              }

              console.log("");
              console.log(`  An upgrade is available: v${vaultVersion} -> v${latestVersion}`);
              console.log("  This will upgrade your vault canister's code while preserving all data.");
              console.log("  The Factory must still be a controller of your vault for this to work.");
              console.log("");

              const readline = await import("node:readline");
              const rl = readline.createInterface({
                input: process.stdin,
                output: process.stdout,
              });

              const answer = await new Promise<string>((resolve) => {
                rl.question("  Proceed with upgrade? (y/N): ", (ans) => {
                  rl.close();
                  resolve(ans);
                });
              });

              if (answer.trim().toLowerCase() !== "y") {
                console.log("");
                console.log("  Upgrade cancelled.");
                console.log("");
                return;
              }

              console.log("");
              console.log("  Upgrading vault...");
              const result = await ic.upgradeMyVault();
              if ("ok" in result) {
                console.log("  Vault upgraded successfully.");
                // Verify the new version
                try {
                  const newVersionInfo = await ic.getVaultVersion();
                  console.log(`  New vault version: ${newVersionInfo.version}`);
                  if (newVersionInfo.supportsEncryption) {
                    console.log("  Encryption support: enabled");
                  }
                } catch {
                  // Non-critical -- version check failed but upgrade succeeded
                }
              } else {
                console.error(`  Upgrade failed: ${result.err}`);
              }
              console.log("");
            } catch (err) {
              console.error(`  Upgrade failed: ${err instanceof Error ? err.message : String(err)}`);
            }
          });

        vault
          .command("delete-identity")
          .description("Delete your IC identity from this device (DESTRUCTIVE)")
          .action(async () => {
            try {
              console.log("");
              console.log("  IC Sovereign Persistent Memory -- Delete Identity");
              console.log("  -------------------------------------------------");
              console.log("");
              console.log("  WARNING: This will permanently delete your IC identity from this device.");
              console.log("  If you have not exported your identity key, you will LOSE ACCESS to your vault.");
              console.log("  There is no recovery without the identity key.");
              console.log("");

              if (!identityExists()) {
                console.log("  No identity found on this device. Nothing to delete.");
                console.log("");
                return;
              }

              // Read confirmation from stdin
              const readline = await import("node:readline");
              const rl = readline.createInterface({
                input: process.stdin,
                output: process.stdout,
              });

              const answer = await new Promise<string>((resolve) => {
                rl.question("  Type 'DELETE' to confirm: ", (ans) => {
                  rl.close();
                  resolve(ans);
                });
              });

              if (answer.trim() !== "DELETE") {
                console.log("");
                console.log("  Aborted. Identity was NOT deleted.");
                console.log("");
                return;
              }

              deleteIdentity();
              console.log("");
              console.log("  Identity deleted from this device.");
              console.log("  If you exported your key previously, you can re-import it with:");
              console.log("    openclaw ic-memory import-identity");
              console.log("");
            } catch (err) {
              console.error(`  Delete failed: ${err instanceof Error ? err.message : String(err)}`);
            }
          });
      },
      { commands: ["ic-memory"] },
    );

    // -- Service --

    api.registerService({
  id: "openclaw-ic-sovereign-persistent-memory",
      start: () => {
        if (cfg.canisterId) {
          api.logger.info(
            `IC Sovereign Memory: active (vault: ${cfg.canisterId}, network: ${cfg.network}, auto-sync: ${cfg.autoSync})`,
          );

          // Background upgrade availability check (non-blocking, best-effort)
          if (identityExists()) {
            (async () => {
              try {
                const ic = getClient();
                let vaultVersion: bigint;
                try {
                  const versionInfo = await ic.getVaultVersion();
                  vaultVersion = versionInfo.version;
                } catch {
                  vaultVersion = 1n;
                }
                const latestVersion = await ic.getLatestVaultVersion();
                if (latestVersion > 0n && vaultVersion < latestVersion) {
                  api.logger.info(
                    `IC Sovereign Memory: vault upgrade available (v${vaultVersion} -> v${latestVersion}). ` +
                    `Run \`openclaw ic-memory upgrade-vault\` to upgrade.`,
                  );
                }
              } catch {
                // Silently ignore -- upgrade check is best-effort
              }
            })();
          }
        }
        // If not configured, the gateway_start hook handles messaging
      },
      stop: () => {
        // Clean up cached encryption key material
        crypto?.destroy();
        api.logger.info("IC Sovereign Memory: service stopped");
      },
    });
  },
};

// -- Utility functions (exported for testing) --

export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  const val = bytes / Math.pow(1024, i);
  return `${val.toFixed(1)} ${units[i]}`;
}

export function formatCycles(cycles: number): string {
  if (cycles >= 1_000_000_000_000) {
    return `${(cycles / 1_000_000_000_000).toFixed(2)} T`;
  }
  if (cycles >= 1_000_000_000) {
    return `${(cycles / 1_000_000_000).toFixed(2)} B`;
  }
  return `${cycles.toLocaleString()}`;
}

export default icStoragePlugin;
