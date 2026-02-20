/// IC Sovereign Persistent Memory -- OpenClaw plugin for sovereign, persistent AI memory on the Internet Computer.
/// Your memories live in a personal canister that only you control -- across devices, forever.

import { Type } from "@sinclair/typebox";
import type { AnyAgentTool, OpenClawPluginApi } from "openclaw/plugin-sdk";
import { parseConfig, icStorageConfigSchema, type IcStorageConfig } from "./config.js";
import { IcClient } from "./ic-client.js";
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

    // Lazy-init the IC client
    function getClient(): IcClient {
      if (!client) {
        client = new IcClient(cfg);
      }
      return client;
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

            const result = await performSync(getClient(), localMemories, []);
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
              return {
                content: [
                  {
                    type: "text" as const,
                    text: `[${entry.category}] ${entry.key}: ${decodeContent(entry.content)}`,
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

            const text = entries
              .map((e) => `[${e.category}] ${e.key}: ${decodeContent(e.content)}`)
              .join("\n");

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
            const result = await restoreFromVault(getClient());
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
        const recalled: Array<{ key: string; category: string; content: Uint8Array }> = [];
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

        // Deduplicate by key
        const seen = new Set<string>();
        const unique = recalled.filter((m) => {
          if (seen.has(m.key)) return false;
          seen.add(m.key);
          return true;
        });

        const context = formatMemoriesAsContext(unique);
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
          await performSync(getClient(), localMemories, []);
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

        await performSync(getClient(), allMemories, []);
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

          await performSync(getClient(), allMemories, []);
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

              if (dashboard.recentMemories.length > 0) {
                console.log("");
                console.log("  Recent memories:");
                for (const m of dashboard.recentMemories.slice(0, 5)) {
                  const preview = decodeContent(m.content).slice(0, 60);
                  console.log(`    [${m.category}] ${m.key}: ${preview}${preview.length >= 60 ? "..." : ""}`);
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

              const result = await performSync(getClient(), localMemories, [], (msg) =>
                console.log(`    ${msg}`),
              );
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
              const result = await restoreFromVault(getClient(), (msg) => console.log(`    ${msg}`));
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
        }
        // If not configured, the gateway_start hook handles messaging
      },
      stop: () => {
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
