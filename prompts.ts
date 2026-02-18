/// Smart prompting messages for IC Sovereign Persistent Memory.
/// Designed for non-technical users. Benefit-focused, concise, respectful.
///
/// The prompting system has three tiers:
/// 1. First-run prompt (gateway_start) -- introduces the concept
/// 2. Memory milestone nudge (agent_end) -- triggers after N unprotected memories
/// 3. Periodic reminder -- gentle, infrequent, after the user has dismissed

import { readFileSync, writeFileSync, mkdirSync } from "fs";
import { join, dirname } from "path";
import { homedir } from "os";

// -- Prompt state persistence --

export interface PromptState {
  /** Whether the user has dismissed the setup prompt */
  dismissed: boolean;
  /** Timestamp of last prompt shown (ms) */
  lastPromptAt: number;
  /** How many times we've prompted */
  promptCount: number;
  /** Tracked local memory count (approximate) */
  trackedMemoryCount: number;
  /** Whether vault setup is complete */
  vaultConfigured: boolean;
}

const DEFAULT_STATE: PromptState = {
  dismissed: false,
  lastPromptAt: 0,
  promptCount: 0,
  trackedMemoryCount: 0,
  vaultConfigured: false,
};

/// Get the path to the prompt state file.
export function getStatePath(configDir?: string): string {
  const base = configDir ?? join(homedir(), ".openclaw");
  return join(base, "ic-sovereign-memory-state.json");
}

/// Load prompt state from disk.
export function loadPromptState(configDir?: string): PromptState {
  try {
    const raw = readFileSync(getStatePath(configDir), "utf-8");
    return { ...DEFAULT_STATE, ...JSON.parse(raw) };
  } catch {
    return { ...DEFAULT_STATE };
  }
}

/// Save prompt state to disk.
export function savePromptState(state: PromptState, configDir?: string): void {
  const path = getStatePath(configDir);
  try {
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, JSON.stringify(state, null, 2));
  } catch {
    // Silently fail -- prompting state is non-critical
  }
}

// -- Timing rules --

/// Minimum time between prompts (24 hours)
const MIN_PROMPT_INTERVAL_MS = 24 * 60 * 60 * 1000;

/// Memory count thresholds that trigger nudges
const MEMORY_MILESTONES = [25, 50, 100, 250, 500];

/// Max number of prompts before we stop entirely
const MAX_PROMPTS = 5;

/// Check if enough time has passed since last prompt.
export function canPrompt(state: PromptState): boolean {
  if (state.vaultConfigured) { return false; }
  if (state.promptCount >= MAX_PROMPTS) { return false; }
  if (state.dismissed && state.promptCount >= 2) { return false; }

  const now = Date.now();
  return now - state.lastPromptAt >= MIN_PROMPT_INTERVAL_MS;
}

/// Check if the user has hit a memory milestone worth nudging about.
export function shouldNudgeForMilestone(state: PromptState, currentCount: number): boolean {
  if (state.vaultConfigured) { return false; }
  if (!canPrompt(state)) { return false; }

  for (const milestone of MEMORY_MILESTONES) {
    if (currentCount >= milestone && state.trackedMemoryCount < milestone) {
      return true;
    }
  }
  return false;
}

// -- Message templates --
// Written for humans, not developers. Short, clear, benefit-first.

/// First-run message shown at gateway startup.
export function getFirstRunMessage(): string[] {
  return [
    "",
    "  IC Sovereign Persistent Memory",
    "  Your AI memories exist only on this device right now.",
    "",
    "  Set up sovereign, persistent storage in under a minute:",
    "  - Your own personal vault on the Internet Computer",
    "  - Only your identity can read or write it",
    "  - Access your memories from any device, forever",
    "",
    "  Run: openclaw ic-memory setup",
    "",
  ];
}

/// Nudge message when user hits a memory milestone.
export function getMilestoneNudgeMessage(memoryCount: number): string[] {
  return [
    "",
    `  IC Sovereign Persistent Memory: ${memoryCount} memories on this device, no backup.`,
    "  If this device is lost or reset, they're gone.",
    "",
    "  Protect them with your own sovereign vault on the Internet Computer.",
    "  Run: openclaw ic-memory setup",
    "",
  ];
}

/// Gentle periodic reminder (shown after dismissal, up to MAX_PROMPTS).
export function getReminderMessage(memoryCount: number): string[] {
  if (memoryCount > 100) {
    return [
      `  IC Sovereign Persistent Memory: ${memoryCount} unprotected memories.`,
      "  One-time setup, permanent protection. Run: openclaw ic-memory setup",
    ];
  }
  return [
    "  IC Sovereign Persistent Memory: Protect your AI memories with sovereign storage.",
    "  Run: openclaw ic-memory setup",
  ];
}

/// Message shown when vault is newly configured (success confirmation).
export function getSetupCompleteMessage(canisterId: string): string[] {
  return [
    "",
    "  IC Sovereign Persistent Memory: Your vault is active.",
    `  Vault: ${canisterId}`,
    "  Your memories are now sovereign and persistent -- synced to your personal IC canister.",
    "  To restore on another device: openclaw ic-memory restore",
    "",
  ];
}
