/// Read and parse local OpenClaw memory files into structured entries for IC vault sync.
///
/// OpenClaw stores memories as plain markdown files:
///   - ~/.openclaw/workspace/MEMORY.md  (primary)
///   - ~/.openclaw/workspace/memory.md  (alternate)
///   - ~/.openclaw/workspace/memory/*.md (daily notes, e.g. 2026-02-20.md)
///
/// This module reads those files, parses them into LocalMemory entries suitable for
/// syncing to the IC vault via bulkSync(), and extracts memory-worthy content from
/// raw agent messages (for the before_compaction and agent_end hooks).

import * as fs from "node:fs";
import * as path from "node:path";
import type { LocalMemory } from "./sync.js";

// -- Constants --

const PRIMARY_MEMORY_FILE = "MEMORY.md";
const ALTERNATE_MEMORY_FILE = "memory.md";
const MEMORY_DIR = "memory";
const DEFAULT_WORKSPACE = path.join(
  process.env.HOME ?? process.env.USERPROFILE ?? ".",
  ".openclaw",
  "workspace",
);

// -- Types --

/// A parsed section from a memory markdown file.
export interface MemorySection {
  /// Heading text (e.g. "User Preferences", "Project Decisions")
  heading: string;
  /// The full content under this heading
  content: string;
  /// Source file path (for dedup and audit)
  sourceFile: string;
}

// -- File discovery --

/// Resolve the workspace directory from hook context or fallback.
export function resolveWorkspaceDir(workspaceDir?: string): string {
  return workspaceDir ?? DEFAULT_WORKSPACE;
}

/// Find all memory files in the workspace directory.
/// Returns absolute paths, sorted by modification time (newest first).
export function findMemoryFiles(workspaceDir: string): string[] {
  const files: Array<{ path: string; mtime: number }> = [];

  // Check primary MEMORY.md
  const primaryPath = path.join(workspaceDir, PRIMARY_MEMORY_FILE);
  if (fs.existsSync(primaryPath)) {
    const stat = fs.statSync(primaryPath);
    files.push({ path: primaryPath, mtime: stat.mtimeMs });
  }

  // Check alternate memory.md (only if different from primary via case-sensitive check)
  const alternatePath = path.join(workspaceDir, ALTERNATE_MEMORY_FILE);
  if (
    alternatePath !== primaryPath &&
    fs.existsSync(alternatePath) &&
    !isSameFile(primaryPath, alternatePath)
  ) {
    const stat = fs.statSync(alternatePath);
    files.push({ path: alternatePath, mtime: stat.mtimeMs });
  }

  // Recursively find all *.md files under memory/ directory
  const memoryDirPath = path.join(workspaceDir, MEMORY_DIR);
  if (fs.existsSync(memoryDirPath) && fs.statSync(memoryDirPath).isDirectory()) {
    collectMarkdownFiles(memoryDirPath, files);
  }

  // Sort by modification time (newest first)
  files.sort((a, b) => b.mtime - a.mtime);

  return files.map((f) => f.path);
}

/// Recursively collect *.md files from a directory.
function collectMarkdownFiles(
  dirPath: string,
  results: Array<{ path: string; mtime: number }>,
): void {
  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(dirPath, { withFileTypes: true });
  } catch {
    return; // Skip directories we can't read
  }

  for (const entry of entries) {
    const fullPath = path.join(dirPath, entry.name);
    if (entry.isDirectory()) {
      collectMarkdownFiles(fullPath, results);
    } else if (entry.isFile() && entry.name.endsWith(".md")) {
      try {
        const stat = fs.statSync(fullPath);
        results.push({ path: fullPath, mtime: stat.mtimeMs });
      } catch {
        // Skip files we can't stat
      }
    }
  }
}

/// Check if two paths refer to the same file (handles case-insensitive filesystems).
function isSameFile(pathA: string, pathB: string): boolean {
  try {
    const statA = fs.statSync(pathA);
    const statB = fs.statSync(pathB);
    return statA.ino === statB.ino && statA.dev === statB.dev;
  } catch {
    return false;
  }
}

// -- Parsing --

/// Strip YAML front matter from markdown content.
/// Returns the content without the leading `---\n...\n---\n` block.
export function stripFrontMatter(content: string): string {
  if (!content.startsWith("---")) return content;

  // Find the closing ---
  const endIndex = content.indexOf("\n---", 3);
  if (endIndex === -1) return content;

  // Skip past the closing --- and any trailing newline
  const afterFrontMatter = endIndex + 4; // "\n---".length = 4
  if (afterFrontMatter >= content.length) return "";
  return content.slice(afterFrontMatter).replace(/^\n/, "");
}

/// Parse a markdown file into sections based on headings.
/// Each section becomes a potential memory entry.
export function parseMarkdownSections(content: string, sourceFile: string): MemorySection[] {
  const cleaned = stripFrontMatter(content);
  if (!cleaned.trim()) return [];

  const lines = cleaned.split("\n");
  const sections: MemorySection[] = [];
  let currentHeading = "";
  let currentLines: string[] = [];

  for (const line of lines) {
    // Match markdown headings (## or ### -- skip # which is usually the doc title)
    const headingMatch = line.match(/^(#{1,4})\s+(.+)$/);
    if (headingMatch) {
      // Save previous section
      if (currentLines.length > 0) {
        const content = currentLines.join("\n").trim();
        if (content) {
          sections.push({
            heading: currentHeading || "general",
            content,
            sourceFile,
          });
        }
      }
      currentHeading = headingMatch[2].trim();
      currentLines = [];
    } else {
      currentLines.push(line);
    }
  }

  // Save final section
  if (currentLines.length > 0) {
    const sectionContent = currentLines.join("\n").trim();
    if (sectionContent) {
      sections.push({
        heading: currentHeading || "general",
        content: sectionContent,
        sourceFile,
      });
    }
  }

  return sections;
}

/// Derive a category from a memory section heading.
/// Maps common heading patterns to stable category names for IC vault storage.
export function deriveCategory(heading: string): string {
  const lower = heading.toLowerCase();

  if (lower.includes("preference") || lower.includes("pref")) return "preferences";
  if (lower.includes("decision") || lower.includes("decided")) return "decisions";
  if (lower.includes("context") || lower.includes("state") || lower.includes("status"))
    return "context";
  if (lower.includes("identity") || lower.includes("user") || lower.includes("about me"))
    return "identity";
  if (lower.includes("tool") || lower.includes("command") || lower.includes("workflow"))
    return "tools";
  if (lower.includes("convention") || lower.includes("style") || lower.includes("pattern"))
    return "conventions";
  if (lower.includes("lesson") || lower.includes("learned") || lower.includes("insight"))
    return "lessons";
  if (lower.includes("blocker") || lower.includes("issue") || lower.includes("bug"))
    return "issues";
  if (lower.includes("todo") || lower.includes("task") || lower.includes("next"))
    return "tasks";
  if (lower.includes("project") || lower.includes("architecture")) return "project";

  // Daily note files (e.g. 2026-02-20.md) get "daily" category
  if (/^\d{4}-\d{2}-\d{2}$/.test(heading)) return "daily";

  return "general";
}

/// Derive a stable key for a memory entry.
/// Keys must be unique within the vault and deterministic for the same content source.
export function deriveKey(heading: string, sourceFile: string): string {
  // Use the filename (without extension) + heading to create a stable key
  const basename = path.basename(sourceFile, ".md");
  const sanitized = heading
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 60);

  return `${basename}/${sanitized || "general"}`;
}

// -- Main API --

/// Read all local OpenClaw memory files and parse them into LocalMemory entries.
/// This is the primary entry point used by hooks and CLI commands.
export function readLocalMemories(workspaceDir?: string): LocalMemory[] {
  const workspace = resolveWorkspaceDir(workspaceDir);
  const files = findMemoryFiles(workspace);
  const nowMs = Date.now();
  const memories: LocalMemory[] = [];
  const seenKeys = new Set<string>();

  for (const filePath of files) {
    let content: string;
    try {
      content = fs.readFileSync(filePath, "utf-8");
    } catch {
      continue; // Skip files we can't read
    }

    if (!content.trim()) continue;

    const sections = parseMarkdownSections(content, filePath);

    for (const section of sections) {
      const key = deriveKey(section.heading, filePath);
      const category = deriveCategory(section.heading);

      // Deduplicate by key (first occurrence wins -- files are sorted newest-first)
      if (seenKeys.has(key)) continue;
      seenKeys.add(key);

      // Get file mtime for timestamp
      let mtimeMs = nowMs;
      try {
        const stat = fs.statSync(filePath);
        mtimeMs = stat.mtimeMs;
      } catch {
        // Use now as fallback
      }

      memories.push({
        key,
        category,
        content: section.content,
        metadata: JSON.stringify({
          heading: section.heading,
          sourceFile: path.relative(workspace, filePath),
        }),
        createdAt: mtimeMs,
        updatedAt: mtimeMs,
      });
    }
  }

  return memories;
}

/// Extract memory-worthy content from raw agent messages.
/// Used by before_compaction and agent_end hooks to capture conversation memories
/// before they are lost to compaction or session end.
///
/// Messages are `unknown[]` from the OpenClaw plugin API -- typically arrays of
/// objects with `role` and `content` fields.
export function extractMemoriesFromMessages(messages: unknown[]): LocalMemory[] {
  const nowMs = Date.now();
  const memories: LocalMemory[] = [];

  // Extract assistant messages that contain memory-worthy patterns
  for (const msg of messages) {
    if (!isMessageObject(msg)) continue;
    if (msg.role !== "assistant") continue;

    const content = extractTextContent(msg.content);
    if (!content) continue;

    // Look for explicit memory markers or structured information
    const memoryBlocks = findMemoryBlocks(content);
    for (const block of memoryBlocks) {
      memories.push({
        key: `conversation/${nowMs}-${memories.length}`,
        category: block.category,
        content: block.content,
        metadata: JSON.stringify({ source: "conversation", extractedAt: nowMs }),
        createdAt: nowMs,
        updatedAt: nowMs,
      });
    }
  }

  return memories;
}

// -- Message parsing helpers --

/// Type guard for message objects with role and content.
function isMessageObject(
  msg: unknown,
): msg is { role: string; content: unknown } {
  return (
    typeof msg === "object" &&
    msg !== null &&
    "role" in msg &&
    typeof (msg as Record<string, unknown>).role === "string"
  );
}

/// Extract text content from a message content field.
/// Handles both string content and array-of-blocks content.
function extractTextContent(content: unknown): string {
  if (typeof content === "string") return content;

  if (Array.isArray(content)) {
    return content
      .filter(
        (block): block is { type: "text"; text: string } =>
          typeof block === "object" &&
          block !== null &&
          "type" in block &&
          block.type === "text" &&
          "text" in block &&
          typeof block.text === "string",
      )
      .map((block) => block.text)
      .join("\n");
  }

  return "";
}

/// Represents a block of memory-worthy content extracted from a conversation.
interface MemoryBlock {
  category: string;
  content: string;
}

/// Find blocks of memory-worthy content in assistant messages.
/// Looks for patterns that indicate the assistant has captured or stated
/// important information worth persisting.
function findMemoryBlocks(text: string): MemoryBlock[] {
  const blocks: MemoryBlock[] = [];

  // Pattern 1: Explicit memory write markers
  // Common patterns: "I'll remember that...", "Noted:", "Key decision:", etc.
  const memoryPatterns = [
    { pattern: /(?:^|\n)(?:key decision|decision)[:\s]+(.+?)(?:\n\n|\n(?=[#*-])|\n$|$)/gis, category: "decisions" },
    { pattern: /(?:^|\n)(?:noted|i'll remember|remembering)[:\s]+(.+?)(?:\n\n|\n(?=[#*-])|\n$|$)/gis, category: "general" },
    { pattern: /(?:^|\n)(?:preference|your preference)[:\s]+(.+?)(?:\n\n|\n(?=[#*-])|\n$|$)/gis, category: "preferences" },
    { pattern: /(?:^|\n)(?:lesson learned|takeaway)[:\s]+(.+?)(?:\n\n|\n(?=[#*-])|\n$|$)/gis, category: "lessons" },
    { pattern: /(?:^|\n)(?:blocker|blocked by|issue)[:\s]+(.+?)(?:\n\n|\n(?=[#*-])|\n$|$)/gis, category: "issues" },
  ];

  for (const { pattern, category } of memoryPatterns) {
    let match: RegExpExecArray | null;
    while ((match = pattern.exec(text)) !== null) {
      const content = match[1].trim();
      if (content.length >= 10 && content.length <= 2000) {
        blocks.push({ category, content });
      }
    }
  }

  // Pattern 2: Markdown sections written by the assistant that look like memory content.
  // Only capture if the text has structured memory-like patterns (headings with bullets).
  const sectionPattern = /(?:^|\n)(#{1,3}\s+.+)\n((?:[-*]\s+.+\n?)+)/g;
  let sectionMatch: RegExpExecArray | null;
  while ((sectionMatch = sectionPattern.exec(text)) !== null) {
    const heading = sectionMatch[1].replace(/^#+\s+/, "").trim();
    const body = sectionMatch[2].trim();
    if (body.length >= 10 && body.length <= 2000) {
      blocks.push({
        category: deriveCategory(heading),
        content: `${heading}\n${body}`,
      });
    }
  }

  return blocks;
}

/// Build a search-optimized prompt context string from vault memories.
/// Used by the before_agent_start hook to inject relevant IC vault memories
/// as prependContext before the agent starts processing.
export function formatMemoriesAsContext(
  memories: Array<{ key: string; category: string; content: Uint8Array | string }>,
  maxTokenEstimate: number = 4000,
): string {
  if (memories.length === 0) return "";

  const lines: string[] = [
    "## Recalled from IC Sovereign Memory Vault",
    "",
  ];

  let estimatedTokens = 10; // header overhead

  for (const mem of memories) {
    const content =
      typeof mem.content === "string"
        ? mem.content
        : new TextDecoder().decode(mem.content);

    // Rough token estimate: ~4 chars per token
    const entryTokens = Math.ceil((mem.key.length + mem.category.length + content.length) / 4);
    if (estimatedTokens + entryTokens > maxTokenEstimate) break;

    lines.push(`### [${mem.category}] ${mem.key}`);
    lines.push(content);
    lines.push("");

    estimatedTokens += entryTokens;
  }

  return lines.join("\n");
}

/// Derive search terms from a user prompt for vault recall.
/// Extracts keywords and potential categories to search for relevant memories.
export function deriveSearchTerms(prompt: string): {
  categories: string[];
  prefixes: string[];
} {
  const lower = prompt.toLowerCase();
  const categories: string[] = [];
  const prefixes: string[] = [];

  // Map prompt keywords to vault categories
  const categoryKeywords: Array<{ keywords: string[]; category: string }> = [
    { keywords: ["prefer", "preference", "like", "want", "style"], category: "preferences" },
    { keywords: ["decide", "decided", "decision", "chose", "agreed"], category: "decisions" },
    { keywords: ["project", "architecture", "design", "structure"], category: "project" },
    { keywords: ["who am i", "my name", "about me", "identity"], category: "identity" },
    { keywords: ["tool", "command", "workflow", "setup", "config"], category: "tools" },
    { keywords: ["convention", "pattern", "standard", "rule"], category: "conventions" },
    { keywords: ["lesson", "learned", "mistake", "insight"], category: "lessons" },
    { keywords: ["issue", "bug", "blocker", "problem", "error"], category: "issues" },
    { keywords: ["todo", "task", "next", "plan"], category: "tasks" },
    { keywords: ["context", "state", "status", "progress", "where"], category: "context" },
    { keywords: ["yesterday", "today", "last time", "previous", "session"], category: "daily" },
  ];

  for (const { keywords, category } of categoryKeywords) {
    if (keywords.some((kw) => lower.includes(kw))) {
      categories.push(category);
    }
  }

  // Extract potential key prefixes from quoted terms or capitalized words
  const quotedTerms = prompt.match(/"([^"]+)"/g);
  if (quotedTerms) {
    for (const term of quotedTerms) {
      const cleaned = term
        .replace(/"/g, "")
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, "-")
        .replace(/^-+|-+$/g, "");
      if (cleaned.length >= 2) {
        prefixes.push(cleaned);
      }
    }
  }

  // If no specific categories matched, search broadly
  if (categories.length === 0) {
    // Return empty to trigger a broad recall
    return { categories: [], prefixes };
  }

  return { categories, prefixes };
}
