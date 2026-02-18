import Types "Types";
import Array "mo:core/Array";
import Int "mo:core/Int";
import List "mo:core/List";
import Map "mo:core/Map";
import Nat "mo:core/Nat";
import Result "mo:core/Result";
import Text "mo:core/Text";
import Time "mo:core/Time";
import Cycles "mo:core/Cycles";
import Principal "mo:core/Principal";

/// Per-user persistent vault canister.
/// Uses Map (mutable B-tree, order 32) for key-value lookups.
/// Uses List (Brodnik resizable array) for the audit log -- amortized O(1) append, O(1) random access.
/// All vars persist across upgrades via Enhanced Orthogonal Persistence.
persistent actor class UserVault(initOwner : Principal) {

  // -- Constants --

  /// Maximum allowed sizes for input validation (DoS prevention)
  let MAX_KEY_SIZE : Nat = 256;
  let MAX_CATEGORY_SIZE : Nat = 128;
  let MAX_CONTENT_SIZE : Nat = 1_048_576;  // 1 MB
  let MAX_METADATA_SIZE : Nat = 65_536;    // 64 KB
  let MAX_SESSION_DATA_SIZE : Nat = 1_048_576; // 1 MB

  /// Maximum audit log entries before FIFO eviction
  let MAX_AUDIT_LOG_SIZE : Nat = 100_000;

  // -- State --
  // All vars implicitly stable (EOP). Map and List are stable types.

  let owner : Principal = initOwner;

  // Mutable B-tree maps -- add/remove/get mutate in-place, no reassignment needed.
  var memories : Map.Map<Text, Types.MemoryEntry> = Map.empty<Text, Types.MemoryEntry>();
  var sessions : Map.Map<Text, Types.SessionEntry> = Map.empty<Text, Types.SessionEntry>();

  // Immutable audit log -- append-only, never modified (except FIFO eviction of oldest entries).
  // List provides amortized O(1) append, O(1) random access, and is a stable type.
  var auditLog : List.List<Types.AuditEntry> = List.empty<Types.AuditEntry>();

  var lastUpdated : Int = 0;

  // Running bytesUsed counter -- maintained incrementally instead of O(n) recompute
  var bytesUsed : Nat = 0;

  // Category counts -- maintained incrementally instead of O(n) recompute
  var categoryCounts : Map.Map<Text, Nat> = Map.empty<Text, Nat>();

  // Category max updatedAt -- maintained incrementally for O(1) categoryChecksum
  var categoryMaxUpdated : Map.Map<Text, Int> = Map.empty<Text, Int>();

  // -- Internal helpers --

  /// Estimate byte size of a memory entry for bytesUsed tracking.
  func memoryEntrySize(entry : Types.MemoryEntry) : Nat {
    entry.key.size() + entry.category.size() + entry.content.size() + entry.metadata.size() + 32;
  };

  /// Estimate byte size of a session entry for bytesUsed tracking.
  func sessionEntrySize(session : Types.SessionEntry) : Nat {
    session.sessionId.size() + session.data.size() + 32;
  };

  /// Increment category count for a category.
  func incrementCategory(category : Text) {
    let current = switch (Map.get(categoryCounts, Text.compare, category)) {
      case (?n) { n };
      case null { 0 };
    };
    Map.add(categoryCounts, Text.compare, category, current + 1);
  };

  /// Decrement category count for a category. Removes entry if count reaches 0.
  func decrementCategory(category : Text) {
    switch (Map.get(categoryCounts, Text.compare, category)) {
      case (?n) {
        if (n <= 1) {
          Map.remove(categoryCounts, Text.compare, category);
          Map.remove(categoryMaxUpdated, Text.compare, category);
        } else {
          Map.add(categoryCounts, Text.compare, category, n - 1);
        };
      };
      case null {}; // shouldn't happen, but defensive
    };
  };

  /// Update the max updatedAt for a category if the given timestamp is newer.
  func updateCategoryMaxUpdated(category : Text, updatedAt : Int) {
    let current = switch (Map.get(categoryMaxUpdated, Text.compare, category)) {
      case (?ts) { ts };
      case null { 0 };
    };
    if (updatedAt > current) {
      Map.add(categoryMaxUpdated, Text.compare, category, updatedAt);
    };
  };

  /// Recompute max updatedAt for a category by scanning its entries.
  /// Only needed on delete when the deleted entry might have been the max.
  func recomputeCategoryMaxUpdated(category : Text) {
    var maxUpdated : Int = 0;
    for ((_, entry) in Map.entries(memories)) {
      if (entry.category == category and entry.updatedAt > maxUpdated) {
        maxUpdated := entry.updatedAt;
      };
    };
    if (maxUpdated > 0) {
      Map.add(categoryMaxUpdated, Text.compare, category, maxUpdated);
    } else {
      Map.remove(categoryMaxUpdated, Text.compare, category);
    };
  };

  /// Get unique categories from the tracked category counts in O(c) where c = number of categories.
  func getUniqueCategories() : [Text] {
    Array.fromIter<Text>(Map.keys(categoryCounts));
  };

  /// Append an entry to the immutable audit log with FIFO eviction.
  /// Uses List.add for amortized O(1) append.
  /// On eviction, rebuilds the list from a slice to remove the oldest 10%.
  func appendAudit(entry : Types.AuditEntry) {
    // FIFO eviction: if at max size, remove oldest 10% to amortize
    if (List.size(auditLog) >= MAX_AUDIT_LOG_SIZE) {
      let evictCount = MAX_AUDIT_LOG_SIZE / 10; // remove 10%
      // Decrement bytesUsed for evicted entries
      let evictedBytes = evictCount * 128;
      bytesUsed := if (bytesUsed >= evictedBytes) { bytesUsed - evictedBytes } else { 0 };

      // Rebuild list from remaining entries (skip oldest evictCount)
      let size = List.size(auditLog);
      let newLog = List.empty<Types.AuditEntry>();
      for (i in Nat.range(evictCount, size)) {
        List.add(newLog, List.at(auditLog, i));
      };
      auditLog := newLog;
    };
    List.add(auditLog, entry);
    // Update bytesUsed estimate for audit entries
    bytesUsed += 128;
  };

  /// Verify caller is vault owner. Logs access denial if not.
  func assertOwner(caller : Principal) : Bool {
    if (caller == owner) { return true };
    appendAudit({
      timestamp = Time.now();
      action = #accessDenied;
      caller = caller;
      key = null;
      category = null;
      details = ?"Unauthorized access attempt";
    });
    false;
  };

  /// Validate input sizes. Returns error text if invalid, null if OK.
  func validateMemoryInput(key : Text, category : Text, content : Blob, metadata : Text) : ?Text {
    if (key.size() > MAX_KEY_SIZE) { return ?("key exceeds " # Nat.toText(MAX_KEY_SIZE) # " byte limit") };
    if (category.size() > MAX_CATEGORY_SIZE) { return ?("category exceeds " # Nat.toText(MAX_CATEGORY_SIZE) # " byte limit") };
    if (content.size() > MAX_CONTENT_SIZE) { return ?("content exceeds " # Nat.toText(MAX_CONTENT_SIZE) # " byte limit (1 MB)") };
    if (metadata.size() > MAX_METADATA_SIZE) { return ?("metadata exceeds " # Nat.toText(MAX_METADATA_SIZE) # " byte limit (64 KB)") };
    null;
  };

  /// Validate session input sizes. Returns error text if invalid, null if OK.
  func validateSessionInput(sessionId : Text, data : Blob) : ?Text {
    if (sessionId.size() > MAX_KEY_SIZE) { return ?("sessionId exceeds " # Nat.toText(MAX_KEY_SIZE) # " byte limit") };
    if (data.size() > MAX_SESSION_DATA_SIZE) { return ?("session data exceeds " # Nat.toText(MAX_SESSION_DATA_SIZE) # " byte limit (1 MB)") };
    null;
  };

  /// Build VaultStats in O(c) where c = number of categories (not O(n) over all entries).
  func buildStats() : Types.VaultStats {
    {
      totalMemories = Map.size(memories);
      totalSessions = Map.size(sessions);
      categories = getUniqueCategories();
      bytesUsed = bytesUsed;
      cycleBalance = Cycles.balance();
      lastUpdated = lastUpdated;
    };
  };

  /// Get recent memories sorted by updatedAt (most recent first), limited.
  func getRecentMemories(limit : Nat) : [Types.MemoryEntry] {
    let all = Array.fromIter<Types.MemoryEntry>(Map.values(memories));
    let sorted = Array.sort<Types.MemoryEntry>(all, func(a, b) {
      if (a.updatedAt > b.updatedAt) { #less }
      else if (a.updatedAt < b.updatedAt) { #greater }
      else { #equal };
    });
    let resultSize = if (sorted.size() < limit) { sorted.size() } else { limit };
    Array.tabulate<Types.MemoryEntry>(resultSize, func(i) { sorted[i] });
  };

  /// Get recent sessions sorted by startedAt (most recent first), limited.
  func getRecentSessions(limit : Nat) : [Types.SessionEntry] {
    let all = Array.fromIter<Types.SessionEntry>(Map.values(sessions));
    let sorted = Array.sort<Types.SessionEntry>(all, func(a, b) {
      if (a.startedAt > b.startedAt) { #less }
      else if (a.startedAt < b.startedAt) { #greater }
      else { #equal };
    });
    let resultSize = if (sorted.size() < limit) { sorted.size() } else { limit };
    Array.tabulate<Types.SessionEntry>(resultSize, func(i) { sorted[i] });
  };

  /// Simple checksum for a category's entries: count:maxUpdatedAt.
  /// O(1) using incrementally maintained categoryCounts and categoryMaxUpdated Maps.
  func categoryChecksum(category : Text) : Text {
    let count = switch (Map.get(categoryCounts, Text.compare, category)) {
      case (?n) { n };
      case null { 0 };
    };
    let maxUpdated = switch (Map.get(categoryMaxUpdated, Text.compare, category)) {
      case (?ts) { ts };
      case null { 0 };
    };
    Nat.toText(count) # ":" # Int.toText(maxUpdated);
  };

  // -- UPDATE CALLS (cost cycles, require consensus) --

  /// Store or update a single memory entry.
  public shared ({ caller }) func store(
    key : Text,
    category : Text,
    content : Blob,
    metadata : Text,
  ) : async Result.Result<(), Types.VaultError> {
    if (not assertOwner(caller)) {
      return #err(#unauthorized);
    };
    if (key == "" or category == "") {
      return #err(#invalidInput("key and category must not be empty"));
    };

    // Validate input sizes
    switch (validateMemoryInput(key, category, content, metadata)) {
      case (?errMsg) { return #err(#invalidInput(errMsg)) };
      case null {};
    };

    let now = Time.now();
    let existing = Map.get(memories, Text.compare, key);
    let createdAt = switch (existing) {
      case (?e) { e.createdAt };
      case null { now };
    };

    let newEntry : Types.MemoryEntry = {
      key = key;
      category = category;
      content = content;
      metadata = metadata;
      createdAt = createdAt;
      updatedAt = now;
    };

    // Map.add replaces existing key if present. Use Map.take to get old value first.
    let old = Map.take(memories, Text.compare, key);
    Map.add(memories, Text.compare, key, newEntry);

    // Update counts, bytesUsed, and categoryMaxUpdated
    switch (old) {
      case null {
        incrementCategory(category);
        bytesUsed += memoryEntrySize(newEntry);
      };
      case (?oldEntry) {
        // Category may have changed
        if (oldEntry.category != category) {
          // Decrement old category and recompute its max if entries remain
          let oldCatCount = switch (Map.get(categoryCounts, Text.compare, oldEntry.category)) {
            case (?n) { n };
            case null { 0 };
          };
          decrementCategory(oldEntry.category);
          if (oldCatCount > 1) {
            recomputeCategoryMaxUpdated(oldEntry.category);
          };
          incrementCategory(category);
        };
        // Adjust bytesUsed: remove old, add new
        let oldSize = memoryEntrySize(oldEntry);
        let newSize = memoryEntrySize(newEntry);
        if (newSize >= oldSize) {
          bytesUsed += (newSize - oldSize);
        } else {
          let diff = oldSize - newSize;
          bytesUsed := if (bytesUsed >= diff) { bytesUsed - diff } else { 0 };
        };
      };
    };
    updateCategoryMaxUpdated(category, now);

    lastUpdated := now;

    appendAudit({
      timestamp = now;
      action = #store;
      caller = caller;
      key = ?key;
      category = ?category;
      details = null;
    });

    #ok(());
  };

  /// Delete a memory by key.
  public shared ({ caller }) func delete(key : Text) : async Result.Result<(), Types.VaultError> {
    if (not assertOwner(caller)) {
      return #err(#unauthorized);
    };

    // Map.take removes the key and returns the old value if present
    let removed = Map.take(memories, Text.compare, key);
    switch (removed) {
      case (?entry) {
        // Defensive underflow not needed: Map.size is authoritative.
        // But track category counts.

        // decrementCategory removes categoryMaxUpdated if count reaches 0;
        // otherwise recompute since deleted entry may have been the max.
        let catCount = switch (Map.get(categoryCounts, Text.compare, entry.category)) {
          case (?n) { n };
          case null { 0 };
        };
        decrementCategory(entry.category);
        if (catCount > 1) {
          // Category still has entries -- recompute max since we may have removed the max entry
          recomputeCategoryMaxUpdated(entry.category);
        };

        // Adjust bytesUsed
        let removedSize = memoryEntrySize(entry);
        bytesUsed := if (bytesUsed >= removedSize) { bytesUsed - removedSize } else { 0 };

        let now = Time.now();
        lastUpdated := now;
        appendAudit({
          timestamp = now;
          action = #delete;
          caller = caller;
          key = ?key;
          category = ?entry.category;
          details = null;
        });
        #ok(());
      };
      case null { #err(#notFound) };
    };
  };

  /// Bulk sync memories and sessions from local storage.
  /// Skips entries where the vault's version is newer (based on updatedAt).
  public shared ({ caller }) func bulkSync(
    memoryInputs : [Types.MemoryInput],
    sessionInputs : [Types.SessionInput],
  ) : async Result.Result<Types.SyncResult, Types.VaultError> {
    if (not assertOwner(caller)) {
      return #err(#unauthorized);
    };

    var stored : Nat = 0;
    var skipped : Nat = 0;
    var errors : [Text] = [];

    // Sync memories
    for (input in memoryInputs.values()) {
      if (input.key == "" or input.category == "") {
        errors := Array.concat(errors, ["Skipped memory with empty key or category"]);
        skipped += 1;
      } else {
        // Validate input sizes
        switch (validateMemoryInput(input.key, input.category, input.content, input.metadata)) {
          case (?errMsg) {
            errors := Array.concat(errors, ["Skipped " # input.key # ": " # errMsg]);
            skipped += 1;
          };
          case null {
            let existing = Map.get(memories, Text.compare, input.key);
            let shouldStore = switch (existing) {
              case (?e) { input.updatedAt > e.updatedAt };
              case null { true };
            };
            if (shouldStore) {
              let newEntry : Types.MemoryEntry = {
                key = input.key;
                category = input.category;
                content = input.content;
                metadata = input.metadata;
                createdAt = input.createdAt;
                updatedAt = input.updatedAt;
              };

              let old = Map.take(memories, Text.compare, input.key);
              Map.add(memories, Text.compare, input.key, newEntry);

              switch (old) {
                case null {
                  incrementCategory(input.category);
                  bytesUsed += memoryEntrySize(newEntry);
                };
                case (?oldEntry) {
                  if (oldEntry.category != input.category) {
                    // Category changed: decrement old, increment new.
                    // If old category still has entries, recompute its max
                    // since the moved entry may have been the max.
                    let oldCatCount = switch (Map.get(categoryCounts, Text.compare, oldEntry.category)) {
                      case (?n) { n };
                      case null { 0 };
                    };
                    decrementCategory(oldEntry.category);
                    if (oldCatCount > 1) {
                      recomputeCategoryMaxUpdated(oldEntry.category);
                    };
                    incrementCategory(input.category);
                  };
                  let oldSize = memoryEntrySize(oldEntry);
                  let newSize = memoryEntrySize(newEntry);
                  if (newSize >= oldSize) {
                    bytesUsed += (newSize - oldSize);
                  } else {
                    let diff = oldSize - newSize;
                    bytesUsed := if (bytesUsed >= diff) { bytesUsed - diff } else { 0 };
                  };
                };
              };
              updateCategoryMaxUpdated(input.category, input.updatedAt);
              stored += 1;
            } else {
              skipped += 1;
            };
          };
        };
      };
    };

    // Sync sessions
    for (input in sessionInputs.values()) {
      if (input.sessionId == "") {
        errors := Array.concat(errors, ["Skipped session with empty sessionId"]);
        skipped += 1;
      } else {
        // Validate session input sizes
        switch (validateSessionInput(input.sessionId, input.data)) {
          case (?errMsg) {
            errors := Array.concat(errors, ["Skipped session " # input.sessionId # ": " # errMsg]);
            skipped += 1;
          };
          case null {
            let existing = Map.get(sessions, Text.compare, input.sessionId);
            let shouldStore = switch (existing) {
              case (?e) { input.startedAt > e.startedAt };
              case null { true };
            };
            if (shouldStore) {
              let newSession : Types.SessionEntry = {
                sessionId = input.sessionId;
                data = input.data;
                startedAt = input.startedAt;
                endedAt = input.endedAt;
              };

              let old = Map.take(sessions, Text.compare, input.sessionId);
              Map.add(sessions, Text.compare, input.sessionId, newSession);

              switch (old) {
                case null {
                  bytesUsed += sessionEntrySize(newSession);
                };
                case (?oldSession) {
                  let oldSize = sessionEntrySize(oldSession);
                  let newSize = sessionEntrySize(newSession);
                  if (newSize >= oldSize) {
                    bytesUsed += (newSize - oldSize);
                  } else {
                    let diff = oldSize - newSize;
                    bytesUsed := if (bytesUsed >= diff) { bytesUsed - diff } else { 0 };
                  };
                };
              };
              stored += 1;
            } else {
              skipped += 1;
            };
          };
        };
      };
    };

    let now = Time.now();

    // Only advance lastUpdated if we actually stored something
    if (stored > 0) {
      lastUpdated := now;
    };

    appendAudit({
      timestamp = now;
      action = #bulkSync;
      caller = caller;
      key = null;
      category = null;
      details = ?("synced " # Nat.toText(stored) # " entries, skipped " # Nat.toText(skipped));
    });

    #ok({
      stored = stored;
      skipped = skipped;
      errors = errors;
    });
  };

  /// Store a session. Only overwrites if the new session is more recent.
  public shared ({ caller }) func storeSession(
    sessionId : Text,
    data : Blob,
    startedAt : Int,
    endedAt : Int,
  ) : async Result.Result<(), Types.VaultError> {
    if (not assertOwner(caller)) {
      return #err(#unauthorized);
    };
    if (sessionId == "") {
      return #err(#invalidInput("sessionId must not be empty"));
    };

    // Validate session input sizes
    switch (validateSessionInput(sessionId, data)) {
      case (?errMsg) { return #err(#invalidInput(errMsg)) };
      case null {};
    };

    let existing = Map.get(sessions, Text.compare, sessionId);

    // Only overwrite if newer (prevent stale session overwrites).
    // Uses AND logic: skip only if BOTH endedAt and startedAt are older-or-equal.
    // If either timestamp is newer, the incoming session is treated as an update.
    switch (existing) {
      case (?e) {
        if (endedAt <= e.endedAt and startedAt <= e.startedAt) {
          // Existing session is newer or same on both timestamps -- skip
          return #ok(());
        };
      };
      case null {};
    };

    let newSession : Types.SessionEntry = {
      sessionId = sessionId;
      data = data;
      startedAt = startedAt;
      endedAt = endedAt;
    };

    let old = Map.take(sessions, Text.compare, sessionId);
    Map.add(sessions, Text.compare, sessionId, newSession);

    switch (old) {
      case null {
        bytesUsed += sessionEntrySize(newSession);
      };
      case (?oldSession) {
        let oldSize = sessionEntrySize(oldSession);
        let newSize = sessionEntrySize(newSession);
        if (newSize >= oldSize) {
          bytesUsed += (newSize - oldSize);
        } else {
          let diff = oldSize - newSize;
          bytesUsed := if (bytesUsed >= diff) { bytesUsed - diff } else { 0 };
        };
      };
    };

    let now = Time.now();
    lastUpdated := now;

    appendAudit({
      timestamp = now;
      action = #store;
      caller = caller;
      key = ?sessionId;
      category = ?"session";
      details = null;
    });

    #ok(());
  };

  // -- QUERY CALLS (free, no consensus needed) --
  // All queries return Result types for graceful error handling instead of assert-trapping.

  /// Recall a specific memory by key.
  public query ({ caller }) func recall(key : Text) : async Result.Result<?Types.MemoryEntry, Types.VaultError> {
    if (caller != owner) { return #err(#unauthorized) };
    #ok(Map.get(memories, Text.compare, key));
  };

  /// Get vault statistics.
  public query ({ caller }) func getStats() : async Result.Result<Types.VaultStats, Types.VaultError> {
    if (caller != owner) { return #err(#unauthorized) };
    #ok(buildStats());
  };

  /// Get unique categories.
  public query ({ caller }) func getCategories() : async Result.Result<[Text], Types.VaultError> {
    if (caller != owner) { return #err(#unauthorized) };
    #ok(getUniqueCategories());
  };

  /// Get paginated audit log entries (chronological order).
  public query ({ caller }) func getAuditLog(offset : Nat, limit : Nat) : async Result.Result<[Types.AuditEntry], Types.VaultError> {
    if (caller != owner) { return #err(#unauthorized) };
    let size = List.size(auditLog);
    if (offset >= size) { return #ok([]) };
    let end = if (offset + limit > size) { size } else { offset + limit };
    #ok(Array.tabulate<Types.AuditEntry>(end - offset, func(i) { List.at(auditLog, offset + i) }));
  };

  /// Get total audit log size.
  public query ({ caller }) func getAuditLogSize() : async Result.Result<Nat, Types.VaultError> {
    if (caller != owner) { return #err(#unauthorized) };
    #ok(List.size(auditLog));
  };

  /// Get vault owner principal (owner-only to prevent privacy leak).
  public query ({ caller }) func getOwner() : async Result.Result<Principal, Types.VaultError> {
    if (caller != owner) { return #err(#unauthorized) };
    #ok(owner);
  };

  // -- COMPOSITE QUERIES (free, single round trip) --

  /// Dashboard: stats + recent memories + recent sessions in one call.
  public composite query ({ caller }) func getDashboard() : async Result.Result<Types.DashboardData, Types.VaultError> {
    if (caller != owner) { return #err(#unauthorized) };
    #ok({
      stats = buildStats();
      recentMemories = getRecentMemories(10);
      recentSessions = getRecentSessions(5);
    });
  };

  /// Search memories by category and/or key prefix, with limit.
  /// Results are sorted by updatedAt descending (most recent first).
  public composite query ({ caller }) func recallRelevant(
    category : ?Text,
    prefix : ?Text,
    limit : Nat,
  ) : async Result.Result<[Types.MemoryEntry], Types.VaultError> {
    if (caller != owner) { return #err(#unauthorized) };

    // Collect all matches into a list
    let matches = List.empty<Types.MemoryEntry>();
    for ((_, entry) in Map.entries(memories)) {
      let catMatch = switch (category) {
        case (?c) { entry.category == c };
        case null { true };
      };
      let prefixMatch = switch (prefix) {
        case (?p) { Text.startsWith(entry.key, #text p) };
        case null { true };
      };
      if (catMatch and prefixMatch) {
        List.add(matches, entry);
      };
    };

    // Sort by updatedAt descending (most recent first)
    let sorted = List.sort<Types.MemoryEntry>(matches, func(a, b) {
      if (a.updatedAt > b.updatedAt) { #less }
      else if (a.updatedAt < b.updatedAt) { #greater }
      else { #equal };
    });

    // Take up to limit
    let sortedSize = List.size(sorted);
    let resultSize = if (sortedSize < limit) { sortedSize } else { limit };
    #ok(Array.tabulate<Types.MemoryEntry>(resultSize, func(i) { List.at(sorted, i) }));
  };

  /// Get paginated sessions (most recent first).
  public composite query ({ caller }) func getSessions(
    offset : Nat,
    limit : Nat,
  ) : async Result.Result<[Types.SessionEntry], Types.VaultError> {
    if (caller != owner) { return #err(#unauthorized) };

    let all = Array.fromIter<Types.SessionEntry>(Map.values(sessions));
    let sorted = Array.sort<Types.SessionEntry>(all, func(a, b) {
      if (a.startedAt > b.startedAt) { #less }
      else if (a.startedAt < b.startedAt) { #greater }
      else { #equal };
    });

    if (offset >= sorted.size()) { return #ok([]) };
    let end = if (offset + limit > sorted.size()) { sorted.size() } else { offset + limit };
    #ok(Array.tabulate<Types.SessionEntry>(end - offset, func(i) { sorted[offset + i] }));
  };

  /// Sync manifest: checksums for differential sync.
  public composite query ({ caller }) func getSyncManifest() : async Result.Result<Types.SyncManifest, Types.VaultError> {
    if (caller != owner) { return #err(#unauthorized) };
    let cats = getUniqueCategories();
    let checksums = Array.map<Text, (Text, Text)>(cats, func(cat) {
      (cat, categoryChecksum(cat));
    });
    #ok({
      lastUpdated = lastUpdated;
      memoriesCount = Map.size(memories);
      sessionsCount = Map.size(sessions);
      categoryChecksums = checksums;
    });
  };
};
