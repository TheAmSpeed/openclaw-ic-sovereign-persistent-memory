import Types "Types";
import Array "mo:base/Array";
import Buffer "mo:base/Buffer";
import Nat "mo:base/Nat";
import Int "mo:base/Int";
import Text "mo:base/Text";
import Time "mo:base/Time";
import Trie "mo:base/Trie";
import Result "mo:base/Result";
import Principal "mo:base/Principal";
import ExperimentalCycles "mo:base/ExperimentalCycles";


/// Per-user persistent vault canister.
/// Uses Trie (functional, stable) for maps, Buffer for audit log.
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
  // All vars implicitly stable (EOP). Using Trie for stable key-value maps.

  let owner : Principal = initOwner;

  var memories : Trie.Trie<Text, Types.MemoryEntry> = Trie.empty();
  var sessions : Trie.Trie<Text, Types.SessionEntry> = Trie.empty();

  // Immutable audit log -- append-only, never modified.
  // Uses Buffer for O(1) amortized appends (replaces O(n) Array.append).
  var auditLogBuf : Buffer.Buffer<Types.AuditEntry> = Buffer.Buffer<Types.AuditEntry>(64);

  var lastUpdated : Int = 0;

  // Track sizes separately for O(1) lookups (Trie doesn't have a .size() method)
  var memoriesCount : Nat = 0;
  var sessionsCount : Nat = 0;

  // Running bytesUsed counter -- maintained incrementally instead of O(n) recompute
  var bytesUsed : Nat = 0;

  // Category counts -- maintained incrementally instead of O(n) recompute
  var categoryCounts : Trie.Trie<Text, Nat> = Trie.empty();

  // Category max updatedAt -- maintained incrementally for O(1) categoryChecksum
  var categoryMaxUpdated : Trie.Trie<Text, Int> = Trie.empty();

  // -- Trie key helpers --

  func textKey(t : Text) : Trie.Key<Text> {
    { key = t; hash = Text.hash(t) };
  };

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
    let current = switch (Trie.get(categoryCounts, textKey(category), Text.equal)) {
      case (?n) { n };
      case null { 0 };
    };
    categoryCounts := Trie.put(categoryCounts, textKey(category), Text.equal, current + 1).0;
  };

  /// Decrement category count for a category. Removes entry if count reaches 0.
  func decrementCategory(category : Text) {
    switch (Trie.get(categoryCounts, textKey(category), Text.equal)) {
      case (?n) {
        if (n <= 1) {
          categoryCounts := Trie.remove(categoryCounts, textKey(category), Text.equal).0;
          categoryMaxUpdated := Trie.remove(categoryMaxUpdated, textKey(category), Text.equal).0;
        } else {
          categoryCounts := Trie.put(categoryCounts, textKey(category), Text.equal, n - 1).0;
        };
      };
      case null {}; // shouldn't happen, but defensive
    };
  };

  /// Update the max updatedAt for a category if the given timestamp is newer.
  func updateCategoryMaxUpdated(category : Text, updatedAt : Int) {
    let current = switch (Trie.get(categoryMaxUpdated, textKey(category), Text.equal)) {
      case (?ts) { ts };
      case null { 0 };
    };
    if (updatedAt > current) {
      categoryMaxUpdated := Trie.put(categoryMaxUpdated, textKey(category), Text.equal, updatedAt).0;
    };
  };

  /// Recompute max updatedAt for a category by scanning its entries.
  /// Only needed on delete when the deleted entry might have been the max.
  func recomputeCategoryMaxUpdated(category : Text) {
    var maxUpdated : Int = 0;
    for ((_, entry) in Trie.iter(memories)) {
      if (entry.category == category and entry.updatedAt > maxUpdated) {
        maxUpdated := entry.updatedAt;
      };
    };
    if (maxUpdated > 0) {
      categoryMaxUpdated := Trie.put(categoryMaxUpdated, textKey(category), Text.equal, maxUpdated).0;
    } else {
      categoryMaxUpdated := Trie.remove(categoryMaxUpdated, textKey(category), Text.equal).0;
    };
  };

  /// Get unique categories from the tracked category counts in O(c) where c = number of categories.
  func getUniqueCategories() : [Text] {
    Trie.toArray<Text, Nat, Text>(categoryCounts, func(k, _) { k });
  };

  /// Append an entry to the immutable audit log with FIFO eviction.
  func appendAudit(entry : Types.AuditEntry) {
    // FIFO eviction: if at max size, remove oldest 10% to amortize
    if (auditLogBuf.size() >= MAX_AUDIT_LOG_SIZE) {
      let evictCount = MAX_AUDIT_LOG_SIZE / 10; // remove 10%
      // Decrement bytesUsed for evicted entries
      let evictedBytes = evictCount * 128;
      bytesUsed := if (bytesUsed >= evictedBytes) { bytesUsed - evictedBytes } else { 0 };

      let remaining = auditLogBuf.size() - evictCount;
      let newBuf = Buffer.Buffer<Types.AuditEntry>(remaining + 64);
      var i = evictCount;
      while (i < auditLogBuf.size()) {
        newBuf.add(auditLogBuf.get(i));
        i += 1;
      };
      auditLogBuf := newBuf;
    };
    auditLogBuf.add(entry);
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
    if (key.size() > MAX_KEY_SIZE) { return ?"key exceeds " # Nat.toText(MAX_KEY_SIZE) # " byte limit" };
    if (category.size() > MAX_CATEGORY_SIZE) { return ?"category exceeds " # Nat.toText(MAX_CATEGORY_SIZE) # " byte limit" };
    if (content.size() > MAX_CONTENT_SIZE) { return ?"content exceeds " # Nat.toText(MAX_CONTENT_SIZE) # " byte limit (1 MB)" };
    if (metadata.size() > MAX_METADATA_SIZE) { return ?"metadata exceeds " # Nat.toText(MAX_METADATA_SIZE) # " byte limit (64 KB)" };
    null;
  };

  /// Validate session input sizes. Returns error text if invalid, null if OK.
  func validateSessionInput(sessionId : Text, data : Blob) : ?Text {
    if (sessionId.size() > MAX_KEY_SIZE) { return ?"sessionId exceeds " # Nat.toText(MAX_KEY_SIZE) # " byte limit" };
    if (data.size() > MAX_SESSION_DATA_SIZE) { return ?"session data exceeds " # Nat.toText(MAX_SESSION_DATA_SIZE) # " byte limit (1 MB)" };
    null;
  };

  /// Build VaultStats in O(c) where c = number of categories (not O(n) over all entries).
  func buildStats() : Types.VaultStats {
    {
      totalMemories = memoriesCount;
      totalSessions = sessionsCount;
      categories = getUniqueCategories();
      bytesUsed = bytesUsed;
      cycleBalance = ExperimentalCycles.balance();
      lastUpdated = lastUpdated;
    };
  };

  /// Get recent memories sorted by updatedAt (most recent first), limited.
  func getRecentMemories(limit : Nat) : [Types.MemoryEntry] {
    let all = Trie.toArray<Text, Types.MemoryEntry, Types.MemoryEntry>(
      memories,
      func(_, v) { v },
    );
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
    let all = Trie.toArray<Text, Types.SessionEntry, Types.SessionEntry>(
      sessions,
      func(_, v) { v },
    );
    let sorted = Array.sort<Types.SessionEntry>(all, func(a, b) {
      if (a.startedAt > b.startedAt) { #less }
      else if (a.startedAt < b.startedAt) { #greater }
      else { #equal };
    });
    let resultSize = if (sorted.size() < limit) { sorted.size() } else { limit };
    Array.tabulate<Types.SessionEntry>(resultSize, func(i) { sorted[i] });
  };

  /// Simple checksum for a category's entries: count:maxUpdatedAt.
  /// O(1) using incrementally maintained categoryCounts and categoryMaxUpdated Tries.
  func categoryChecksum(category : Text) : Text {
    let count = switch (Trie.get(categoryCounts, textKey(category), Text.equal)) {
      case (?n) { n };
      case null { 0 };
    };
    let maxUpdated = switch (Trie.get(categoryMaxUpdated, textKey(category), Text.equal)) {
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
    let existing = Trie.get(memories, textKey(key), Text.equal);
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

    let (newMemories, old) = Trie.put(memories, textKey(key), Text.equal, newEntry);
    memories := newMemories;

    // Update counts, bytesUsed, and categoryMaxUpdated
    switch (old) {
      case null {
        memoriesCount += 1;
        incrementCategory(category);
        bytesUsed += memoryEntrySize(newEntry);
      };
      case (?oldEntry) {
        // Category may have changed
        if (oldEntry.category != category) {
          decrementCategory(oldEntry.category);
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

    let existing = Trie.get(memories, textKey(key), Text.equal);
    switch (existing) {
      case (?removed) {
        let (newMemories, _) = Trie.remove(memories, textKey(key), Text.equal);
        memories := newMemories;

        // Defensive underflow protection
        if (memoriesCount > 0) { memoriesCount -= 1 };

        // decrementCategory removes categoryMaxUpdated if count reaches 0;
        // otherwise recompute since deleted entry may have been the max.
        let catCount = switch (Trie.get(categoryCounts, textKey(removed.category), Text.equal)) {
          case (?n) { n };
          case null { 0 };
        };
        decrementCategory(removed.category);
        if (catCount > 1) {
          // Category still has entries — recompute max since we may have removed the max entry
          recomputeCategoryMaxUpdated(removed.category);
        };

        // Adjust bytesUsed
        let removedSize = memoryEntrySize(removed);
        bytesUsed := if (bytesUsed >= removedSize) { bytesUsed - removedSize } else { 0 };

        let now = Time.now();
        lastUpdated := now;
        appendAudit({
          timestamp = now;
          action = #delete;
          caller = caller;
          key = ?key;
          category = ?removed.category;
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
    let errorsBuf = Buffer.Buffer<Text>(4);

    // Sync memories
    for (input in memoryInputs.vals()) {
      if (input.key == "" or input.category == "") {
        errorsBuf.add("Skipped memory with empty key or category");
        skipped += 1;
      } else {
        // Validate input sizes
        switch (validateMemoryInput(input.key, input.category, input.content, input.metadata)) {
          case (?errMsg) {
            errorsBuf.add("Skipped " # input.key # ": " # errMsg);
            skipped += 1;
          };
          case null {
            let existing = Trie.get(memories, textKey(input.key), Text.equal);
            let shouldStore = switch (existing) {
              case (?e) { input.updatedAt > e.updatedAt };
              case null { true };
            };
            if (shouldStore) {
              let isNew = switch (existing) {
                case null { true };
                case _ { false };
              };
              let newEntry : Types.MemoryEntry = {
                key = input.key;
                category = input.category;
                content = input.content;
                metadata = input.metadata;
                createdAt = input.createdAt;
                updatedAt = input.updatedAt;
              };
              let (newMem, old) = Trie.put(memories, textKey(input.key), Text.equal, newEntry);
              memories := newMem;

              if (isNew) {
                memoriesCount += 1;
                incrementCategory(input.category);
                bytesUsed += memoryEntrySize(newEntry);
              } else {
                switch (old) {
                  case (?oldEntry) {
                    if (oldEntry.category != input.category) {
                      decrementCategory(oldEntry.category);
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
                  case null {};
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
    for (input in sessionInputs.vals()) {
      if (input.sessionId == "") {
        errorsBuf.add("Skipped session with empty sessionId");
        skipped += 1;
      } else {
        // Validate session input sizes
        switch (validateSessionInput(input.sessionId, input.data)) {
          case (?errMsg) {
            errorsBuf.add("Skipped session " # input.sessionId # ": " # errMsg);
            skipped += 1;
          };
          case null {
            let existing = Trie.get(sessions, textKey(input.sessionId), Text.equal);
            let shouldStore = switch (existing) {
              case (?e) { input.startedAt > e.startedAt };
              case null { true };
            };
            if (shouldStore) {
              let isNew = switch (existing) {
                case null { true };
                case _ { false };
              };
              let newSession : Types.SessionEntry = {
                sessionId = input.sessionId;
                data = input.data;
                startedAt = input.startedAt;
                endedAt = input.endedAt;
              };
              let (newSess, old) = Trie.put(sessions, textKey(input.sessionId), Text.equal, newSession);
              sessions := newSess;

              if (isNew) {
                sessionsCount += 1;
                bytesUsed += sessionEntrySize(newSession);
              } else {
                switch (old) {
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
                  case null {};
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
      errors = Buffer.toArray(errorsBuf);
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

    let existing = Trie.get(sessions, textKey(sessionId), Text.equal);

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

    let isNew = switch (existing) {
      case null { true };
      case _ { false };
    };

    let newSession : Types.SessionEntry = {
      sessionId = sessionId;
      data = data;
      startedAt = startedAt;
      endedAt = endedAt;
    };

    let (newSess, old) = Trie.put(sessions, textKey(sessionId), Text.equal, newSession);
    sessions := newSess;

    if (isNew) {
      sessionsCount += 1;
      bytesUsed += sessionEntrySize(newSession);
    } else {
      switch (old) {
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
        case null {};
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
    #ok(Trie.get(memories, textKey(key), Text.equal));
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
    let size = auditLogBuf.size();
    if (offset >= size) { return #ok([]) };
    let end = if (offset + limit > size) { size } else { offset + limit };
    #ok(Array.tabulate<Types.AuditEntry>(end - offset, func(i) { auditLogBuf.get(offset + i) }));
  };

  /// Get total audit log size.
  public query ({ caller }) func getAuditLogSize() : async Result.Result<Nat, Types.VaultError> {
    if (caller != owner) { return #err(#unauthorized) };
    #ok(auditLogBuf.size());
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

    // Collect all matches first
    let matchBuf = Buffer.Buffer<Types.MemoryEntry>(64);
    for ((_, entry) in Trie.iter(memories)) {
      let catMatch = switch (category) {
        case (?c) { entry.category == c };
        case null { true };
      };
      let prefixMatch = switch (prefix) {
        case (?p) { Text.startsWith(entry.key, #text p) };
        case null { true };
      };
      if (catMatch and prefixMatch) {
        matchBuf.add(entry);
      };
    };

    // Sort by updatedAt descending (most recent first)
    let matches = Buffer.toArray(matchBuf);
    let sorted = Array.sort<Types.MemoryEntry>(matches, func(a, b) {
      if (a.updatedAt > b.updatedAt) { #less }
      else if (a.updatedAt < b.updatedAt) { #greater }
      else { #equal };
    });

    // Take up to limit
    let resultSize = if (sorted.size() < limit) { sorted.size() } else { limit };
    #ok(Array.tabulate<Types.MemoryEntry>(resultSize, func(i) { sorted[i] }));
  };

  /// Get paginated sessions (most recent first).
  public composite query ({ caller }) func getSessions(
    offset : Nat,
    limit : Nat,
  ) : async Result.Result<[Types.SessionEntry], Types.VaultError> {
    if (caller != owner) { return #err(#unauthorized) };

    let all = Trie.toArray<Text, Types.SessionEntry, Types.SessionEntry>(
      sessions,
      func(_, v) { v },
    );
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
      memoriesCount = memoriesCount;
      sessionsCount = sessionsCount;
      categoryChecksums = checksums;
    });
  };
};
