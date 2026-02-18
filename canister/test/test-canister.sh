#!/bin/bash
# Comprehensive test suite for IC Memory Vault canisters.
# Tests UserVault and Factory via dfx canister call against local replica.
# Run from the canister/ directory: bash test/test-canister.sh

set -euo pipefail

export PATH="$HOME/Library/Application Support/org.dfinity.dfx/bin:$PATH"

VAULT_ID="uxrrr-q7777-77774-qaaaq-cai"
PASS=0
FAIL=0
TOTAL=0

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

assert_contains() {
  local test_name="$1"
  local actual="$2"
  local expected="$3"
  TOTAL=$((TOTAL + 1))
  if echo "$actual" | grep -q "$expected"; then
    echo -e "  ${GREEN}PASS${NC}: $test_name"
    PASS=$((PASS + 1))
  else
    echo -e "  ${RED}FAIL${NC}: $test_name"
    echo -e "    Expected to contain: $expected"
    echo -e "    Actual: $actual"
    FAIL=$((FAIL + 1))
  fi
}

assert_equals() {
  local test_name="$1"
  local actual="$2"
  local expected="$3"
  TOTAL=$((TOTAL + 1))
  if [ "$actual" = "$expected" ]; then
    echo -e "  ${GREEN}PASS${NC}: $test_name"
    PASS=$((PASS + 1))
  else
    echo -e "  ${RED}FAIL${NC}: $test_name"
    echo -e "    Expected: $expected"
    echo -e "    Actual: $actual"
    FAIL=$((FAIL + 1))
  fi
}

call() {
  dfx canister call "$VAULT_ID" "$@" 2>&1
}

echo ""
echo "=== IC Memory Vault - Canister Test Suite ==="
echo ""

# ----------------------------------------
echo "--- Test Group 1: Initial State ---"

result=$(call getStats)
assert_contains "initial stats: 0 memories" "$result" "totalMemories = 0"
assert_contains "initial stats: 0 sessions" "$result" "totalSessions = 0"
assert_contains "initial stats: lastUpdated = 0" "$result" "lastUpdated = 0"

result=$(call getCategories)
assert_equals "initial categories empty" "$result" "(vec {})"

result=$(call getAuditLogSize)
assert_equals "initial audit log empty" "$result" "(0 : nat)"

result=$(call getOwner)
OWNER_PRINCIPAL=$(dfx identity get-principal)
assert_contains "owner matches default identity" "$result" "$OWNER_PRINCIPAL"

# ----------------------------------------
echo ""
echo "--- Test Group 2: Store and Recall ---"

result=$(call store '("test-key-1", "facts", blob "hello world", "{\"source\":\"test\"}")')
assert_contains "store returns ok" "$result" "ok"

result=$(call recall '("test-key-1")')
assert_contains "recall returns content" "$result" "hello world"
assert_contains "recall returns category" "$result" "facts"
assert_contains "recall returns metadata" "$result" "source"

result=$(call recall '("nonexistent")')
assert_equals "recall nonexistent returns null" "$result" "(null)"

# ----------------------------------------
echo ""
echo "--- Test Group 3: Stats After Store ---"

result=$(call getStats)
assert_contains "stats: 1 memory" "$result" "totalMemories = 1"
assert_contains "stats: bytesUsed > 0" "$result" "bytesUsed"

result=$(call getCategories)
assert_contains "categories include facts" "$result" "facts"

result=$(call getAuditLogSize)
assert_equals "audit log has 1 entry" "$result" "(1 : nat)"

result=$(call getAuditLog '(0, 10)')
assert_contains "audit log entry is store action" "$result" "store"
assert_contains "audit log entry has key" "$result" "test-key-1"
assert_contains "audit log entry has category" "$result" "facts"

# ----------------------------------------
echo ""
echo "--- Test Group 4: Store Multiple + Update ---"

result=$(call store '("test-key-2", "preferences", blob "dark mode", "{}")')
assert_contains "store second key ok" "$result" "ok"

# Update existing key
result=$(call store '("test-key-1", "facts", blob "updated content", "{\"source\":\"test\",\"version\":2}")')
assert_contains "update existing key ok" "$result" "ok"

result=$(call recall '("test-key-1")')
assert_contains "recall updated content" "$result" "updated content"

result=$(call getStats)
assert_contains "stats: still 2 memories" "$result" "totalMemories = 2"

result=$(call getAuditLogSize)
assert_equals "audit log has 3 entries" "$result" "(3 : nat)"

# ----------------------------------------
echo ""
echo "--- Test Group 5: Delete ---"

result=$(call delete '("test-key-2")')
assert_contains "delete returns ok" "$result" "ok"

result=$(call recall '("test-key-2")')
assert_equals "deleted key returns null" "$result" "(null)"

result=$(call delete '("nonexistent")')
assert_contains "delete nonexistent returns notFound" "$result" "notFound"

result=$(call getStats)
assert_contains "stats: 1 memory after delete" "$result" "totalMemories = 1"

result=$(call getAuditLogSize)
assert_equals "audit log has 4 entries (store+store+update+delete)" "$result" "(4 : nat)"

# Check audit log for delete entry (4th entry, index 3)
result=$(call getAuditLog '(3, 1)')
assert_contains "audit log delete entry" "$result" "delete"

# ----------------------------------------
echo ""
echo "--- Test Group 6: Input Validation ---"

result=$(call store '("", "facts", blob "empty key", "{}")')
assert_contains "empty key rejected" "$result" "invalidInput"

result=$(call store '("valid-key", "", blob "empty cat", "{}")')
assert_contains "empty category rejected" "$result" "invalidInput"

# ----------------------------------------
echo ""
echo "--- Test Group 7: Store Session ---"

result=$(call storeSession '("session-001", blob "session data here", 1000000, 2000000)')
assert_contains "store session ok" "$result" "ok"

result=$(call getStats)
assert_contains "stats: 1 session" "$result" "totalSessions = 1"

# Store empty session ID
result=$(call storeSession '("", blob "bad", 0, 0)')
assert_contains "empty sessionId rejected" "$result" "invalidInput"

# ----------------------------------------
echo ""
echo "--- Test Group 8: Bulk Sync ---"

result=$(call bulkSync '(vec { record { key = "bulk-1"; category = "facts"; content = blob "bulk data 1"; metadata = "{}"; createdAt = 100; updatedAt = 200 }; record { key = "bulk-2"; category = "ideas"; content = blob "bulk data 2"; metadata = "{}"; createdAt = 100; updatedAt = 200 } }, vec { record { sessionId = "session-002"; data = blob "session 2"; startedAt = 3000000; endedAt = 4000000 } })')
assert_contains "bulk sync ok" "$result" "ok"
assert_contains "bulk sync stored 3" "$result" "stored = 3"
assert_contains "bulk sync skipped 0" "$result" "skipped = 0"

result=$(call recall '("bulk-1")')
assert_contains "bulk-1 exists" "$result" "bulk data 1"

result=$(call recall '("bulk-2")')
assert_contains "bulk-2 exists" "$result" "bulk data 2"

result=$(call getStats)
assert_contains "stats: 3 memories total" "$result" "totalMemories = 3"
assert_contains "stats: 2 sessions total" "$result" "totalSessions = 2"

# Bulk sync with older data -- should be skipped
result=$(call bulkSync '(vec { record { key = "bulk-1"; category = "facts"; content = blob "older data"; metadata = "{}"; createdAt = 50; updatedAt = 100 } }, vec {})')
assert_contains "older data skipped" "$result" "skipped = 1"
assert_contains "older data stored 0" "$result" "stored = 0"

# Verify data wasn't overwritten
result=$(call recall '("bulk-1")')
assert_contains "bulk-1 still has newer data" "$result" "bulk data 1"

# Bulk sync with empty key/category
result=$(call bulkSync '(vec { record { key = ""; category = "facts"; content = blob "bad"; metadata = "{}"; createdAt = 100; updatedAt = 200 } }, vec {})')
assert_contains "empty key in bulk sync has error" "$result" "Skipped memory with empty"

# ----------------------------------------
echo ""
echo "--- Test Group 9: Categories ---"

result=$(call getCategories)
assert_contains "categories include facts" "$result" "facts"
assert_contains "categories include ideas" "$result" "ideas"

# ----------------------------------------
echo ""
echo "--- Test Group 10: Composite Queries ---"

result=$(call getDashboard)
assert_contains "dashboard has stats" "$result" "totalMemories = 3"
assert_contains "dashboard has recentMemories" "$result" "recentMemories"
assert_contains "dashboard has recentSessions" "$result" "recentSessions"

result=$(call recallRelevant '(opt "facts", null, 10)')
assert_contains "recallRelevant by category" "$result" "bulk data 1"

result=$(call recallRelevant '(null, opt "bulk", 10)')
assert_contains "recallRelevant by prefix" "$result" "bulk"

result=$(call recallRelevant '(opt "nonexistent", null, 10)')
assert_equals "recallRelevant empty for unknown category" "$result" "(vec {})"

result=$(call getSyncManifest)
assert_contains "sync manifest has memoriesCount" "$result" "memoriesCount = 3"
assert_contains "sync manifest has sessionsCount" "$result" "sessionsCount = 2"
assert_contains "sync manifest has categoryChecksums" "$result" "categoryChecksums"

# ----------------------------------------
echo ""
echo "--- Test Group 11: Audit Log Pagination ---"

result=$(call getAuditLogSize)
log_size=$(echo "$result" | sed 's/[^0-9]//g')
echo "  Audit log size: $log_size"

# Get first 3 entries
result=$(call getAuditLog '(0, 3)')
assert_contains "audit log page 1 has entries" "$result" "timestamp"

# Get entries beyond end
result=$(call getAuditLog '(1000, 10)')
assert_equals "audit log past end returns empty" "$result" "(vec {})"

# ----------------------------------------
echo ""
echo "--- Test Group 12: Audit Log Immutability ---"
# The audit log is append-only. There's no delete or update function.
# Verify that the audit log only grows and that past entries are not modified.

initial_size_result=$(call getAuditLogSize)
initial_size=$(echo "$initial_size_result" | tr -dc '0-9')

# Get the first audit entry for comparison
first_entry=$(call getAuditLog '(0, 1)')

# Do another operation
call store '("immutability-test", "test", blob "check", "{}")' > /dev/null

# Check size increased
new_size_result=$(call getAuditLogSize)
new_size=$(echo "$new_size_result" | tr -dc '0-9')
TOTAL=$((TOTAL + 1))
if [ "$new_size" -gt "$initial_size" ]; then
  echo -e "  ${GREEN}PASS${NC}: audit log size increased ($initial_size -> $new_size)"
  PASS=$((PASS + 1))
else
  echo -e "  ${RED}FAIL${NC}: audit log size did not increase"
  FAIL=$((FAIL + 1))
fi

# Check first entry is unchanged
first_entry_after=$(call getAuditLog '(0, 1)')
assert_equals "first audit entry unchanged after new store" "$first_entry" "$first_entry_after"

# ----------------------------------------
echo ""
echo "==========================================="
echo -e "Total: $TOTAL | ${GREEN}Passed: $PASS${NC} | ${RED}Failed: $FAIL${NC}"
echo "==========================================="

if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
echo ""
echo "All tests passed!"
