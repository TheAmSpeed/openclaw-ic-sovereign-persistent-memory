import Types "Types";
import Array "mo:base/Array";
import Buffer "mo:base/Buffer";
import Nat "mo:base/Nat";
import Principal "mo:base/Principal";
import Result "mo:base/Result";
import Trie "mo:base/Trie";
import Text "mo:base/Text";
import ExperimentalCycles "mo:base/ExperimentalCycles";
import Time "mo:base/Time";

import UserVault "UserVault";

/// Factory canister that spawns per-user UserVault canisters.
/// Launcher, not landlord -- creates vault, then transfers control to the user.
/// Uses Trie for O(1) vault lookups (replaces O(n) linear scan over arrays).
persistent actor Factory {

  // -- IC management canister interface (subset for controller transfer) --

  let ic : actor {
    update_settings : shared {
      canister_id : Principal;
      settings : {
        controllers : ?[Principal];
        compute_allocation : ?Nat;
        memory_allocation : ?Nat;
        freezing_threshold : ?Nat;
      };
    } -> async ();
  } = actor "aaaaa-aa";

  // -- Configuration --

  // Cycles to seed each new vault with (1.2T cycles ~= $1.56)
  // IC requires ~1.1T for canister installation as of 2026
  let VAULT_CREATION_CYCLES : Nat = 1_200_000_000_000;

  // Admin principal (deployer) -- set once via claimAdmin, then immutable.
  // IMPORTANT: With EOP (persistent actor), this survives upgrades.
  // Never use --wasm-memory-persistence replace on the Factory canister.
  var admin : ?Principal = null;

  // -- State (auto-persisted via EOP) --

  // Trie of owner principal -> vault canister ID for O(1) lookup and O(1) amortized insert
  // (replaces O(n) linear scan and O(n) Array.append)
  var vaultsTrie : Trie.Trie<Principal, Principal> = Trie.empty();
  var totalCreated : Nat = 0;

  // Audit log for factory operations (Buffer for O(1) amortized appends)
  var auditLogBuf : Buffer.Buffer<Types.AuditEntry> = Buffer.Buffer<Types.AuditEntry>(16);

  // -- Internal helpers --

  func principalKey(p : Principal) : Trie.Key<Principal> {
    { key = p; hash = Principal.hash(p) };
  };

  /// Look up a vault for a principal. O(1) via Trie.
  func findVault(owner : Principal) : ?Principal {
    Trie.get(vaultsTrie, principalKey(owner), Principal.equal);
  };

  /// Assert caller is admin. Returns error result if not.
  func requireAdmin(caller : Principal) : ?Types.FactoryError {
    switch (admin) {
      case null { ?#unauthorized("Admin not set -- call claimAdmin first") };
      case (?a) {
        if (caller != a) { ?#unauthorized("Only admin can perform this operation") }
        else { null };
      };
    };
  };

  /// Append to factory audit log.
  func appendAudit(entry : Types.AuditEntry) {
    auditLogBuf.add(entry);
  };

  // -- Public API --

  /// Create a new vault for the caller.
  /// Rate-limited: one vault per principal.
  public shared ({ caller }) func createVault() : async Result.Result<Principal, Types.FactoryError> {
    // Reject anonymous callers
    if (Principal.isAnonymous(caller)) {
      return #err(#creationFailed("Anonymous callers cannot create vaults"));
    };

    // Check if vault already exists -- O(1) lookup
    switch (findVault(caller)) {
      case (?_) { return #err(#alreadyExists) };
      case null {};
    };

    // Check we have enough cycles to seed the new vault
    if (ExperimentalCycles.balance() < VAULT_CREATION_CYCLES + 1_000_000_000) {
      return #err(#insufficientCycles);
    };

    // Seed cycles and create the UserVault canister
    ExperimentalCycles.add<system>(VAULT_CREATION_CYCLES);
    let vault = await UserVault.UserVault(caller);
    let canisterId = Principal.fromActor(vault);

    // Store the mapping -- O(1) amortized via Trie (replaces O(n) Array.append)
    vaultsTrie := Trie.put(vaultsTrie, principalKey(caller), Principal.equal, canisterId).0;
    totalCreated += 1;

    // Transfer IC-level controller to the user (+ keep Factory for future ops)
    let factoryPrincipal = Principal.fromActor(Factory);
    await ic.update_settings({
      canister_id = canisterId;
      settings = {
        controllers = ?[caller, factoryPrincipal];
        compute_allocation = null;
        memory_allocation = null;
        freezing_threshold = null;
      };
    });

    appendAudit({
      timestamp = Time.now();
      action = #created;
      caller = caller;
      key = ?Principal.toText(canisterId);
      category = ?"factory";
      details = ?"Vault created";
    });

    #ok(canisterId);
  };

  /// Transfer IC-level controller of a vault to its owner.
  /// Sets controllers to [owner, Factory] so the owner can upgrade their own
  /// vault directly, while Factory retains access for future operations.
  /// Only the vault owner can call this.
  public shared ({ caller }) func transferController() : async Result.Result<(), Types.FactoryError> {
    if (Principal.isAnonymous(caller)) {
      return #err(#unauthorized("Anonymous callers cannot transfer controllers"));
    };

    switch (findVault(caller)) {
      case null { return #err(#notFound("No vault found for caller")) };
      case (?vaultId) {
        let factoryPrincipal = Principal.fromActor(Factory);
        await ic.update_settings({
          canister_id = vaultId;
          settings = {
            controllers = ?[caller, factoryPrincipal];
            compute_allocation = null;
            memory_allocation = null;
            freezing_threshold = null;
          };
        });
        #ok(());
      };
    };
  };

  /// Revoke Factory's controller access to the caller's vault.
  /// After this call, only the vault owner is a controller.
  /// This makes the vault fully sovereign -- the Factory can no longer
  /// upgrade or modify the vault canister settings.
  /// WARNING: This is irreversible. The Factory cannot re-add itself.
  public shared ({ caller }) func revokeFactoryController() : async Result.Result<(), Types.FactoryError> {
    if (Principal.isAnonymous(caller)) {
      return #err(#unauthorized("Anonymous callers cannot revoke controllers"));
    };

    switch (findVault(caller)) {
      case null { return #err(#notFound("No vault found for caller")) };
      case (?vaultId) {
        // Set controllers to [owner] only -- removes Factory
        await ic.update_settings({
          canister_id = vaultId;
          settings = {
            controllers = ?[caller];
            compute_allocation = null;
            memory_allocation = null;
            freezing_threshold = null;
          };
        });

        appendAudit({
          timestamp = Time.now();
          action = #created; // Reuse #created for factory-level operations; details field disambiguates
          caller = caller;
          key = ?Principal.toText(vaultId);
          category = ?"factory";
          details = ?"Factory controller revoked -- vault is fully sovereign";
        });

        #ok(());
      };
    };
  };

  // -- Admin functions --

  /// Claim admin role. Can only be called once (when admin is unset).
  /// IMPORTANT: Call immediately after deployment to secure the Factory.
  /// With EOP (persistent actor), admin survives canister upgrades.
  /// NEVER use --wasm-memory-persistence replace on the Factory canister,
  /// as that resets all state including admin, creating a frontrunning window.
  public shared ({ caller }) func claimAdmin() : async Result.Result<(), Types.FactoryError> {
    if (Principal.isAnonymous(caller)) {
      return #err(#unauthorized("Anonymous callers cannot claim admin"));
    };
    switch (admin) {
      case (?_) { #err(#alreadyExists) };
      case null {
        admin := ?caller;
        #ok(());
      };
    };
  };

  /// Re-register an existing vault mapping (admin-only recovery).
  /// Use after a Factory upgrade that lost state.
  public shared ({ caller }) func adminRegisterVault(
    owner : Principal,
    vaultId : Principal,
  ) : async Result.Result<(), Types.FactoryError> {
    switch (requireAdmin(caller)) {
      case (?err) { return #err(err) };
      case null {};
    };

    // Don't allow duplicate registrations for the same owner
    switch (findVault(owner)) {
      case (?_) { return #err(#alreadyExists) };
      case null {};
    };

    vaultsTrie := Trie.put(vaultsTrie, principalKey(owner), Principal.equal, vaultId).0;
    totalCreated += 1;
    #ok(());
  };

  /// Get the current admin principal.
  public query func getAdmin() : async ?Principal {
    admin;
  };

  // -- Public queries --

  /// Get the vault canister ID for the caller.
  public query ({ caller }) func getVault() : async ?Principal {
    findVault(caller);
  };

  /// Get total vaults created.
  public query func getTotalCreated() : async Nat {
    totalCreated;
  };

  /// Get all vaults (admin-only diagnostic).
  /// Returns Result instead of assert-trapping on unauthorized access.
  public query ({ caller }) func getAllVaults() : async Result.Result<[(Principal, Principal)], Types.FactoryError> {
    switch (admin) {
      case null { return #err(#unauthorized("Admin not set")) };
      case (?a) {
        if (caller != a) { return #err(#unauthorized("Only admin can view all vaults")) };
      };
    };
    #ok(Trie.toArray<Principal, Principal, (Principal, Principal)>(vaultsTrie, func(k, v) { (k, v) }));
  };
};
