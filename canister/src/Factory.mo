import Types "Types";
import List "mo:core/List";
import Map "mo:core/Map";
import Principal "mo:core/Principal";
import Result "mo:core/Result";
import Cycles "mo:core/Cycles";
import Time "mo:core/Time";

import UserVault "UserVault";

/// Factory canister that spawns per-user UserVault canisters.
/// Launcher, not landlord -- creates vault, then transfers control to the user.
/// Uses Map (B-tree, order 32) for O(log n) vault lookups.
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

  // Map of owner principal -> vault canister ID for O(log n) lookup and insert.
  // Map is mutable (B-tree): add/remove mutate in-place, no reassignment needed.
  var vaults : Map.Map<Principal, Principal> = Map.empty<Principal, Principal>();
  var totalCreated : Nat = 0;

  // Audit log for factory operations.
  // List provides amortized O(1) append and O(1) random access, and is a stable type.
  var auditLog : List.List<Types.AuditEntry> = List.empty<Types.AuditEntry>();

  // -- Internal helpers --

  /// Look up a vault for a principal. O(log n) via Map.
  func findVault(owner : Principal) : ?Principal {
    Map.get(vaults, Principal.compare, owner);
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
    List.add(auditLog, entry);
  };

  // -- Public API --

  /// Create a new vault for the caller.
  /// Rate-limited: one vault per principal.
  public shared ({ caller }) func createVault() : async Result.Result<Principal, Types.FactoryError> {
    // Reject anonymous callers
    if (Principal.isAnonymous(caller)) {
      return #err(#creationFailed("Anonymous callers cannot create vaults"));
    };

    // Check if vault already exists -- O(log n) lookup
    switch (findVault(caller)) {
      case (?_) { return #err(#alreadyExists) };
      case null {};
    };

    // Check we have enough cycles to seed the new vault
    if (Cycles.balance() < VAULT_CREATION_CYCLES + 1_000_000_000) {
      return #err(#insufficientCycles);
    };

    // Seed cycles and create the UserVault canister
    let vault = await (with cycles = VAULT_CREATION_CYCLES) UserVault.UserVault(caller);
    let canisterId = Principal.fromActor(vault);

    // Store the mapping -- Map mutates in-place, no reassignment needed
    Map.add(vaults, Principal.compare, caller, canisterId);
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

    Map.add(vaults, Principal.compare, owner, vaultId);
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
    #ok(Map.toArray(vaults));
  };
};
