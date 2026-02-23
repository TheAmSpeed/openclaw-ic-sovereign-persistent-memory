import Types "Types";
import Array "mo:core/Array";
import Error "mo:core/Error";
import List "mo:core/List";
import Map "mo:core/Map";
import Nat "mo:core/Nat";
import Principal "mo:core/Principal";
import Result "mo:core/Result";
import Cycles "mo:core/Cycles";
import Time "mo:core/Time";

import IC "mo:base/ExperimentalInternetComputer";

import UserVault "UserVault";

/// Factory canister that spawns per-user UserVault canisters.
/// Launcher, not landlord -- creates vault, then transfers control to the user.
/// Uses Map (B-tree, order 32) for O(log n) vault lookups.
///
/// Migration: The running Factory on IC mainnet embeds v1 stable types
/// (AuditAction without #upgrade). Every upgrade must include a migration
/// function that widens the AuditAction variant until the stable type
/// metadata issue is resolved (the WASM's embedded "previous" type reflects
/// the migration INPUT, not the post-migration OUTPUT, so subsequent
/// upgrades always see v1 types as the "previous" type).
(with migration = func(
  old : {
    // Consume auditLog with the FULL current AuditAction type (including #upgrade).
    // The running Factory on IC mainnet already has #upgrade in its AuditAction.
    // All other stable variables are passed through unchanged by the EOP runtime.
    auditLog : List.List<Types.AuditEntry>;
  }
) : {
  auditLog : List.List<Types.AuditEntry>;
} {
  // Identity migration — auditLog type hasn't changed, just pass through.
  { auditLog = old.auditLog }
})
persistent actor Factory {

  // -- IC management canister interface --
  // transient: re-initialized on every upgrade from the expression below.
  // This avoids EOP compatibility issues when extending the actor interface.
  //
  // NOTE: install_code is NOT included here. It is called via
  // ExperimentalInternetComputer.call with raw Candid bytes in doUpgradeVault,
  // because Motoko's typed actor call has an encoding issue with the
  // wasm_memory_persistence field for EOP canisters.

  transient let ic : actor {
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

  // -- Vault WASM upgrade state --
  // The latest compiled UserVault WASM module, uploaded by admin.
  // Used by both admin-pushed and user-triggered vault upgrades.
  var latestVaultWasm : ?Blob = null;
  var latestVaultVersion : Nat = 0;

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

  /// Find the owner principal for a given vault canister ID.
  /// O(n) scan — only used for admin upgrade operations, not hot path.
  func findOwnerByVault(vaultId : Principal) : ?Principal {
    for ((owner, vid) in Map.entries(vaults)) {
      if (vid == vaultId) { return ?owner };
    };
    null;
  };

  /// Upgrade a single vault canister to the latest WASM.
  /// Caller must have verified admin/owner authorization before calling this.
  /// The `owner` is passed as the Candid-encoded init arg for the actor class.
  ///
  /// Uses ExperimentalInternetComputer.call with raw Candid bytes instead of a
  /// typed actor call. This bypasses Motoko's typed management canister binding,
  /// which has an encoding issue with `wasm_memory_persistence` for EOP canisters.
  func doUpgradeVault(vaultId : Principal, owner : Principal, triggeredBy : Principal) : async Result.Result<(), Types.FactoryError> {
    let wasm = switch (latestVaultWasm) {
      case null { return #err(#noWasmUploaded) };
      case (?w) { w };
    };

    // Encode the owner principal as the init argument for UserVault(initOwner : Principal).
    let initArg : Blob = to_candid (owner);

    // Construct the install_code argument as a Motoko value, then use to_candid
    // to serialize it. The type annotation ensures the Candid encoding matches
    // the IC management canister's expected type for install_code.
    //
    // The IC spec defines install_code mode as:
    //   variant { install; reinstall; upgrade : opt record {
    //     skip_pre_upgrade : opt bool;
    //     wasm_memory_persistence : opt variant { keep; replace };
    //   }}
    //
    // We include skip_pre_upgrade (as null) to match the full IC spec record shape.
    type UpgradeOpts = {
      skip_pre_upgrade : ?Bool;
      wasm_memory_persistence : ?{ #keep; #replace };
    };
    type InstallMode = {
      #install;
      #reinstall;
      #upgrade : ?UpgradeOpts;
    };
    type InstallCodeArgs = {
      mode : InstallMode;
      canister_id : Principal;
      wasm_module : Blob;
      arg : Blob;
      sender_canister_version : ?Nat64;
    };

    let installArgs : InstallCodeArgs = {
      mode = #upgrade(?{
        skip_pre_upgrade = ?false;
        wasm_memory_persistence = ?#keep;
      });
      canister_id = vaultId;
      wasm_module = wasm;
      arg = initArg;
      sender_canister_version = null;
    };

    let rawArgs : Blob = to_candid (installArgs);
    let mgmtPrincipal = Principal.fromText("aaaaa-aa");

    try {
      ignore await IC.call(mgmtPrincipal, "install_code", rawArgs);
    } catch (e) {
      return #err(#upgradeError(
        "install_code failed for " # Principal.toText(vaultId) # ": " #
        debug_show (Error.code(e)) # " " # Error.message(e)
      ));
    };

    appendAudit({
      timestamp = Time.now();
      action = #upgrade;
      caller = triggeredBy;
      key = ?Principal.toText(vaultId);
      category = ?"factory";
      details = ?("Vault upgraded to version " # Nat.toText(latestVaultVersion));
    });

    #ok(());
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

  // -- Vault upgrade API --

  /// User-triggered: upgrade the caller's vault to the latest WASM.
  /// Requires that the Factory is still a controller of the vault
  /// (i.e., the user has NOT called revokeFactoryController).
  public shared ({ caller }) func upgradeMyVault() : async Result.Result<(), Types.FactoryError> {
    if (Principal.isAnonymous(caller)) {
      return #err(#unauthorized("Anonymous callers cannot upgrade vaults"));
    };

    switch (findVault(caller)) {
      case null { return #err(#notFound("No vault found for caller")) };
      case (?vaultId) {
        await doUpgradeVault(vaultId, caller, caller);
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

  /// Upload a new vault WASM module (admin-only).
  /// Must be called before any vault upgrades can proceed.
  /// The version number is for tracking only — the Factory does not
  /// enforce monotonic version numbers (admin is trusted).
  public shared ({ caller }) func adminUploadVaultWasm(
    wasm : Blob,
    version : Nat,
  ) : async Result.Result<(), Types.FactoryError> {
    switch (requireAdmin(caller)) {
      case (?err) { return #err(err) };
      case null {};
    };

    if (wasm.size() == 0) {
      return #err(#upgradeError("WASM module must not be empty"));
    };

    latestVaultWasm := ?wasm;
    latestVaultVersion := version;

    appendAudit({
      timestamp = Time.now();
      action = #upgrade;
      caller = caller;
      key = null;
      category = ?"factory";
      details = ?("Vault WASM uploaded, version " # Nat.toText(version) # ", size " # Nat.toText(wasm.size()) # " bytes");
    });

    #ok(());
  };

  /// Upgrade a specific vault canister (admin-only).
  /// Useful for targeted upgrades or troubleshooting.
  public shared ({ caller }) func adminUpgradeVault(
    vaultId : Principal,
  ) : async Result.Result<(), Types.FactoryError> {
    switch (requireAdmin(caller)) {
      case (?err) { return #err(err) };
      case null {};
    };

    // Find the owner for this vault (needed for init arg)
    switch (findOwnerByVault(vaultId)) {
      case null { return #err(#notFound("No vault registered with canister ID " # Principal.toText(vaultId))) };
      case (?owner) {
        await doUpgradeVault(vaultId, owner, caller);
      };
    };
  };

  /// Upgrade all registered vaults to the latest WASM (admin-only).
  /// Returns a summary of successes and failures.
  /// Vaults that have revoked Factory controller access will fail individually
  /// but will not stop the batch from continuing.
  public shared ({ caller }) func adminUpgradeAllVaults() : async Result.Result<Types.UpgradeResult, Types.FactoryError> {
    switch (requireAdmin(caller)) {
      case (?err) { return #err(err) };
      case null {};
    };

    if (latestVaultWasm == null) {
      return #err(#noWasmUploaded);
    };

    var succeeded : Nat = 0;
    var failed : Nat = 0;
    var errors : [Text] = [];

    for ((owner, vaultId) in Map.entries(vaults)) {
      let result = await doUpgradeVault(vaultId, owner, caller);
      switch (result) {
        case (#ok(())) { succeeded += 1 };
        case (#err(err)) {
          failed += 1;
          let errMsg = switch (err) {
            case (#upgradeError(msg)) { msg };
            case (#noWasmUploaded) { "No WASM uploaded" };
            case _ { "Unknown error" };
          };
          errors := Array.concat(errors, [Principal.toText(vaultId) # ": " # errMsg]);
        };
      };
    };

    #ok({
      succeeded = succeeded;
      failed = failed;
      errors = errors;
    });
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

  /// Get the latest vault WASM version number.
  /// Returns 0 if no WASM has been uploaded yet.
  /// This is a public query — any client can check whether an upgrade is available.
  public query func getLatestVaultVersion() : async Nat {
    latestVaultVersion;
  };
};
