/// Placeholder test canister -- will be expanded with full test suite.
/// Tests are run via dfx canister call against a deployed local replica.
persistent actor UserVaultTest {
  public func ping() : async Text {
    "pong";
  };
};
