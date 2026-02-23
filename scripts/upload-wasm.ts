/// Upload compiled UserVault WASM to the Factory canister's adminUploadVaultWasm endpoint.
/// Usage: npx tsx scripts/upload-wasm.ts [version]
/// Example: npx tsx scripts/upload-wasm.ts 2

import { readFileSync } from "fs";
import { resolve } from "path";
import { Actor, HttpAgent } from "@dfinity/agent";
import { IDL } from "@dfinity/candid";
import { loadIdentityAsync } from "../identity.js";

const FACTORY_CANISTER_ID = "v7tpn-laaaa-aaaac-bcmdq-cai";
const WASM_PATH = resolve(import.meta.dirname, "../canister/.dfx/local/canisters/user_vault/user_vault.wasm");

const version = Number(process.argv[2] || "2");
if (!Number.isInteger(version) || version < 1) {
  console.error("Usage: npx tsx scripts/upload-wasm.ts <version>");
  console.error("  version must be a positive integer");
  process.exit(1);
}

const FactoryError = IDL.Variant({
  alreadyExists: IDL.Null,
  insufficientCycles: IDL.Null,
  unauthorized: IDL.Text,
  notFound: IDL.Text,
  creationFailed: IDL.Text,
  upgradeError: IDL.Text,
  noWasmUploaded: IDL.Null,
});

const ResultOkFactoryUnit = IDL.Variant({ ok: IDL.Null, err: FactoryError });

const factoryIdl = ({ IDL: _IDL }: any) =>
  IDL.Service({
    adminUploadVaultWasm: IDL.Func([IDL.Vec(IDL.Nat8), IDL.Nat], [ResultOkFactoryUnit], []),
    getLatestVaultVersion: IDL.Func([], [IDL.Nat], ["query"]),
  });

async function main() {
  console.log(`Reading WASM from: ${WASM_PATH}`);
  const wasm = readFileSync(WASM_PATH);
  console.log(`WASM size: ${wasm.byteLength} bytes (${(wasm.byteLength / 1024).toFixed(1)} KB)`);

  console.log("Loading identity from keychain...");
  const identity = await loadIdentityAsync();
  console.log(`Principal: ${identity.getPrincipal().toText()}`);

  console.log("Creating agent...");
  const agent = await HttpAgent.create({
    host: "https://icp0.io",
    identity,
  });

  const factory = Actor.createActor(factoryIdl, {
    agent,
    canisterId: FACTORY_CANISTER_ID,
  });

  console.log(`Uploading WASM as version ${version}...`);
  const result = (await factory.adminUploadVaultWasm(wasm, BigInt(version))) as
    | { ok: null }
    | { err: unknown };

  if ("ok" in result) {
    console.log("Upload successful.");
  } else {
    console.error("Upload failed:", result.err);
    process.exit(1);
  }

  // Verify
  const latestVersion = (await factory.getLatestVaultVersion()) as bigint;
  console.log(`Factory latest vault version: ${latestVersion}`);
}

main().catch((err) => {
  console.error("Fatal:", err);
  process.exit(1);
});
