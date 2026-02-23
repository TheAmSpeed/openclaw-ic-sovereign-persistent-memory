/// Generate the Candid argument file for adminUploadVaultWasm.
/// Usage: node scripts/gen-upload-arg.js > /tmp/upload-wasm-arg.txt
/// Then: dfx canister call factory adminUploadVaultWasm --argument-file /tmp/upload-wasm-arg.txt ...

const fs = require("fs");
const path = require("path");

const wasmPath = path.resolve(__dirname, "../canister/.dfx/local/canisters/user_vault/user_vault.wasm");
const wasm = fs.readFileSync(wasmPath);

// Candid blob literal: blob "\DE\AD\BE\EF..."
const hex = wasm.toString("hex");
const escaped = hex.replace(/../g, "\\$&");

process.stdout.write(`(blob "${escaped}", 2 : nat)`);
