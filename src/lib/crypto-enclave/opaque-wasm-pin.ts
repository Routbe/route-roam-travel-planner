/**
 * SHA-384 of the committed OPAQUE + Argon2id engine
 * (src/lib/crypto-enclave/wasm/rout-opaque.wasm), built deterministically by
 * wasm/rout-opaque/build.sh (official rustup rustc 1.95.0 with LLVM 22.1.2, Cargo.lock). The loader refuses any
 * other bytes before compiling; CI rebuilds from source and compares (F.2).
 */
export const ROUT_OPAQUE_WASM_SHA384 = "619e81251e353ade293fc8265980e5237c26ff7d87fdd5c00a4bdff4727da2a2d174bd8d4b814a3ee4b7825e3d1c38b6";
