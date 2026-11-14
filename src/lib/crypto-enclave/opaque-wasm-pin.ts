/**
 * SHA-384 of the committed OPAQUE + Argon2id engine
 * (src/lib/crypto-enclave/wasm/rout-opaque.wasm), built deterministically by
 * wasm/rout-opaque/build.sh (rustc 1.95.0, Cargo.lock). The loader refuses any
 * other bytes before compiling; CI rebuilds from source and compares (F.2).
 */
export const ROUT_OPAQUE_WASM_SHA384 = "971a75ee3f1000525454721b5ab86f975d4c52a0a200486f6e7de2c956c54ea90fc97f5cac21cdaa3071977a457d44b3";
