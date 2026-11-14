//! ROUT OPAQUE engine: RFC 9807 OPAQUE-3DH (opaque-ke 4.0.1, ristretto255 +
//! SHA-512) with Argon2id (RFC 9106) as key stretching function, compiled to
//! one allocator-free wasm32 module.
//!
//! Memory model (owner rules F.2, H.1, I.6):
//!   * linear memory is imported; the host creates it per operation with
//!     initial == maximum and zero-fills all of it in `finally`;
//!   * no global allocator is linked: every buffer is a stack value or a
//!     caller-provided region, so the module has no `memory.grow`;
//!   * Argon2id works in a caller-provided block region (no heap);
//!   * every secret value created here is dropped (opaque-ke zeroizes) before
//!     the call returns; the host wipe covers what Rust cannot reach.
//!
//! ABI: every export returns 0 on success or a negative error code. Pointers
//! are byte offsets in the imported memory; fixed-size outputs are written to
//! the given offsets. Sizes come from `rout_len`.
#![no_std]

use core::slice;

use argon2::{Algorithm, Argon2, Block, Params, Version};
use generic_array::{ArrayLength, GenericArray};
use opaque_ke::errors::InternalError;
use opaque_ke::ksf::Ksf;
use opaque_ke::{
    CipherSuite, ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialFinalization, CredentialRequest,
    CredentialResponse, Identifiers, RegistrationRequest, RegistrationResponse,
    RegistrationUpload, Ristretto255, ServerLogin, ServerLoginParameters, ServerRegistration,
    ServerSetup, TripleDh,
};
use rand_core::{CryptoRng, Error as RandError, RngCore};

// ------------------------------------------------------------------ host

#[link(wasm_import_module = "env")]
extern "C" {
    /// Fills `len` bytes at `ptr` from the host CSPRNG (crypto.getRandomValues).
    fn rout_random(ptr: *mut u8, len: usize);
}

extern "C" {
    /// Linker-defined: first byte after the stack and static data.
    static __heap_base: u8;
}

/// Allocation is impossible by construction: every request returns null and
/// traps. The dependency graph links `alloc` (zeroize's default feature) but
/// no code path in this module allocates; a test runs every export.
struct NoAlloc;
unsafe impl core::alloc::GlobalAlloc for NoAlloc {
    unsafe fn alloc(&self, _: core::alloc::Layout) -> *mut u8 {
        core::ptr::null_mut()
    }
    unsafe fn dealloc(&self, _: *mut u8, _: core::alloc::Layout) {}
}
#[global_allocator]
static ALLOCATOR: NoAlloc = NoAlloc;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    core::arch::wasm32::unreachable()
}

struct HostRng;
impl RngCore for HostRng {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }
    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        if !dest.is_empty() {
            unsafe { rout_random(dest.as_mut_ptr(), dest.len()) }
        }
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), RandError> {
        self.fill_bytes(dest);
        Ok(())
    }
}
impl CryptoRng for HostRng {}

// ------------------------------------------------------------------ KSF

/// Owner floor (Stap 3): at least 64 MiB and 4 passes; weaker calls are refused.
pub const MIN_M_KIB: u32 = 65_536;
pub const MIN_T: u32 = 4;
pub const MAX_P: u32 = 4;

/// Argon2id over a caller-provided block region. `Default` has no memory and
/// therefore always fails: opaque-ke can never silently run without stretching.
#[derive(Default)]
pub struct RoutArgon2id {
    blocks: usize,
    m_kib: u32,
    t: u32,
    p: u32,
}

fn mem_bytes() -> usize {
    core::arch::wasm32::memory_size(0) * 65_536
}

fn region_ok(ptr: usize, len: usize) -> bool {
    match ptr.checked_add(len) {
        Some(end) => ptr >= heap_base() && end <= mem_bytes(),
        None => false,
    }
}

fn argon2id_into(pwd: &[u8], salt: &[u8], out: &mut [u8], m_kib: u32, t: u32, p: u32, blocks: usize) -> Result<(), ()> {
    let need = (m_kib as usize).checked_mul(core::mem::size_of::<Block>()).ok_or(())?;
    if blocks % core::mem::align_of::<Block>() != 0 || !region_ok(blocks, need) {
        return Err(());
    }
    let params = Params::new(m_kib, t, p, Some(out.len())).map_err(|_| ())?;
    let memory = unsafe { slice::from_raw_parts_mut(blocks as *mut Block, m_kib as usize) };
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into_with_memory(pwd, salt, out, memory)
        .map_err(|_| ())
}

impl Ksf for RoutArgon2id {
    fn hash<L: ArrayLength<u8>>(&self, input: GenericArray<u8, L>) -> Result<GenericArray<u8, L>, InternalError> {
        if self.m_kib < MIN_M_KIB || self.t < MIN_T || self.p == 0 || self.p > MAX_P {
            return Err(InternalError::KsfError);
        }
        let mut output = GenericArray::<u8, L>::default();
        // Same fixed salt as opaque-ke's own Argon2 KSF: the input is the
        // per-credential OPRF output, so it is already unique per account.
        argon2id_into(&input, &[0u8; 16], &mut output, self.m_kib, self.t, self.p, self.blocks)
            .map_err(|_| InternalError::KsfError)?;
        Ok(output)
    }
}

pub struct Suite;
impl CipherSuite for Suite {
    type OprfCs = Ristretto255;
    type KeyExchange = TripleDh<Ristretto255, sha2::Sha512>;
    type Ksf = RoutArgon2id;
}

// ------------------------------------------------------------------ helpers

const OK: i32 = 0;
const E_ARGS: i32 = -1;
const E_DECODE: i32 = -2;
const E_PROTOCOL: i32 = -3;
const E_KSF: i32 = -4;

fn heap_base() -> usize {
    unsafe { &__heap_base as *const u8 as usize }
}

unsafe fn input<'a>(ptr: usize, len: usize) -> Option<&'a [u8]> {
    if len == 0 {
        return Some(&[]);
    }
    if !region_ok(ptr, len) {
        return None;
    }
    Some(slice::from_raw_parts(ptr as *const u8, len))
}

unsafe fn output<'a>(ptr: usize, len: usize) -> Option<&'a mut [u8]> {
    if !region_ok(ptr, len) {
        return None;
    }
    Some(slice::from_raw_parts_mut(ptr as *mut u8, len))
}

unsafe fn write(ptr: usize, bytes: &[u8]) -> Result<(), i32> {
    let out = output(ptr, bytes.len()).ok_or(E_ARGS)?;
    out.copy_from_slice(bytes);
    Ok(())
}

fn code(r: Result<(), i32>) -> i32 {
    match r {
        Ok(()) => OK,
        Err(e) => e,
    }
}

const CONTEXT_MAX: usize = 256;

// Serialized sizes (ristretto255, SHA-512), RFC 9807 section 4 / appendix.
pub const LEN_REGISTRATION_REQUEST: usize = 32;
pub const LEN_REGISTRATION_RESPONSE: usize = 64;
pub const LEN_REGISTRATION_UPLOAD: usize = 192;
pub const LEN_KE1: usize = 96;
pub const LEN_KE2: usize = 320;
pub const LEN_KE3: usize = 64;
pub const LEN_SESSION_KEY: usize = 64;
pub const LEN_EXPORT_KEY: usize = 64;
pub const LEN_PUBLIC_KEY: usize = 32;

// Variable-length opaque-ke states are written with their length (u32 LE at
// the `*_len` pointer); the host keeps them in fixed 512-byte slots.
const STATE_MAX: usize = 512;

fn len_of(which: u32) -> usize {
    match which {
        1 => LEN_REGISTRATION_REQUEST,
        2 => LEN_REGISTRATION_RESPONSE,
        3 => LEN_REGISTRATION_UPLOAD,
        4 => LEN_KE1,
        5 => LEN_KE2,
        6 => LEN_KE3,
        7 => LEN_SESSION_KEY,
        8 => LEN_EXPORT_KEY,
        9 => LEN_PUBLIC_KEY,
        10 => STATE_MAX,
        _ => 0,
    }
}

unsafe fn write_sized(ptr: usize, len_ptr: usize, bytes: &[u8]) -> Result<(), i32> {
    if bytes.len() > STATE_MAX {
        return Err(E_ARGS);
    }
    write(ptr, bytes)?;
    write(len_ptr, &(bytes.len() as u32).to_le_bytes())
}

unsafe fn sized_input<'a>(ptr: usize, len: usize) -> Result<&'a [u8], i32> {
    if len == 0 || len > STATE_MAX {
        return Err(E_ARGS);
    }
    input(ptr, len).ok_or(E_ARGS)
}

fn ksf(m_kib: u32, t: u32, p: u32, blocks: usize) -> RoutArgon2id {
    RoutArgon2id { blocks, m_kib, t, p }
}

fn params_ok(m_kib: u32, t: u32, p: u32) -> bool {
    m_kib >= MIN_M_KIB && t >= MIN_T && p >= 1 && p <= MAX_P
}

// ------------------------------------------------------------------ exports

#[no_mangle]
pub extern "C" fn rout_abi_version() -> u32 {
    1
}

#[no_mangle]
pub extern "C" fn rout_heap_base() -> usize {
    heap_base()
}

#[no_mangle]
pub extern "C" fn rout_len(which: u32) -> usize {
    len_of(which)
}

/// Raw Argon2id (RFC 9106, v1.3). Used for known-answer tests against an
/// independent implementation and for vault key derivation; any parameters.
#[no_mangle]
pub unsafe extern "C" fn rout_argon2id(
    pwd: usize, pwd_len: usize, salt: usize, salt_len: usize, out: usize, out_len: usize,
    m_kib: u32, t: u32, p: u32, blocks: usize,
) -> i32 {
    code((|| {
        let pwd = input(pwd, pwd_len).ok_or(E_ARGS)?;
        let salt = input(salt, salt_len).ok_or(E_ARGS)?;
        let out = output(out, out_len).ok_or(E_ARGS)?;
        argon2id_into(pwd, salt, out, m_kib, t, p, blocks).map_err(|_| E_KSF)
    })())
}

// --- client

#[no_mangle]
pub unsafe extern "C" fn rout_client_register_start(pwd: usize, pwd_len: usize, out_request: usize, out_state: usize, out_state_len: usize) -> i32 {
    code((|| {
        let pwd = input(pwd, pwd_len).ok_or(E_ARGS)?;
        let started = ClientRegistration::<Suite>::start(&mut HostRng, pwd).map_err(|_| E_PROTOCOL)?;
        write(out_request, &started.message.serialize())?;
        write_sized(out_state, out_state_len, &started.state.serialize())
    })())
}

#[no_mangle]
pub unsafe extern "C" fn rout_client_register_finish(
    pwd: usize, pwd_len: usize, state: usize, state_len: usize, response: usize,
    m_kib: u32, t: u32, p: u32, blocks: usize,
    out_upload: usize, out_export_key: usize, out_server_pk: usize,
) -> i32 {
    code((|| {
        if !params_ok(m_kib, t, p) {
            return Err(E_KSF);
        }
        let pwd = input(pwd, pwd_len).ok_or(E_ARGS)?;
        let state = ClientRegistration::<Suite>::deserialize(sized_input(state, state_len)?)
            .map_err(|_| E_DECODE)?;
        let response = RegistrationResponse::<Suite>::deserialize(input(response, LEN_REGISTRATION_RESPONSE).ok_or(E_ARGS)?)
            .map_err(|_| E_DECODE)?;
        let stretch = ksf(m_kib, t, p, blocks);
        let params = ClientRegistrationFinishParameters::new(Identifiers { client: None, server: None }, Some(&stretch));
        let done = state.finish(&mut HostRng, pwd, response, params).map_err(|e| match e {
            opaque_ke::errors::ProtocolError::LibraryError(InternalError::KsfError) => E_KSF,
            _ => E_PROTOCOL,
        })?;
        write(out_upload, &done.message.serialize())?;
        write(out_export_key, &done.export_key)?;
        write(out_server_pk, &done.server_s_pk.serialize())
    })())
}

#[no_mangle]
pub unsafe extern "C" fn rout_client_login_start(pwd: usize, pwd_len: usize, out_ke1: usize, out_state: usize, out_state_len: usize) -> i32 {
    code((|| {
        let pwd = input(pwd, pwd_len).ok_or(E_ARGS)?;
        let started = ClientLogin::<Suite>::start(&mut HostRng, pwd).map_err(|_| E_PROTOCOL)?;
        write(out_ke1, &started.message.serialize())?;
        write_sized(out_state, out_state_len, &started.state.serialize())
    })())
}

#[no_mangle]
pub unsafe extern "C" fn rout_client_login_finish(
    pwd: usize, pwd_len: usize, state: usize, state_len: usize, ke2: usize, ctx: usize, ctx_len: usize,
    m_kib: u32, t: u32, p: u32, blocks: usize,
    out_ke3: usize, out_session_key: usize, out_export_key: usize, out_server_pk: usize,
) -> i32 {
    code((|| {
        if !params_ok(m_kib, t, p) || ctx_len > CONTEXT_MAX {
            return Err(if ctx_len > CONTEXT_MAX { E_ARGS } else { E_KSF });
        }
        let pwd = input(pwd, pwd_len).ok_or(E_ARGS)?;
        let context = input(ctx, ctx_len).ok_or(E_ARGS)?;
        let state = ClientLogin::<Suite>::deserialize(sized_input(state, state_len)?)
            .map_err(|_| E_DECODE)?;
        let ke2 = CredentialResponse::<Suite>::deserialize(input(ke2, LEN_KE2).ok_or(E_ARGS)?).map_err(|_| E_DECODE)?;
        let stretch = ksf(m_kib, t, p, blocks);
        let params = ClientLoginFinishParameters::new(Some(context), Identifiers { client: None, server: None }, Some(&stretch));
        let done = state.finish(&mut HostRng, pwd, ke2, params).map_err(|e| match e {
            opaque_ke::errors::ProtocolError::LibraryError(InternalError::KsfError) => E_KSF,
            _ => E_PROTOCOL,
        })?;
        write(out_ke3, &done.message.serialize())?;
        write(out_session_key, &done.session_key)?;
        write(out_export_key, &done.export_key)?;
        write(out_server_pk, &done.server_s_pk.serialize())
    })())
}

// --- server

#[no_mangle]
pub unsafe extern "C" fn rout_server_setup_new(out_setup: usize, out_setup_len: usize) -> i32 {
    code((|| {
        let setup = ServerSetup::<Suite>::new(&mut HostRng);
        write_sized(out_setup, out_setup_len, &setup.serialize())
    })())
}

unsafe fn load_setup(setup: usize, setup_len: usize) -> Result<ServerSetup<Suite>, i32> {
    ServerSetup::<Suite>::deserialize(sized_input(setup, setup_len)?).map_err(|_| E_DECODE)
}

#[no_mangle]
pub unsafe extern "C" fn rout_server_public_key(setup: usize, setup_len: usize, out_pk: usize) -> i32 {
    code((|| {
        let setup = load_setup(setup, setup_len)?;
        write(out_pk, &setup.keypair().public().serialize())
    })())
}

#[no_mangle]
pub unsafe extern "C" fn rout_server_register_start(setup: usize, setup_len: usize, request: usize, cred: usize, cred_len: usize, out_response: usize) -> i32 {
    code((|| {
        let setup = load_setup(setup, setup_len)?;
        let request = RegistrationRequest::<Suite>::deserialize(input(request, LEN_REGISTRATION_REQUEST).ok_or(E_ARGS)?)
            .map_err(|_| E_DECODE)?;
        let cred = input(cred, cred_len).ok_or(E_ARGS)?;
        if cred.is_empty() {
            return Err(E_ARGS);
        }
        let started = ServerRegistration::<Suite>::start(&setup, request, cred).map_err(|_| E_PROTOCOL)?;
        write(out_response, &started.message.serialize())
    })())
}

/// Validates an upload (all points decode) and returns the password file.
#[no_mangle]
pub unsafe extern "C" fn rout_server_register_finish(upload: usize, out_record: usize) -> i32 {
    code((|| {
        let upload = RegistrationUpload::<Suite>::deserialize(input(upload, LEN_REGISTRATION_UPLOAD).ok_or(E_ARGS)?)
            .map_err(|_| E_DECODE)?;
        write(out_record, &ServerRegistration::<Suite>::finish(upload).serialize())
    })())
}

/// `record == 0` runs the RFC 9807 fake-record path (unknown account): the
/// response is indistinguishable and the later finish always fails.
#[no_mangle]
pub unsafe extern "C" fn rout_server_login_start(
    setup: usize, setup_len: usize, record: usize, ke1: usize, cred: usize, cred_len: usize, ctx: usize, ctx_len: usize,
    out_ke2: usize, out_state: usize, out_state_len: usize,
) -> i32 {
    code((|| {
        if ctx_len > CONTEXT_MAX {
            return Err(E_ARGS);
        }
        let setup = load_setup(setup, setup_len)?;
        let password_file = if record == 0 {
            None
        } else {
            Some(ServerRegistration::<Suite>::deserialize(input(record, LEN_REGISTRATION_UPLOAD).ok_or(E_ARGS)?).map_err(|_| E_DECODE)?)
        };
        let ke1 = CredentialRequest::<Suite>::deserialize(input(ke1, LEN_KE1).ok_or(E_ARGS)?).map_err(|_| E_DECODE)?;
        let cred = input(cred, cred_len).ok_or(E_ARGS)?;
        if cred.is_empty() {
            return Err(E_ARGS);
        }
        let context = input(ctx, ctx_len).ok_or(E_ARGS)?;
        let params = ServerLoginParameters { context: Some(context), identifiers: Identifiers { client: None, server: None } };
        let started = ServerLogin::start(&mut HostRng, &setup, password_file, ke1, cred, params).map_err(|_| E_PROTOCOL)?;
        write(out_ke2, &started.message.serialize())?;
        write_sized(out_state, out_state_len, &started.state.serialize())
    })())
}

#[no_mangle]
pub unsafe extern "C" fn rout_server_login_finish(state: usize, state_len: usize, ke3: usize, ctx: usize, ctx_len: usize, out_session_key: usize) -> i32 {
    code((|| {
        if ctx_len > CONTEXT_MAX {
            return Err(E_ARGS);
        }
        let state = ServerLogin::<Suite>::deserialize(sized_input(state, state_len)?).map_err(|_| E_DECODE)?;
        let ke3 = CredentialFinalization::<Suite>::deserialize(input(ke3, LEN_KE3).ok_or(E_ARGS)?).map_err(|_| E_DECODE)?;
        let context = input(ctx, ctx_len).ok_or(E_ARGS)?;
        let params = ServerLoginParameters { context: Some(context), identifiers: Identifiers { client: None, server: None } };
        let done = state.finish(ke3, params).map_err(|_| E_PROTOCOL)?;
        write(out_session_key, &done.session_key)
    })())
}
