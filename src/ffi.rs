use std::ffi::c_uchar;

#[link(name = "wallet_crypto", kind = "static")]
unsafe extern "C" {
    // ed25519
    fn ed25519_generate_keypair(out_pub32: *mut c_uchar, out_priv32: *mut c_uchar) -> bool;
    fn ed25519_sign(msg: *const c_uchar, msg_len: usize,
                    priv32: *const c_uchar, out_sig64: *mut c_uchar) -> bool;
    fn ed25519_verify(msg: *const c_uchar, msg_len: usize,
                      pub32: *const c_uchar, sig64: *const c_uchar) -> bool;

    // sha3-256
    fn sha3_256(data: *const c_uchar, len: usize, out32: *mut c_uchar) -> bool;

    // secp256k1
    fn secp256k1_generate_keypair(out_pub33: *mut c_uchar, out_priv32: *mut c_uchar) -> bool;
    fn secp256k1_sign(msg32: *const c_uchar, priv32: *const c_uchar, out_sig64: *mut c_uchar) -> bool;
    fn secp256k1_verify(msg32: *const c_uchar, pub33: *const c_uchar, sig64: *const c_uchar) -> bool;
}

pub fn ed25519_keypair() -> ([u8; 32], [u8; 32]) {
    let mut pubk = [0u8; 32];
    let mut privk = [0u8; 32];
    let ok = unsafe { ed25519_generate_keypair(pubk.as_mut_ptr(), privk.as_mut_ptr()) };
    assert!(ok, "ed25519_generate_keypair failed");
    (pubk, privk)
}

pub fn ed25519_sign_msg(msg: &[u8], privk: &[u8; 32]) -> [u8; 64] {
    let mut sig = [0u8; 64];
    let ok = unsafe {
        ed25519_sign(
            msg.as_ptr(), msg.len(),
            privk.as_ptr(), sig.as_mut_ptr(),
        )
    };
    assert!(ok, "ed25519_sign failed");
    sig
}

pub fn ed25519_verify_msg(msg: &[u8], pubk: &[u8; 32], sig: &[u8; 64]) -> bool {
    unsafe { ed25519_verify(msg.as_ptr(), msg.len(), pubk.as_ptr(), sig.as_ptr()) }
}

pub fn sha3_256_hash(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let ok = unsafe { sha3_256(data.as_ptr(), data.len(), out.as_mut_ptr()) };
    assert!(ok, "sha3_256 failed");
    out
}

pub fn secp256k1_keypair() -> ([u8; 33], [u8; 32]) {
    let mut pubk = [0u8; 33];
    let mut privk = [0u8; 32];
    let ok = unsafe { secp256k1_generate_keypair(pubk.as_mut_ptr(), privk.as_mut_ptr()) };
    assert!(ok, "secp256k1_generate_keypair failed");
    (pubk, privk)
}

pub fn secp256k1_sign32(msg32: &[u8; 32], privk: &[u8; 32]) -> [u8; 64] {
    let mut sig = [0u8; 64];
    let ok = unsafe { secp256k1_sign(msg32.as_ptr(), privk.as_ptr(), sig.as_mut_ptr()) };
    assert!(ok, "secp256k1_sign failed");
    sig
}

pub fn secp256k1_verify32(msg32: &[u8; 32], pubk: &[u8; 33], sig: &[u8; 64]) -> bool {
    unsafe { secp256k1_verify(msg32.as_ptr(), pubk.as_ptr(), sig.as_ptr()) }
}
