use serde::{Deserialize, Serialize};
use crate::ffi;
use serde_with::{serde_as, Bytes};

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ed25519Keypair {
    pub public: [u8; 32],
    pub private: [u8; 32],
}

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bytes33(
    #[serde_as(as = "Bytes")] pub [u8; 33]
);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Secp256k1Keypair {
    pub public_compressed: Bytes33,
    pub private: [u8; 32],
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Wallet {
    pub ed: Ed25519Keypair,
    pub secp: Secp256k1Keypair,
}

impl Wallet {
    pub fn new() -> Self {
        let (ed_pub, ed_priv) = ffi::ed25519_keypair();
        let (secp_pub, secp_priv) = ffi::secp256k1_keypair();
        Self {
            ed: Ed25519Keypair { public: ed_pub, private: ed_priv },
            secp: Secp256k1Keypair { public_compressed:  Bytes33(secp_pub), private: secp_priv },
        }
    }

    pub fn address_from_ed25519(&self) -> String {
        let h = ffi::sha3_256_hash(&self.ed.public);
        // pretend bech32/hex address; we’ll use hex for demo
        format!("ed25519:{}", hex::encode(h))
    }

    pub fn address_from_secp256k1(&self) -> String {
        let h = ffi::sha3_256_hash(&self.secp.public_compressed.0);
        format!("secp256k1:{}", hex::encode(h))
    }

    pub fn sign_ed25519(&self, msg: &[u8]) -> [u8; 64] {
        ffi::ed25519_sign_msg(msg, &self.ed.private)
    }

    pub fn verify_ed25519(&self, msg: &[u8], sig: &[u8; 64]) -> bool {
        ffi::ed25519_verify_msg(msg, &self.ed.public, sig)
    }
}
