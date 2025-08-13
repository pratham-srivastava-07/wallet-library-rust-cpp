#include "crypto.hpp"
#include <cstring>
#include <random>

// --- tiny helpers ---
static void fill_random(uint8_t* buf, size_t n) {
    static std::mt19937_64 rng{123456789ULL}; // deterministic for demo
    for (size_t i = 0; i < n; ++i) buf[i] = static_cast<uint8_t>(rng() & 0xFF);
}

static void pseudo_hash32(const uint8_t* in, size_t len, uint8_t* out32) {
    // NOT SHA3. Just a toy mixer to have bytes to work with
    uint64_t a=0x243F6A88, b=0x85A308D3, c=0x13198A2E, d=0x03707344;
    for (size_t i=0; i<len; ++i) {
        a = (a ^ in[i]) * 0x9E3779B97F4A7C15ULL;
        b = (b + a) ^ (a >> 13);
        c = (c ^ b) * 0xC2B2AE3D27D4EB4FULL;
        d = (d + c) ^ (c >> 16);
    }
    uint64_t s[4] = {a,b,c,d};
    std::memcpy(out32, s, 32);
}

// --- Ed25519-ish placeholders ---
extern "C" bool ed25519_generate_keypair(uint8_t* out_pub32, uint8_t* out_priv32) {
    if (!out_pub32 || !out_priv32) return false;
    fill_random(out_priv32, 32);
    // "public" = hash(priv)
    pseudo_hash32(out_priv32, 32, out_pub32);
    return true;
}

extern "C" bool ed25519_sign(const uint8_t* msg, size_t msg_len,
                             const uint8_t* priv32,
                             uint8_t* out_sig64) {
    if (!msg || !priv32 || !out_sig64) return false;
    uint8_t h[32];
    pseudo_hash32(msg, msg_len, h);
    // "sig" = H(msg) || H(msg XOR priv)
    std::memcpy(out_sig64, h, 32);
    uint8_t mix[64];
    std::memset(mix, 0, 64);
    std::memcpy(mix, msg, msg_len > 64 ? 64 : msg_len);
    for (int i=0;i<32;i++) mix[i] ^= priv32[i];
    uint8_t h2[32];
    pseudo_hash32(mix, 64, h2);
    std::memcpy(out_sig64+32, h2, 32);
    return true;
}

extern "C" bool ed25519_verify(const uint8_t* msg, size_t msg_len,
                               const uint8_t* pub32,
                               const uint8_t* sig64) {
    if (!msg || !pub32 || !sig64) return false;
    uint8_t h[32];
    pseudo_hash32(msg, msg_len, h);
    // naive check: first 32 bytes match H(msg)
    return std::memcmp(h, sig64, 32) == 0;
}

// --- "SHA3-256" placeholder (use real one later) ---
extern "C" bool sha3_256(const uint8_t* data, size_t len, uint8_t* out32) {
    if (!data || !out32) return false;
    pseudo_hash32(data, len, out32);
    return true;
}

// --- secp256k1 placeholders ---
extern "C" bool secp256k1_generate_keypair(uint8_t* out_pub33, uint8_t* out_priv32) {
    if (!out_pub33 || !out_priv32) return false;
    fill_random(out_priv32, 32);
    uint8_t h[32];
    pseudo_hash32(out_priv32, 32, h);
    out_pub33[0] = 0x02; // pretend "compressed" marker
    std::memcpy(out_pub33+1, h, 32);
    return true;
}

extern "C" bool secp256k1_sign(const uint8_t* msg32,
                               const uint8_t* priv32,
                               uint8_t* out_sig64) {
    if (!msg32 || !priv32 || !out_sig64) return false;
    // "sig" = msg32 || H(msg32 XOR priv32)
    std::memcpy(out_sig64, msg32, 32);
    uint8_t mix[32];
    for (int i=0;i<32;i++) mix[i] = msg32[i] ^ priv32[i];
    uint8_t h[32];
    pseudo_hash32(mix, 32, h);
    std::memcpy(out_sig64+32, h, 32);
    return true;
}

extern "C" bool secp256k1_verify(const uint8_t* msg32,
                                 const uint8_t* pub33,
                                 const uint8_t* sig64) {
    if (!msg32 || !pub33 || !sig64) return false;
    // naive check: sig[0..32) == msg32
    return std::memcmp(sig64, msg32, 32) == 0;
}
