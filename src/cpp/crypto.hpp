#pragma once
#include <cstddef>
#include <cstdint>

extern "C" {
bool ed25519_generate_keypair(uint8_t* out_pub32, uint8_t* out_priv32);


bool ed25519_sign(const uint8_t* msg, size_t msg_len,
                  const uint8_t* priv32,
                  uint8_t* out_sig64);


bool ed25519_verify(const uint8_t* msg, size_t msg_len,
                    const uint8_t* pub32,
                    const uint8_t* sig64);


bool sha3_256(const uint8_t* data, size_t len, uint8_t* out32);


bool secp256k1_generate_keypair(uint8_t* out_pub33, uint8_t* out_priv32);
bool secp256k1_sign(const uint8_t* msg32,
                    const uint8_t* priv32,
                    uint8_t* out_sig64);
bool secp256k1_verify(const uint8_t* msg32,
                      const uint8_t* pub33,
                      const uint8_t* sig64);
}
