#ifndef CRYPTO_H
#define CRYPTO_H

#include <openssl/bn.h>
#include <string>
#include <vector>

struct DHKeyPair {
    BIGNUM* private_key;
    BIGNUM* public_key;
};

DHKeyPair generate_dh_keypair();

BIGNUM* compute_dh_shared_secret(
    const BIGNUM* private_key,
    const BIGNUM* peer_public_key
);

std::string bn_to_string(const BIGNUM* value);

BIGNUM* string_to_bn(const std::string& value);

std::vector<unsigned char> derive_aes_key(
    const BIGNUM* shared_secret
);

std::string fingerprint(
    const BIGNUM* shared_secret
);

std::string aes_gcm_encrypt(
    const std::string& plaintext,
    const std::vector<unsigned char>& key
);

bool aes_gcm_decrypt(
    const std::string& input,
    const std::vector<unsigned char>& key,
    std::string& plaintext
);

std::string bytes_to_hex(const std::string& input);

std::string hex_to_bytes(const std::string& input);

#endif
