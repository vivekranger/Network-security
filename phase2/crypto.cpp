#include "crypto.h"

#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <vector>

//
// RFC 3526 - 2048-bit MODP Group (Group 14)
//
static const char* RFC3526_PRIME =
"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
"29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
"83655D23DCA3AD961C62F356208552BB9ED529077096966D"
"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2"
"BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68"
"FFFFFFFFFFFFFFFF";

static BIGNUM* get_prime()
{
    BIGNUM* p = nullptr;

    BN_hex2bn(&p, RFC3526_PRIME);

    return p;
}

static BIGNUM* get_generator()
{
    BIGNUM* g = BN_new();

    BN_set_word(g, 2);

    return g;
}


//
// Our own modular exponentiation:
//
// result = base^exponent mod modulus
//
static BIGNUM* modular_exponentiation(
    const BIGNUM* base,
    const BIGNUM* exponent,
    const BIGNUM* modulus)
{
    BN_CTX* ctx = BN_CTX_new();

    BIGNUM* result = BN_new();
    BIGNUM* current = BN_new();
    BIGNUM* exp = BN_dup(exponent);

    BN_one(result);

    BN_mod(current, base, modulus, ctx);

    while (!BN_is_zero(exp)) {

        if (BN_is_odd(exp)) {

            BN_mod_mul(
                result,
                result,
                current,
                modulus,
                ctx
            );
        }

        BN_mod_mul(
            current,
            current,
            current,
            modulus,
            ctx
        );

        BN_rshift1(exp, exp);
    }

    BN_free(current);
    BN_free(exp);
    BN_CTX_free(ctx);

    return result;
}


//
// Generate DH private and public values
//
DHKeyPair generate_dh_keypair()
{
    DHKeyPair pair;

    BIGNUM* p = get_prime();
    BIGNUM* g = get_generator();

    pair.private_key = BN_new();

    BN_rand_range(
        pair.private_key,
        p
    );

    pair.public_key =
        modular_exponentiation(
            g,
            pair.private_key,
            p
        );

    BN_free(p);
    BN_free(g);

    return pair;
}


//
// Calculate:
//
// shared_secret = peer_public^private mod p
//
BIGNUM* compute_dh_shared_secret(
    const BIGNUM* private_key,
    const BIGNUM* peer_public_key)
{
    BIGNUM* p = get_prime();

    BIGNUM* shared =
        modular_exponentiation(
            peer_public_key,
            private_key,
            p
        );

    BN_free(p);

    return shared;
}


//
// Convert a BIGNUM to hexadecimal text
//
std::string bn_to_string(const BIGNUM* value)
{
    char* hex = BN_bn2hex(value);

    std::string result(hex);

    OPENSSL_free(hex);

    return result;
}


//
// Convert hexadecimal text back to BIGNUM
//
BIGNUM* string_to_bn(const std::string& value)
{
    BIGNUM* result = nullptr;

    BN_hex2bn(
        &result,
        value.c_str()
    );

    return result;
}


//
// SHA-256(raw DH shared secret)
//
// SHA-256 gives 32 bytes.
// 32 bytes = 256 bits.
// Therefore this becomes an AES-256 key.
//
std::vector<unsigned char> derive_aes_key(
    const BIGNUM* shared_secret)
{
    int size =
        BN_num_bytes(shared_secret);

    std::vector<unsigned char> secret(size);

    BN_bn2bin(
        shared_secret,
        secret.data()
    );

    unsigned char hash[SHA256_DIGEST_LENGTH];

    SHA256(
        secret.data(),
        secret.size(),
        hash
    );

    return std::vector<unsigned char>(
        hash,
        hash + SHA256_DIGEST_LENGTH
    );
}


//
// Print only a fingerprint of the DH secret.
// Never print the actual secret.
//
std::string fingerprint(
    const BIGNUM* shared_secret)
{
    int size =
        BN_num_bytes(shared_secret);

    std::vector<unsigned char> secret(size);

    BN_bn2bin(
        shared_secret,
        secret.data()
    );

    unsigned char hash[SHA256_DIGEST_LENGTH];

    SHA256(
        secret.data(),
        secret.size(),
        hash
    );

    std::ostringstream out;

    for (int i = 0;
         i < SHA256_DIGEST_LENGTH;
         i++) {

        out << std::hex
            << std::setw(2)
            << std::setfill('0')
            << static_cast<int>(hash[i]);
    }

    return out.str();
}


//
// AES-256-GCM encryption
//
// Output format:
//
// [12-byte nonce]
// [16-byte authentication tag]
// [ciphertext]
//
std::string aes_gcm_encrypt(
    const std::string& plaintext,
    const std::vector<unsigned char>& key)
{
    unsigned char nonce[12];

    if (RAND_bytes(
            nonce,
            sizeof(nonce)) != 1) {

        throw std::runtime_error(
            "Nonce generation failed"
        );
    }

    EVP_CIPHER_CTX* ctx =
        EVP_CIPHER_CTX_new();

    if (!ctx) {
        throw std::runtime_error(
            "Cipher context creation failed"
        );
    }

    int len;
    int ciphertext_len;

    std::vector<unsigned char> ciphertext(
        plaintext.size() + 16
    );

    unsigned char tag[16];

    EVP_EncryptInit_ex(
        ctx,
        EVP_aes_256_gcm(),
        nullptr,
        nullptr,
        nullptr
    );

    EVP_CIPHER_CTX_ctrl(
        ctx,
        EVP_CTRL_GCM_SET_IVLEN,
        sizeof(nonce),
        nullptr
    );

    EVP_EncryptInit_ex(
        ctx,
        nullptr,
        nullptr,
        key.data(),
        nonce
    );

    EVP_EncryptUpdate(
        ctx,
        ciphertext.data(),
        &len,
        reinterpret_cast<
            const unsigned char*
        >(plaintext.data()),
        plaintext.size()
    );

    ciphertext_len = len;

    EVP_EncryptFinal_ex(
        ctx,
        ciphertext.data() + len,
        &len
    );

    ciphertext_len += len;

    EVP_CIPHER_CTX_ctrl(
        ctx,
        EVP_CTRL_GCM_GET_TAG,
        sizeof(tag),
        tag
    );

    EVP_CIPHER_CTX_free(ctx);

    std::string output;

    output.append(
        reinterpret_cast<char*>(nonce),
        sizeof(nonce)
    );

    output.append(
        reinterpret_cast<char*>(tag),
        sizeof(tag)
    );

    output.append(
        reinterpret_cast<char*>(
            ciphertext.data()
        ),
        ciphertext_len
    );

    return output;
}


//
// AES-256-GCM decryption
//
bool aes_gcm_decrypt(
    const std::string& input,
    const std::vector<unsigned char>& key,
    std::string& plaintext)
{
    //
    // 12 bytes nonce + 16 bytes tag
    //
    if (input.size() < 28) {
        return false;
    }

    const unsigned char* nonce =
        reinterpret_cast<
            const unsigned char*
        >(input.data());

    const unsigned char* tag =
        reinterpret_cast<
            const unsigned char*
        >(input.data() + 12);

    const unsigned char* ciphertext =
        reinterpret_cast<
            const unsigned char*
        >(input.data() + 28);

    int ciphertext_len =
        input.size() - 28;

    EVP_CIPHER_CTX* ctx =
        EVP_CIPHER_CTX_new();

    if (!ctx) {
        return false;
    }

    int len;
    int plaintext_len;

    std::vector<unsigned char> output(
        ciphertext_len + 16
    );

    EVP_DecryptInit_ex(
        ctx,
        EVP_aes_256_gcm(),
        nullptr,
        nullptr,
        nullptr
    );

    EVP_CIPHER_CTX_ctrl(
        ctx,
        EVP_CTRL_GCM_SET_IVLEN,
        12,
        nullptr
    );

    EVP_DecryptInit_ex(
        ctx,
        nullptr,
        nullptr,
        key.data(),
        nonce
    );

    EVP_DecryptUpdate(
        ctx,
        output.data(),
        &len,
        ciphertext,
        ciphertext_len
    );

    plaintext_len = len;

    //
    // Give GCM the authentication tag
    //
    EVP_CIPHER_CTX_ctrl(
        ctx,
        EVP_CTRL_GCM_SET_TAG,
        16,
        const_cast<unsigned char*>(tag)
    );

    //
    // This verifies the authentication tag.
    //
    int result =
        EVP_DecryptFinal_ex(
            ctx,
            output.data() + len,
            &len
        );

    EVP_CIPHER_CTX_free(ctx);

    //
    // result <= 0 means authentication failed.
    //
    if (result <= 0) {
        return false;
    }

    plaintext_len += len;

    plaintext.assign(
        reinterpret_cast<char*>(
            output.data()
        ),
        plaintext_len
    );

    return true;
}


//
// Convert binary data to hexadecimal text.
//
// This is necessary because our existing protocol
// uses newline framing and arbitrary binary ciphertext
// could contain '\n'.
//
std::string bytes_to_hex(
    const std::string& input)
{
    const char* hex =
        "0123456789abcdef";

    std::string output;

    for (unsigned char c : input) {

        output += hex[c >> 4];
        output += hex[c & 0x0f];
    }

    return output;
}


//
// Convert hexadecimal text back to binary.
//
std::string hex_to_bytes(
    const std::string& input)
{
    std::string output;

    if (input.size() % 2 != 0) {
        return "";
    }

    for (size_t i = 0;
         i < input.size();
         i += 2) {

        unsigned int value;

        std::stringstream ss;

        ss << std::hex
           << input.substr(i, 2);

        ss >> value;

        output.push_back(
            static_cast<char>(value)
        );
    }

    return output;
}
