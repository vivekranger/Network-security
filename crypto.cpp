#include "crypto.h"
#include <vector>

BIGNUM *exp_mod(const BIGNUM *base, const BIGNUM *exp, const BIGNUM *m) {
  BN_CTX *ctx = BN_CTX_new();
  BIGNUM *res = BN_new();
  BN_set_word(res, 1);
  BIGNUM *b = BN_new();

  BN_mod(b, base, m, ctx);

  for (int i = 0; i < BN_num_bits(exp); i++) {
    if (BN_is_bit_set(exp, i))
      BN_mod_mul(res, res, b, m, ctx);
    BN_mod_sqr(b, b, m, ctx);
  }

  BN_CTX_free(ctx);
  BN_free(b);
  return res;
}

BIGNUM *random_private(BIGNUM *P) {
  BIGNUM *a = BN_new();
  do {
    BN_rand_range(a, P);
  } while (BN_num_bits(a) < 1000);
  return a;
}

bool valid_public(const BIGNUM *y, BIGNUM *P) {
  BIGNUM *two = BN_new();
  BN_set_word(two, 2);
  BIGNUM *limit = BN_new();
  BIGNUM *q = BN_new();
  BN_copy(limit, P);

  BN_sub_word(limit, 2);
  if (BN_cmp(y, two) < 0)
    return false;
  if (BN_cmp(y, limit) > 0)
    return false;

  BN_copy(q, P);
  BN_sub_word(q, 1);
  BN_rshift1(q, q);

  BIGNUM *t = exp_mod(y, q, P);
  bool res = BN_is_one(t);
  BN_free(two);
  BN_free(limit);
  BN_free(q);
  BN_free(t);
  return res;
}

vuc to_bytes(BIGNUM *x) {
  BIGNUM *y = BN_new();
  int n = KEY_SIZE;
  vuc out(n);
  BN_bn2binpad(x, out.data(), n);
  return out;
}

BIGNUM *from_bytes(vuc &buf) {
  BIGNUM *x = BN_new();
  BN_bin2bn(buf.data(), buf.size(), x);
  return x;
}

vuc derive_key(const vuc &secret) {
  vuc key(32);
  SHA256(secret.data(), secret.size(), key.data());
  return key;
}

string fingerprint(const vuc &key) {
  unsigned char h[32];
  SHA256(key.data(), key.size(), h);
  char out[17];
  for (int i = 0; i < 8; i++) {
    sprintf(out + i * 2, "%02x", h[i]);
  }
  return string(out);
}

string encrypt(const vuc &key, const string &text) {
  vuc nonce(12), ct(text.size()), tag(16);
  unsigned char scratch[16];
  int len;

  RAND_bytes(nonce.data(), 12);

  EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
  EVP_EncryptInit_ex(c, EVP_aes_256_gcm(), NULL, key.data(), nonce.data());
  EVP_EncryptUpdate(c, ct.data(), &len, (unsigned char *)text.data(),
                    text.size());
  EVP_EncryptFinal_ex(c, scratch, &len);
  EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_GET_TAG, 16, tag.data());
  EVP_CIPHER_CTX_free(c);

  string out;
  out.append(nonce.begin(), nonce.end());
  out.append(ct.begin(), ct.end());
  out.append(tag.begin(), tag.end());
  return out;
}

string decrypt(const vuc &key, const string &enc_msg) {
  if (enc_msg.size() < 28)
    throw "Message size invalid...";

  vuc msg(enc_msg.begin(), enc_msg.end());
  const unsigned char *nonce = msg.data();
  const unsigned char *ct = msg.data() + 12;
  int ctlen = msg.size() - 28;
  unsigned char *tag = (unsigned char *)msg.data() + 12 + ctlen;

  vuc plain(ctlen);
  unsigned char scratch[16];
  int len;

  EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
  EVP_DecryptInit_ex(c, EVP_aes_256_gcm(), NULL, key.data(), nonce);
  EVP_DecryptUpdate(c, plain.data(), &len, ct, ctlen);
  EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_TAG, 16, tag);
  int ok = EVP_DecryptFinal_ex(c, scratch, &len);
  EVP_CIPHER_CTX_free(c);

  if (ok <= 0)
    throw "Decryption failed...";
  string text(plain.begin(), plain.end());
  return text;
}
