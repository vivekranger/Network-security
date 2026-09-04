#include "crypto.h"
#include <fstream>
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

string b64enc(const string &raw) {
  string out((raw.size() + 2) / 3 * 4 + 1, '\0');
  int n = EVP_EncodeBlock((unsigned char *)out.data(),
                          (const unsigned char *)raw.data(), raw.size());
  out.resize(n < 0 ? 0 : n);
  return out;
}

string b64dec(const string &b64) {
  if (b64.size() % 4 || b64.empty())
    return "";
  string out(b64.size() / 4 * 3, '\0');
  int n = EVP_DecodeBlock((unsigned char *)out.data(),
                          (const unsigned char *)b64.data(), b64.size());
  if (n < 0)
    return "";
  size_t pad = 0;
  while (pad < 2 && b64[b64.size() - 1 - pad] == '=')
    pad++;
  out.resize(n - pad);
  return out;
}

string read_file(const string &path) {
  ifstream f(path, ios::binary);
  return string(istreambuf_iterator<char>(f), istreambuf_iterator<char>());
}

EVP_PKEY *load_privkey(const string &path) {
  FILE *f = fopen(path.c_str(), "r");
  if (!f)
    return NULL;
  EVP_PKEY *k = PEM_read_PrivateKey(f, NULL, NULL, NULL);
  fclose(f);
  return k;
}

string sign_data(EVP_PKEY *key, const string &data) {
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  string sig;
  size_t len = 0;
  if (EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, key) == 1 &&
      EVP_DigestSign(ctx, NULL, &len, (const unsigned char *)data.data(),
                     data.size()) == 1) {
    sig.resize(len);
    if (EVP_DigestSign(ctx, (unsigned char *)sig.data(), &len,
                       (const unsigned char *)data.data(), data.size()) == 1)
      sig.resize(len);
    else
      sig.clear();
  }
  EVP_MD_CTX_free(ctx);
  return sig;
}

EVP_PKEY *verify_cert(const string &cert_pem, const string &ca_path,
                      const string &expected_name) {
  BIO *b = BIO_new_mem_buf(cert_pem.data(), cert_pem.size());
  X509 *leaf = PEM_read_bio_X509(b, NULL, NULL, NULL);
  BIO_free(b);
  if (!leaf)
    return NULL;

  EVP_PKEY *pub = NULL;
  X509_STORE *store = X509_STORE_new();
  X509_STORE_CTX *ctx = X509_STORE_CTX_new();

  if (X509_STORE_load_locations(store, ca_path.c_str(), NULL) == 1 &&
      X509_STORE_CTX_init(ctx, store, leaf, NULL) == 1) {
    X509_VERIFY_PARAM *p = X509_STORE_CTX_get0_param(ctx);
    X509_VERIFY_PARAM_set1_host(p, expected_name.c_str(), expected_name.size());
    if (X509_verify_cert(ctx) == 1)
      pub = X509_get_pubkey(leaf);
    else
      cerr << "cert verify failed: "
           << X509_verify_cert_error_string(X509_STORE_CTX_get_error(ctx))
           << endl;
  }
  X509_STORE_CTX_free(ctx);
  X509_STORE_free(store);
  X509_free(leaf);
  return pub;
}

bool verify_sig(EVP_PKEY *pub, const string &data, const string &sig) {
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  bool ok =
      EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pub) == 1 &&
      EVP_DigestVerify(ctx, (const unsigned char *)sig.data(), sig.size(),
                       (const unsigned char *)data.data(), data.size()) == 1;
  EVP_MD_CTX_free(ctx);
  return ok;
}
