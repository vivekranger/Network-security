#pragma once
#include <iostream>
#include <string>
#include <vector>
#include <cstdio>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

using namespace std;

typedef vector<unsigned char> vuc;

static const char* P_HEX =
"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
"29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
"83655D23DCA3AD961C62F356208552BB9ED529077096966D"
"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
"DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
"15728E5A8AACAA68FFFFFFFFFFFFFFFF";

const int KEY_SIZE = 256;
// string aes_gcm_enc(const string &key, const string &msg);
// string aes_gcm_dec(const string &key, const string &enc_msg);

BIGNUM *exp_mod(const BIGNUM *base, const BIGNUM *exp, const BIGNUM *m);
BIGNUM *random_private(BIGNUM *P);
bool valid_public(const BIGNUM *y, BIGNUM *P);
vuc to_bytes(BIGNUM *x);
BIGNUM *from_bytes(vuc &buf);
vuc derive_key(const vuc &secret);
string fingerprint(const vuc &key);
string encrypt(const vuc &key, const string &text);
string decrypt(const vuc &key, const string &enc_msg);
