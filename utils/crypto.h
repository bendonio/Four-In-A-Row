#ifndef CRYPTO_H
#define CRYPTO_H

#include <iostream>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "./shared-constants.h"
using namespace std;

int sym_dec_and_auth(unsigned char* sym_dec_key, unsigned char* sym_dec_iv, unsigned char* cphr_buf_in, unsigned int cphr_buf_size,
			unsigned char*& clear_buf_out, unsigned char* aad_in, unsigned int aad_len, unsigned char* tag_out);

EVP_PKEY* load_dh_pubkey(const char * key_file_name);

static DH *get_dh2048(void);

EVP_PKEY* create_and_store_dh_prvkey(const char * key_file_name);

EVP_PKEY * read_user_pubkey(char *pubkey_file_name);

/**
 * @brief Encrypt using AES-128 in mode GCM
 * 
 * @param sym_enc_key 
 * @param sym_enc_iv 
 * @param clear_buf_in 
 * @param clear_buf_size 
 * @param cphr_buf_out 
 * @param aad_in 
 * @param aad_len 
 * @param tag_out 
 * @return the encrypted text size 
 */
unsigned int sym_enc_and_auth(unsigned char* sym_enc_key, unsigned char*& sym_enc_iv, 
								unsigned char* clear_buf_in, unsigned int clear_buf_size,
								unsigned char*& cphr_buf_out, unsigned char* aad_in, unsigned int aad_len, 
								unsigned char*& tag_out);


bool certificate_is_verified(X509_STORE *store, X509* certificate);

X509_STORE* build_store(string ca_cert_file_name, string CRL_cert_file_name);

void generate_random_quantity(unsigned char* out_buf, unsigned int num_bytes);

void compute_hash(unsigned char*& digest, unsigned int &digest_len, unsigned char *clear_buf, 
					unsigned int clear_buf_size);

unsigned int generate_dh_secret(unsigned char*& dh_secret_out, EVP_PKEY* my_dh_prvkey, 	
								EVP_PKEY* peer_dh_pubkey);

bool signature_is_verified(unsigned char* clear_buf, unsigned int clear_size, unsigned char *sig_buf, 
                            unsigned int sig_size, EVP_PKEY* pubkey);

unsigned char* digitally_sign(unsigned char *clear_buf, int clear_size, 
                                unsigned int &signature_len, EVP_PKEY* prvkey);

X509* load_certificate(const char* cert_file_name);

EVP_PKEY* load_privkey(const char * prvkey_file_name, string password);

#endif