#include "./crypto.h"
using namespace std;

int sym_dec_and_auth(unsigned char* sym_dec_key, unsigned char* sym_dec_iv, unsigned char* cphr_buf_in, 
						unsigned int cphr_buf_size, unsigned char*& clear_buf_out, unsigned char* aad_in, 
						unsigned int aad_len, unsigned char* tag_in){

	int ret;

	const EVP_CIPHER *cipher = EVP_aes_128_gcm();

	int total_len = 0;
	int len = 0;

	clear_buf_out = (unsigned char *)malloc(cphr_buf_size);
	if(!clear_buf_out) {
		
        cerr << "<ERR> malloc() returned NULL, disconnecting!\n";
        exit(1);

    }

	EVP_CIPHER_CTX *ctx_dec = NULL; 
	ctx_dec = EVP_CIPHER_CTX_new();
	if(!ctx_dec) {
	
		cerr << "<ERR>  EVP_CIPHER_CTX_new returned NULL\n";
		exit(1);
		
	}

	ret = EVP_DecryptInit(ctx_dec, cipher, sym_dec_key, sym_dec_iv);
	if(ret != 1){
	
		cerr << "<ERR>  EVP_DecryptInit failed\n";
		exit(1);
	
	}

	ret = EVP_DecryptUpdate(ctx_dec, NULL, &len, aad_in, aad_len);
	if( ret != 1 ){
		
		cerr << "<ERR>  EncryptUpdate 1 failed \n";
		exit(1);
		
	}

	ret = EVP_DecryptUpdate(ctx_dec, clear_buf_out, &len, cphr_buf_in, cphr_buf_size);
	if( ret != 1 ){
		
		cerr << "<ERR>  EncryptUpdate 2 failed \n";
		exit(1);
		
	}
	
	total_len += len;

	ret = EVP_CIPHER_CTX_ctrl(ctx_dec, EVP_CTRL_AEAD_SET_TAG, TAG_LEN, tag_in);
	if( ret != 1){
	
		cerr << "<ERR>  EVP_CIPHER_CTX_ctrl failed \n";
		exit(1);
	
	}

	ret = EVP_DecryptFinal(ctx_dec, clear_buf_out + total_len, &len);
	if( ret == 0 ){
		
		cerr << "<ERR>  EVP_DecryptFinal returned 0 --> tag mismatch \n";
		exit(1);
		
	} else if( ret != 1){
	
		cerr << "<ERR>  EVP_DecryptFinal failed\n";
		exit(1);

	}

	total_len += len;

	return total_len;
}

EVP_PKEY* load_dh_pubkey(const char * key_file_name){

	FILE* pubkey_file_name = fopen(key_file_name, "r");
	if(!pubkey_file_name){ 
		
		cerr << "<ERR>  cannot open file '"<< key_file_name << "' (missing?)\n"; 
		exit(1); 

	}

	EVP_PKEY* my_pubkey = PEM_read_PUBKEY(pubkey_file_name, NULL, NULL, NULL);
	fclose(pubkey_file_name);
	if(!my_pubkey){ 
		cerr << "<ERR>  PEM_read_PUBKEY returned NULL\n"; 
		exit(1); 
	}

	return my_pubkey;
}

static DH *get_dh2048(void){
    static unsigned char dhp_2048[] = {
        0x94, 0xB9, 0xD7, 0x7D, 0x55, 0xF0, 0x1C, 0x62, 0xD5, 0x83,
        0x40, 0x8B, 0x9A, 0x65, 0x5E, 0x69, 0x7A, 0xEC, 0x43, 0x36,
        0x22, 0x71, 0x20, 0xB7, 0x4D, 0xCC, 0x2D, 0x24, 0xC2, 0x17,
        0x23, 0xE0, 0xC3, 0x9D, 0x9A, 0xC9, 0x78, 0x11, 0x39, 0xD7,
        0x55, 0xCE, 0x5B, 0xF0, 0xCF, 0x64, 0x89, 0x7A, 0x61, 0x91,
        0x29, 0x26, 0xD8, 0xE6, 0xA1, 0x62, 0x09, 0x4A, 0x83, 0xE4,
        0xFC, 0x47, 0xD2, 0xB0, 0xF8, 0xD9, 0xDF, 0x6F, 0x58, 0x52,
        0xED, 0xB3, 0x54, 0x5B, 0x58, 0x19, 0xAC, 0x9D, 0x32, 0x84,
        0x7A, 0x63, 0x74, 0x32, 0x27, 0xD7, 0x40, 0x1A, 0xD1, 0x78,
        0x29, 0x9E, 0x8B, 0x59, 0x05, 0xF8, 0x77, 0x69, 0xC4, 0x7F,
        0x12, 0x42, 0xB6, 0x13, 0xA3, 0x53, 0xE6, 0x6A, 0x98, 0xEB,
        0x5B, 0x14, 0x0F, 0x6C, 0x29, 0x3E, 0xAF, 0x56, 0x1E, 0xF5,
        0x2D, 0x3E, 0xF0, 0xF2, 0xB7, 0xEF, 0xF4, 0x1D, 0x02, 0x6E,
        0xA7, 0x70, 0xBA, 0x4D, 0xBB, 0x54, 0x23, 0x7F, 0x65, 0x91,
        0x29, 0x60, 0x0A, 0xB7, 0xD6, 0x5C, 0xE6, 0x4B, 0xE0, 0xC3,
        0x8D, 0x75, 0xE5, 0x50, 0x45, 0xB7, 0x1A, 0xC7, 0xCF, 0x08,
        0xE8, 0xE4, 0x8D, 0x76, 0x15, 0x14, 0xAA, 0x98, 0xE0, 0x57,
        0xAE, 0x0F, 0x1F, 0x3F, 0x78, 0x6D, 0x03, 0xAF, 0xC1, 0x42,
        0x98, 0xD3, 0xFA, 0xE1, 0x94, 0xEA, 0x53, 0x9F, 0xAA, 0x97,
        0x93, 0x4E, 0xB9, 0x0E, 0xFB, 0x14, 0xBE, 0x29, 0x4C, 0x75,
        0x57, 0x67, 0xC2, 0x2A, 0x99, 0xC6, 0x2E, 0xEF, 0xCA, 0x74,
        0x61, 0x37, 0xF3, 0xBB, 0xE7, 0xCF, 0x05, 0x11, 0x7A, 0x6A,
        0xE5, 0x7A, 0xC9, 0x88, 0x42, 0x41, 0x94, 0x6C, 0xA3, 0xFB,
        0x10, 0xB1, 0xAE, 0x42, 0x45, 0xD9, 0x5E, 0x47, 0xEF, 0x24,
        0x18, 0x4C, 0xF7, 0x1F, 0x9F, 0xAC, 0xDC, 0x42, 0x0B, 0xDE,
        0x20, 0x02, 0x9B, 0x94, 0xF1, 0xD3
    };
    static unsigned char dhg_2048[] = {
        0x02
    };
    DH *dh = DH_new();
    BIGNUM *p, *g;

    if (dh == NULL)
        return NULL;
    p = BN_bin2bn(dhp_2048, sizeof(dhp_2048), NULL);
    g = BN_bin2bn(dhg_2048, sizeof(dhg_2048), NULL);
    if (p == NULL || g == NULL
            || !DH_set0_pqg(dh, p, NULL, g)) {
        DH_free(dh);
        BN_free(p);
        BN_free(g);
        return NULL;
    }
    return dh;
}

EVP_PKEY* create_and_store_dh_prvkey(const char * key_file_name){

	int ret;

	EVP_PKEY *params = NULL;
	params = EVP_PKEY_new();
	if(params == NULL){

		cerr << "<ERR> <ERR>  EVP_PKEY_new() returned NULL!\n";
		exit(1);

	}

	DH* temp = get_dh2048();
	
	ret = EVP_PKEY_set1_DH(params,temp);
	if(ret != 1) {

		cerr << "<ERR>  Error loading DH params!\n";
		exit(1);

	}

	DH_free(temp);

	// Create context for the key generation 
	EVP_PKEY_CTX *DHctx = NULL;

	DHctx = EVP_PKEY_CTX_new(params, NULL);
	if(!DHctx){
		
		cerr << "<ERR>   EVP_PKEY_CTX_new() returned NULL!\n";
		exit(1);

	}
	// Generate a new key 
	EVP_PKEY *my_dh_prvkey = NULL;

	ret = EVP_PKEY_keygen_init(DHctx);
	if(ret != 1){

		cerr << "<ERR>   EVP_PKEY_keygen_init() failed!\n";
		exit(1);

	}

	ret = EVP_PKEY_keygen(DHctx, &my_dh_prvkey);
	if(ret != 1){

		cerr << "<ERR>   EVP_PKEY_keygen() failed!\n";
		exit(1);

	}

	FILE* pubkey_file_name = fopen(key_file_name, "w");
	if(!pubkey_file_name){ 
		
		cerr << "<ERR>  cannot open file '"<< key_file_name << "' (missing?)\n"; 
		exit(1); 

	}

	PEM_write_PUBKEY(pubkey_file_name, my_dh_prvkey);
	fclose(pubkey_file_name);

	return my_dh_prvkey;
}

EVP_PKEY * read_user_pubkey(char *pubkey_file_name){

	EVP_PKEY *pubkey = NULL;

	string pubkey_file_name_str(pubkey_file_name);
	string pubkey_file_path = "server_files/";
	pubkey_file_path.append(pubkey_file_name_str);

	// load the public key:
	FILE* pubkey_file = fopen(pubkey_file_path.c_str(), "r");
	if(!pubkey_file){
	
		cerr << "<ERR> Cannot open file '" << pubkey_file_name << "' (file does not exist ?)";

	}
	
	pubkey = PEM_read_PUBKEY(pubkey_file, NULL, NULL, NULL);
	if(!pubkey){
	
		cerr << "<ERR> PEM_read_PUBKEY failed!";

	}
	
	fclose(pubkey_file);

	return pubkey;
}

unsigned int sym_enc_and_auth(unsigned char* sym_enc_key, unsigned char*& sym_enc_iv, unsigned char* clear_buf_in, unsigned int clear_buf_size,
			unsigned char*& cphr_buf_out, unsigned char* aad_in, unsigned int aad_len, unsigned char*& tag_out){

	int ret = 0;

	int len;
	int cphr_len = 0;

	const EVP_CIPHER *cipher = EVP_aes_128_gcm();
	
	int block_size = EVP_CIPHER_block_size(cipher);
	unsigned int sym_enc_iv_len = EVP_CIPHER_iv_length(cipher);
	sym_enc_iv = (unsigned char*)malloc(sym_enc_iv_len);
	if(!sym_enc_iv){

		cerr << "<ERR>  malloc returned NULL\n";
		exit(1);

	}

	cphr_buf_out = (unsigned char*)malloc(clear_buf_size);
	if(!cphr_buf_out){

		cerr << "<ERR>  malloc returned NULL\n";
		exit(1);

	}

	generate_random_quantity(sym_enc_iv, sym_enc_iv_len);

	EVP_CIPHER_CTX *ctx = NULL; 
	ctx = EVP_CIPHER_CTX_new();
	if(!ctx) {
	
		cerr << "<ERR>  EVP_CIPHER_CTX_new returned NULL\n";
		exit(1);
		
	}

	ret = EVP_EncryptInit(ctx, cipher, sym_enc_key, sym_enc_iv);
	if(ret != 1){
	
		cerr << "<ERR>  EVP_EncryptInit failed\n";
		exit(1);
	
	}

	tag_out = (unsigned char *)malloc(TAG_LEN);
	if(!tag_out) {
		
        cerr << "<ERR> malloc() returned NULL, disconnecting!\n";
        exit(1);

    }

	// Authenticate aad
	ret = EVP_EncryptUpdate(ctx, NULL, &len, aad_in, aad_len);
	if( ret != 1 ){
		
		cerr << "<ERR>  EncryptUpdate failed 1\n";
		exit(1);
		
	}

	// Encrypt clear text
	ret = EVP_EncryptUpdate(ctx, cphr_buf_out, &len, clear_buf_in, clear_buf_size);
	if( ret != 1 ){
		
		cerr << "<ERR>  EncryptUpdate failed 2\n";
		exit(1);
		
	}
	
	cphr_len += len;

	ret = EVP_EncryptFinal(ctx, clear_buf_in + cphr_len, &len);
	if( ret != 1){
	
		cerr << "<ERR>  EncryptFinal failed \n";
		exit(1);
	
	}
	
	cphr_len += len;

	ret = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, TAG_LEN, tag_out);
	if( ret != 1){
	
		cerr << "<ERR>  EVP_CIPHER_CTX_ctrl failed \n";
		exit(1);
	
	}
	
	EVP_CIPHER_CTX_free(ctx);

	return cphr_len;
}

bool certificate_is_verified(X509_STORE *store, X509* certificate){

	int ret;

	X509_STORE_CTX *ctx_cert_verify = X509_STORE_CTX_new();
    if(!ctx_cert_verify){
        
        cerr << "<ERR>  X509_STORE_CTX_new returned NULL\n";
	    return false; 

    }

    ret = X509_STORE_CTX_init(ctx_cert_verify, store, certificate, NULL);
    if(ret != 1){
        
        cerr << "ERR: X509_STORE_CTX_init failed\n";
	    return false; 

    }

    ret = X509_verify_cert(ctx_cert_verify);
    if(ret != 1){

        cerr << "ERR: authentication (\"X509_verify_cert()\") failed!\n";
        return false;

    }

	return true;
}

X509_STORE* build_store(string CA_cert_file_name, string CRL_file_name){

	int ret;
	
	// Load the CA certificate

	X509* CA_cert = NULL;
	FILE* CA_cert_file = fopen(CA_cert_file_name.c_str(), "r");
	if(!CA_cert_file){

		cerr<< "Error opening file " << CA_cert_file_name << " (not existing ?)\n";
		return NULL;
	
	}
	// ----------------------
	CA_cert = PEM_read_X509(CA_cert_file, NULL, NULL, NULL);
	if(!CA_cert){cerr<<"Error reading the CA certificate\n"; exit(1);}

	fclose(CA_cert_file);

	// Load the CRL
	X509_CRL* CA_CRL = NULL;
	FILE* CA_CRL_file = fopen(CRL_file_name.c_str(), "r");
	if(!CA_CRL_file){
		
		cerr<<"Error opening file "<<CRL_file_name<<" (not existing ?)\n"; 
		return NULL;
	
	}

	CA_CRL = PEM_read_X509_CRL(CA_CRL_file, NULL, NULL, NULL);
	if(!CA_CRL){cerr<<"Error reading the CA CRL\n"; exit(1);}

	fclose(CA_CRL_file);
	// ----------------------

	//Build the store
    X509_STORE *store = X509_STORE_new();
    if(!store){

        cerr << "<ERR>  X509_STORE_new returned NULL\n";
	    return NULL;

    } 

    ret = X509_STORE_add_cert(store, CA_cert);
    if(ret != 1){

        cerr << "<ERR>  X509_STORE_add_cert failed!\n";
	    return NULL;

    }

    ret = X509_STORE_add_crl(store, CA_CRL);
    if(ret != 1){

        cerr << "<ERR>  X509_STORE_add_crl failed!\n";
	    return NULL;
        
    }

    ret = X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK);
    if(ret != 1){

        cerr << "<ERR>  X509_STORE_set_flags failed!\n";
	    return NULL;
        
    }

	return store;

}

void compute_hash(unsigned char*& digest, unsigned int &digest_len, unsigned char *clear_buf, unsigned int clear_buf_size){

	int ret;

	EVP_MD_CTX* ctx_hash;
	const EVP_MD *hash_function = EVP_sha256();
	digest_len = EVP_MD_size(hash_function);
	digest = (unsigned char *)malloc(digest_len);
	if(!digest){
	
		cerr << "<ERR>  malloc(digest) returned NULL\n";
		return;

	}

	ctx_hash = EVP_MD_CTX_new();
	
	ret = EVP_DigestInit(ctx_hash, hash_function);
	if(ret != 1){
		
		cerr << "<ERR>  EVP_DigestInit returned NULL\n";
		return;
	
	}
	
	ret = EVP_DigestUpdate(ctx_hash, clear_buf, clear_buf_size);
	if(ret != 1){
		
		cerr << "<ERR>  EVP_DigestUpdate returned NULL\n";
		return;
	
	}
	
	ret = EVP_DigestFinal(ctx_hash, digest, &digest_len);
	if(ret != 1){
		
		cerr << "<ERR>  EVP_DigestUpdate returned NULL\n";
		return;
	
	}
	
	EVP_MD_CTX_free(ctx_hash);

}

unsigned int generate_dh_secret(unsigned char*& dh_secret_out, EVP_PKEY* my_dh_prvkey, EVP_PKEY* peer_dh_pubkey){

	int ret;

	// Initializing shared secret derivation context
	EVP_PKEY_CTX *ctx_drv = EVP_PKEY_CTX_new(my_dh_prvkey, NULL);
	if(!ctx_drv){
	
		cerr << "<ERR>  EVP_PKEY_CTX_new returned NULL\n";
		exit(1);
	
	}
	ret = EVP_PKEY_derive_init(ctx_drv);
	if(ret <= 0){
	
		cerr << "<ERR>  EVP_PKEY_derive_init failed\n";
		exit(1);
	
	}
	EVP_PKEY_derive_set_peer(ctx_drv, peer_dh_pubkey);
	if(ret <= 0){
	
		cerr << "<ERR>  EVP_PKEY_derive_set_peer failed\n";
		exit(1);
	
	}

	// Retrieving shared secret's length
	size_t secret_len;
	ret = EVP_PKEY_derive(ctx_drv, NULL, &secret_len);
	if(ret <= 0){
	
		cerr << "<ERR>  EVP_PKEY_derive failed\n";
		exit(1);
	
	}

	// Deriving shared secred
	dh_secret_out = (unsigned char *)(malloc(int(secret_len)));
	if(!dh_secret_out){
	
		cerr << "<ERR>  malloc(dh_secret_out) returned NULL\n";
		exit(1);
	
	}
	
	ret = EVP_PKEY_derive(ctx_drv, dh_secret_out, &secret_len);
	if(ret <= 0){
	
		cerr << "<ERR>  EVP_PKEY_derive failed\n";
		exit(1);
	
	}

	return secret_len;
}

void generate_random_quantity(unsigned char* out_buf, unsigned int num_bytes){

	if(!out_buf) {

		out_buf = (unsigned char*)malloc(num_bytes);
		if(!out_buf){

			cerr << "<ERR>  malloc returned NULL!\n";
			exit(1);

		}
	}

	int ret = RAND_bytes(out_buf, num_bytes);
	if(ret != 1){

			cerr << "<ERR>  Error generating random quantity!\n";
			exit(1);

	}
	
}

bool signature_is_verified(unsigned char* clear_buf, unsigned int clear_size, unsigned char *sig_buf, 
							unsigned int sig_size, EVP_PKEY* pubkey){

	int ret;

	EVP_MD_CTX *ctx_verify_signature = EVP_MD_CTX_new();
	if(!ctx_verify_signature){
	
		cerr << "<ERR>  EVP_MD_CTX_new returned NULL\n";
		return false;
	
	}
	
    // Declare some useful variables
	const EVP_MD *hash_func = EVP_sha256();
	
	ret = EVP_VerifyInit(ctx_verify_signature, hash_func);
	if(ret != 1){
		
		cerr << "<ERR>  EVP_VerifyInit failed\n";
		return false;
	
	}
	
	ret = EVP_VerifyUpdate(ctx_verify_signature, clear_buf, clear_size);
	if(ret != 1){
		
		cerr << "<ERR>  EVP_VerifyUpdate failed\n";
		return false;
	
	}
	
	ret = EVP_VerifyFinal(ctx_verify_signature, sig_buf, sig_size, pubkey);
	if(ret == -1){
		
		cerr << "<ERR>  EVP_VerifyFinal returned " << ret << "(invalid signature?)\n";
		return false;
	
	} else if(ret == 0) {
	
		cerr << "<ERR signature_is_verified()>  Invalid signature\n";
		return false;

	}

	return true;

}

unsigned char* digitally_sign(unsigned char *clear_buf, int clear_size, unsigned int &signature_len, EVP_PKEY* prvkey){

	int ret;

	int max_sig_len = EVP_PKEY_size(prvkey);
	unsigned char *signature = (unsigned char *)malloc(max_sig_len);
	if(!signature){
	
		cerr << "<ERR>  malloc(signature) returned NULL!\n";
		exit(1);
		
	} 
	
	EVP_MD_CTX *ctx_sign = EVP_MD_CTX_new();
	if(!ctx_sign){
	
		cerr << "<ERR>  EVP_MD_CTX_new failed!\n";
		exit(1);
		
	}
	
	const EVP_MD *hash_func = EVP_sha256();

	ret = EVP_SignInit(ctx_sign, hash_func);
	if(ret != 1){
		
		cerr << "<ERR>  EVP_SignInit failed\n";
		exit(1);
	
	}

	ret = EVP_SignUpdate(ctx_sign, clear_buf, clear_size);
	if(ret != 1){
		
		cerr << "<ERR>  EVP_SignUpdate failed\n";
		exit(1);
	
	}

	ret = EVP_SignFinal(ctx_sign, signature, &signature_len, prvkey);
	if(ret != 1){
		
		cerr << "<ERR>  EVP_SignFinal() failed\n";
		exit(1);
	
	}
	
	EVP_MD_CTX_free(ctx_sign);

	return signature;
}



X509* load_certificate(const char* cert_file_name){

    FILE* sv_cert_file = fopen(cert_file_name, "r");
	if(!sv_cert_file){
		
		cerr<<" <ERR> Error opening file "<< cert_file_name <<" (not existing ?)\n"; 
		return NULL;
	}

	X509* sv_cert = PEM_read_X509(sv_cert_file, NULL, NULL, NULL);
	if(!sv_cert){
		
		cerr<<" <ERR> Error reading the server certificate\n"; 
		return NULL;

	}

	cout << "<OK>   Certificate loaded\n\n";

	fclose(sv_cert_file);

    return sv_cert;

}

EVP_PKEY* load_privkey(const char * prvkey_file_name, string password){

	FILE* prvkey_file = fopen(prvkey_file_name, "r");
	if(!prvkey_file){ 

		cerr << "<ERR>  cannot open file '" << prvkey_file_name << "' (missing?)\n"; 
		return NULL; 

	}

	EVP_PKEY* prvkey = PEM_read_PrivateKey(prvkey_file, NULL, NULL, (void*)password.c_str());
	fclose(prvkey_file);

	if(!prvkey){ 
		
		cerr << "<ERR>  PEM_read_PrivateKey returned NULL\n"; 
		return NULL;  
		
	}

	return prvkey;
}