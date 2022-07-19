#include "client-class.h"
#include "./shared-constants.h"
#include "./shared-functions.h"
#include "./client-constants.h"
#include <errno.h>
using namespace std;

// ---------------------------------------
// 				UTILITY
// ---------------------------------------

void printMatchResult(const FourInARow::Result &result) {
    if (result == FourInARow::Result::WIN) {
        std::cout << "You win! Those moves were superb!\n";
    } else if (result == FourInARow::Result::LOSS) {
        std::cout << "You lose. Play again to get better! Or search for \"solved games\"...\n";
    } else {
        std::cout << "Draw! What a tight match!\n";
    }
}

void clearScreen() {
    cout << "\033[2J\033[1;1H" << flush;
}

map<string, string> print_and_store_online_players_menu(unsigned char* list_of_online_players, uint16_t num_of_players){

	uint16_t index = 0;

	map<string, string> list_to_return;

	cout << "---------------------------------\n";
	cout << "          ONLINE PLAYERS\n";
	cout << "---------------------------------\n";

	unsigned char username_tmp[MAX_USERNAME_LEN];

	for(uint16_t i= 0; i < num_of_players; i++){

		strncpy((char *)username_tmp, (char *)list_of_online_players + index, MAX_USERNAME_LEN);
		username_tmp[MAX_USERNAME_LEN-1] = '\0';

		string username_tmp_str((char*)username_tmp);

		list_to_return[to_string(i+1)] = username_tmp_str;

		cout << i+1 << ". " << username_tmp<<"\n";

		index += MAX_USERNAME_LEN;
	}
	cout << "\n---------------------------------\n";

	return list_to_return;
}

uint16_t get_num_of_online_players(unsigned char *buffer){

	uint16_t num_of_online_players; 

	memcpy(&num_of_online_players, buffer, sizeof(num_of_online_players));

	return num_of_online_players;

}

// -------------------------------------------------------------------------------------------------

// ---------------------------------------
// 	   CLASS FUNCTION IMPLEMENTATION
// ---------------------------------------

Client::Client(){}

Client::Client(string username){

    setUsername(username);
	makeConnection();
	user_prvkey_file_name = CLIENT_PUBKEY_DIR_PATH + this->username + "_privkey.pem";

}

void Client::setUsername(string username){

    this->username = username;

}

void Client::makeConnection(){

    // Creating socket
    master_fd = socket(AF_INET, SOCK_DGRAM, 0);	

	memset(&sv_addr, 0, sizeof(sv_addr)); // Cleaning the buffer 
    sv_addr.sin_family = AF_INET;
    sv_addr.sin_port = htons(SERVER_PORT);
    inet_pton(AF_INET, SERVER_IP , &sv_addr.sin_addr);

	len_sv_addr = sizeof(sv_addr);

}

bool Client::authentication(string password){
    
    int ret;

    unsigned char packet[MAX_PACKET_SIZE]; // Packet to send
    unsigned char buffer_in[MAX_PACKET_SIZE]; // Incoming packet

    // Retrieve the user private key from file for future use
	user_prvkey = load_privkey(user_prvkey_file_name.c_str(), password);
	if(!user_prvkey){

		cerr << "<ERR>  Error loading user private key!\n\n";
		return false;

	}
	// ------------------------------------------------------

    generate_random_quantity(last_nonce_user, NONCE_LEN);

    // hello_c packet format: | Opcode (2 bytes) | username (16 bytes + 1 null-termination) | nonce (2 bytes) |
	uint16_t opcode = htons(HELLO_C_PKT); // Operative code for hello_c packet

	memset(packet, 0, MAX_PACKET_SIZE); // Clean the buffer

	uint16_t num_fields = 3;

	vector<unsigned char *> pkt_fields_pkt1 = {(unsigned char*)&opcode, (unsigned char*)username.c_str(), 
												last_nonce_user};
	vector<unsigned int> pkt_fields_len_pkt1 = {OPCODE_LEN, MAX_USERNAME_LEN, 
												NONCE_LEN};

	unsigned int packet_size = load_in_buffer(packet, pkt_fields_pkt1, pkt_fields_len_pkt1, num_fields);

    ret = sendto(master_fd, packet, packet_size, 0,
                 (struct sockaddr*)&sv_addr, sizeof(sv_addr));
    if(ret < 0){
        cerr<<"<ERR>  Hello message not sent. ret = "<<ret<<endl;
        return false;
    }

    memset(buffer_in, 0, MAX_PACKET_SIZE); // Clean the buffer
	
	cout<<"<INFO> Waiting the server's certificate\n";

    ret = recvfrom(master_fd, buffer_in, MAX_PACKET_SIZE, 0,
	               (sockaddr*)&sv_addr, &len_sv_addr);
	if(ret < 0){

		cerr << "<ERR>  Error while receiving the HELLO_S packet\n";
		return false;

	}
	// -------------------

    // First, check the opcode
	opcode = get_opcode(buffer_in);
	if(!opcode_is_ok(opcode, HELLO_S_PKT) && !opcode_is_ok(opcode, ERR_USER_LOGGED_S_PKT) 
		&& !opcode_is_ok(opcode, ERR_CONNECTION_S_PKT)){

		cerr << "<ERR>  Wrong message arrived\n";
		return false;

	}
	// ------------------------

	if(opcode == ERR_CONNECTION_S_PKT){

		cout << "<INFO> Received ERR_CONNECTION_S_PKT, disconnecting!\n";
		return false;

	} 

	unsigned int sv_cert_size;
	unsigned int signature_len;
	unsigned int sv_dh_pubkey_size;
	unsigned char *sv_cert_buf = NULL;
	unsigned char nonce_sv[NONCE_LEN];
	unsigned char *signature = NULL;
	unsigned char *sv_dh_pubkey_buf = NULL;
	X509* sv_cert = NULL;
	X509_STORE *store = NULL;
	vector<unsigned char *> pkt_fields_pkt51;
	vector<unsigned int> pkt_fields_len_pkt51;
	vector<unsigned char *> pkt_fields_pkt2;
	vector<unsigned int> pkt_fields_len_pkt2;

	if(opcode == ERR_USER_LOGGED_S_PKT){
		// Error packet, user already logged-in/online

		cout << "<DBG>  Error, I'm already logged in!"<< endl << endl;


		// Retrieve fixed length fields from packet 51
		num_fields = 4;
		pkt_fields_pkt51 = {(unsigned char*)&sv_cert_size, sv_cert_buf,
							(unsigned char*)&signature_len, signature};

		pkt_fields_len_pkt51 = {sizeof(unsigned int), 0, 
								sizeof(unsigned int), 0};

		get_fixed_len_fields(pkt_fields_pkt51, pkt_fields_len_pkt51, buffer_in, num_fields, true);

		// ------------------------------------------
	} else {

		// Retrieve fixed length fields from packet 2
		num_fields = 7;
		pkt_fields_pkt2 = {(unsigned char*)&sv_cert_size, sv_cert_buf, nonce_sv, 
							 (unsigned char*)&sv_dh_pubkey_size, sv_dh_pubkey_buf,
							(unsigned char*)&signature_len, signature};

		pkt_fields_len_pkt2 = {sizeof(unsigned int), 0, NONCE_LEN, 
								sizeof(unsigned int), 0, 
								sizeof(unsigned int), 0};

		get_fixed_len_fields(pkt_fields_pkt2, pkt_fields_len_pkt2, buffer_in, num_fields, true);
		// ------------------------------------------

		// Allocate space for buffers of variable length fields
		sv_dh_pubkey_size = ntohs(sv_dh_pubkey_size);
		sv_dh_pubkey_buf = (unsigned char*)malloc(sv_dh_pubkey_size);
		if(!sv_dh_pubkey_buf){

				cerr << "<ERR> malloc() returned NULL, disconnecting!\n\n";
				return false;
				
		}
		// -----------------------------------------------------
	}

	// Allocate space for buffers of variable length fields
	sv_cert_size = ntohs(sv_cert_size);
	sv_cert_buf = (unsigned char*)malloc(sv_cert_size);
	signature_len = ntohs(signature_len);
	signature = (unsigned char*)malloc(signature_len);

	if(!sv_cert_buf || !signature){

		cerr << "<ERR> malloc() returned NULL, disconnecting!\n\n";
		return false;
				
	}
	// -----------------------------------------------------
	

	if(opcode == ERR_USER_LOGGED_S_PKT){
		// Retrieve variable length fields from packet 2
		pkt_fields_pkt51 = {NULL, sv_cert_buf, 
							NULL, signature};
		pkt_fields_len_pkt51 = {sizeof(unsigned int), sv_cert_size, 
								sizeof(unsigned int), signature_len};

		get_variable_len_fields(pkt_fields_pkt51, pkt_fields_len_pkt51, buffer_in, num_fields);

		// ---------------------------------------------
	} else {

		// Retrieve variable length fields from packet 2
		pkt_fields_pkt2 = {NULL, sv_cert_buf, NULL, 
							NULL, sv_dh_pubkey_buf, 
							NULL, signature};
		pkt_fields_len_pkt2 = {sizeof(unsigned int), sv_cert_size, NONCE_LEN, 
								sizeof(unsigned int),sv_dh_pubkey_size, 
								sizeof(unsigned int), signature_len};

		get_variable_len_fields(pkt_fields_pkt2, pkt_fields_len_pkt2, buffer_in, num_fields);
		// ---------------------------------------------
	}
	
	// Decode the sv certificate
	sv_cert = d2i_X509(NULL, (const unsigned char **)&sv_cert_buf, (long)sv_cert_size);
	if(!sv_cert){

		cerr<<"<ERR> Error storing the server certificate\n"; 
		return false;

	}
	// ----------------------------------------------

	// Create the store with the CA certificate + CRL 
	string CA_cert_file_name(CA_CERT_FILE_NAME);
	string CRL_file_name(CRL_FILE_NAME);
	store = build_store(CA_cert_file_name, CRL_file_name);
	if(!store){

		cerr << "<ERR>  Error creating the store!\n\n";
		return false;

	}

	cout << "<OK>   Store built successfully!\n\n";
	// -----------------------------------------------

	cout << "<INFO> Verifying the digital signature on user nonce + server DH ephemeral key\n";

	// Verify the subject certificate with the store
	if(!certificate_is_verified(store, sv_cert)){

		cerr << "<ERR>  Verification of the certificate failed!\n\n";
		return false;
	}

	cout << "<OK>   Certificate is valid!\n\n";
	//----------------------------------------------

	// Retrieve the server's public key from the certificate
	EVP_PKEY* sv_pubkey = X509_get_pubkey(sv_cert);
	if(!sv_pubkey){

		cerr << "<ERR>  X509_get_pubkey() returned NULL\n";
		return false;

	}
	// -----------------------------------------------------

	// Compose the message to be verified (nonce user + server dh ephemeral key)
	unsigned int cleartext_to_verify_size;
	unsigned char *cleartext_to_verify = NULL;

	if(opcode == ERR_USER_LOGGED_S_PKT){

		cleartext_to_verify_size = NONCE_LEN;
		cleartext_to_verify = (unsigned char *)malloc(cleartext_to_verify_size);
		if(!cleartext_to_verify){

			cerr << "<ERR>  malloc() returned NULL, disconnecting!\n\n";
			return false;
					
		}
		
		memset(cleartext_to_verify, 0, cleartext_to_verify_size); // Cleaning the buffer;

		// Digitally sign the user nonce + the server dh ephemeral key
		num_fields = 1;

		memcpy(cleartext_to_verify, last_nonce_user, NONCE_LEN);

	} else {
		if(NONCE_LEN > UINT_MAX - sv_dh_pubkey_size){

			cerr << "<ERR>  Too big unsigned int\n\n";
			exit(1);

		}
		cleartext_to_verify_size = NONCE_LEN + sv_dh_pubkey_size;
		cleartext_to_verify = (unsigned char *)malloc(cleartext_to_verify_size);
		if(!cleartext_to_verify){

			cerr << "<ERR>  malloc() returned NULL, disconnecting!\n\n";
			return false;
					
		}
		memset(cleartext_to_verify, 0, cleartext_to_verify_size); // Cleaning the buffer;

		num_fields = 2;

		vector<unsigned char *> cleartext_to_verify_pkt2_fields = {last_nonce_user, sv_dh_pubkey_buf};
		vector<unsigned int> cleartext_to_verify_pkt2_fields_len = {NONCE_LEN, sv_dh_pubkey_size};

		load_in_buffer(cleartext_to_verify, cleartext_to_verify_pkt2_fields, 
						cleartext_to_verify_pkt2_fields_len, num_fields);

	}
		
	if(!signature_is_verified(cleartext_to_verify, cleartext_to_verify_size, signature, 
								signature_len, sv_pubkey)){

		cerr << "<ERR> Signature is not valid!\n\n";
		return false;

	}

#pragma optimize("", off)
	memset(signature, 0, signature_len);
#pragma optimize("", on)
	free(signature);

	cout << "<OK>   Signature is valid!\n\n";
	// Since the signature is verified the message is fresh (the user nonce is in the signature)

	if(opcode == ERR_USER_LOGGED_S_PKT){

		cout << "<INFO> This user is already logged-in/online\n\n";
		return false;
	}
	// ----------------------------------------------

	// Deserialize server DH ephemeral key
	EVP_PKEY *sv_dh_pubkey = NULL;
	sv_dh_pubkey = d2i_PUBKEY(NULL, (const unsigned char **)&sv_dh_pubkey_buf, (long)sv_dh_pubkey_size);
	if(!sv_dh_pubkey){

		cerr << "<ERR>  Error deserializing server DH ephemeral key\n";
		return false;

	}
	cout << "<OK>   Server DH ephemeral key deserialization done!\n\n";
	// ----------------------------------

	// Packet 3 

	// This function returns my dh ephemeral (public) key
	string user_dh_prvkey_file_name = CLIENT_PUBKEY_DIR_PATH + username + "_dh_key.pem";
	//EVP_PKEY* user_dh_pubkey = create_and_store_dh_key(user_dh_prvkey_file_name.c_str());

	EVP_PKEY* user_dh_prvkey = create_and_store_dh_prvkey(user_dh_prvkey_file_name.c_str());

	if(!user_dh_prvkey){

		cerr << "<ERR>  Error creating and storing dh private key!\n";
		return false;

	}

	cout << "<OK>   DH private key retrieved!\n\n";

	EVP_PKEY* user_dh_pubkey = load_dh_pubkey(user_dh_prvkey_file_name.c_str());
	if(!user_dh_pubkey){

		cerr << "<ERR>  Error retrieving dh pubkey!\n";
		return false;

	}

	cout << "<OK>   DH public key retrieved!\n\n";

	// Serialize the DH ephemeral key to be sent over socket
	unsigned char* user_dh_pubkey_buf = NULL;
	unsigned int USER_DH_PUBKEY_SIZE = i2d_PUBKEY(user_dh_pubkey, &user_dh_pubkey_buf);
	unsigned int user_dh_pubkey_size = htons(USER_DH_PUBKEY_SIZE);

	if(NONCE_LEN > UINT_MAX - USER_DH_PUBKEY_SIZE){

		cerr << "<ERR>  Too big number\n\n";
		exit(1);

	}
	unsigned int cleartext_dig_sig_pkt3_size = NONCE_LEN + USER_DH_PUBKEY_SIZE; // Size of stuffs to be digitally signed
	unsigned char *cleartext_dig_sig_pkt3 = (unsigned char *)malloc(cleartext_dig_sig_pkt3_size);

	if(!cleartext_dig_sig_pkt3 || !user_dh_pubkey_buf) {
		
		cerr << "<ERR> malloc() for dig sig packet 3 returned NULL!\n";
		return false;

	}
	// -----------------------------------------------------

	unsigned int SIGNATURE_LEN;

	// Digitally sign the server nonce + the user dh ephemeral key
	num_fields = 2;

	vector<unsigned char *> dig_sig_fields_pkt3 = {nonce_sv, user_dh_pubkey_buf};
	vector<unsigned int> dig_sig_fields_len_pkt3 = {NONCE_LEN, USER_DH_PUBKEY_SIZE};

	load_in_buffer(cleartext_dig_sig_pkt3, dig_sig_fields_pkt3, dig_sig_fields_len_pkt3, num_fields);

	unsigned char *dig_sig_pkt3 = (unsigned char *)malloc(EVP_PKEY_size(user_prvkey));
	if(!dig_sig_pkt3){

		cerr << "<ERR> malloc(dig_sig_pkt3) returned NULL!\n";
		logout();
		exit(1);

	}

	dig_sig_pkt3 = digitally_sign(cleartext_dig_sig_pkt3, cleartext_dig_sig_pkt3_size, SIGNATURE_LEN, 
									user_prvkey);
	if(!dig_sig_pkt3){

		cerr << "<ERR>  Error generating the signature!\n";
		return false;

	}

	cout << "<OK>   Signature for packet 3 generated!\n\n";
	// ------------------------------------------------------------

	// Convert the signature len to be sent over the nw
	signature_len = htons(SIGNATURE_LEN);
	// -------------------------------------------------

	// Prepare packet 3 to be sent
	memset(&packet, 0, MAX_PACKET_SIZE); // Cleaning the buffer
	
	opcode = htons(HELLO_DONE_C_PKT); // Operative code for hello_c packet

	num_fields = 5;

	vector<unsigned char *> pkt_fields_pkt3 = {(unsigned char*)&opcode,  
												(unsigned char*)&user_dh_pubkey_size, user_dh_pubkey_buf,
												(unsigned char*)&signature_len, dig_sig_pkt3};
	vector<unsigned int> pkt_fields_len_pkt3 = {OPCODE_LEN,
												sizeof(unsigned int), USER_DH_PUBKEY_SIZE, 
												sizeof(unsigned int), SIGNATURE_LEN};


	packet_size = load_in_buffer(packet, pkt_fields_pkt3, pkt_fields_len_pkt3, num_fields);
	// ---------------------------

	// Send out packet 3
	// cout<<"<INFO> Sending the dig sig AND DH ephemeral key to the server\n";

	ret = sendto(master_fd, packet, packet_size, 0,
				(struct sockaddr*)&sv_addr, sizeof(sv_addr));
	if( ret < 0 ){

		cerr<<"<ERR> Error sending the dig sig AND DH ephemeral key to the server\n";
		return false;

	}
	// ------------------

	// At this point client and server both knows each other's DH ephemeral key
	// --> They can generate the shared secret
	
	// Generate the dh secret
	unsigned char *dh_secret = NULL;

	size_t dh_secret_len = generate_dh_secret(dh_secret, user_dh_prvkey, sv_dh_pubkey);

	// We will use the hash of the shared secret as a key for AES_GCM
	unsigned char *shared_secret_digest = NULL;
	unsigned int shared_secret_digest_len; 

	compute_hash(shared_secret_digest, shared_secret_digest_len, dh_secret, (unsigned int)dh_secret_len);
	
	memcpy(session_key, shared_secret_digest, sym_enc_dec_key_len);

#pragma optimize("", off)
	memset(dh_secret, 0, dh_secret_len);
	memset(shared_secret_digest, 0, shared_secret_digest_len);
	memset(cleartext_to_verify, 0, cleartext_to_verify_size);
	memset(dig_sig_pkt3, 0, SIGNATURE_LEN);
	memset(cleartext_dig_sig_pkt3, 0, cleartext_dig_sig_pkt3_size);
	memset(user_dh_pubkey_buf, 0, USER_DH_PUBKEY_SIZE);

#pragma optimize("", on)
	free(dh_secret);
	free(shared_secret_digest);
	free(cleartext_to_verify);
	free(dig_sig_pkt3);
	free(cleartext_dig_sig_pkt3);
	free(user_dh_pubkey_buf);
	return true;
}

bool Client::sendRequestListOnlinePlayers(){

	unsigned char packet[MAX_PACKET_SIZE];
	memset(packet, 0, MAX_PACKET_SIZE); // Cleaning the buffer

	// I need to authenticate the sequence number to avoid replay attacks, or reordering. 
	unsigned char *sym_enc_iv_pkt4 = NULL; 

	uint16_t opcode = REQ_PLAYERS_LIST_C_PKT;
	
	unsigned int aad_size = OPCODE_LEN + sizeof(seq_write_ops);
	unsigned char *aad = (unsigned char*)malloc(aad_size);
	if(!aad){

		cerr << "<ERR> malloc() returned NULL, disconnecting!\n\n";
		logout();
		exit(1);
				
	}

	unsigned char *tag_pkt4 = NULL;
	unsigned char *_dummy_cphr = NULL;

	// Concatenate AAD fields (Opcode, seq_write_ops) 
	uint16_t num_fields = 2;

	vector<unsigned char *> aad_fields_pkt4 = {(unsigned char*)&opcode, (unsigned char*)&seq_write_ops};
	vector<unsigned int> aad_fields_pkt4_len = {OPCODE_LEN, sizeof(seq_write_ops)};

	aad_size = load_in_buffer(aad, aad_fields_pkt4, aad_fields_pkt4_len, num_fields);
	// ----------------------------------------------

	// Apply AES_GCM and get the tag and the IV
	sym_enc_and_auth(session_key, sym_enc_iv_pkt4, NULL, 0, _dummy_cphr, aad, aad_size, tag_pkt4);
	// ----------------------------------------

	// Prepare packet
	memset(packet, 0, MAX_PACKET_SIZE); // Cleaning the buffer

	opcode = htons(opcode);

	num_fields = 3;
	
	vector<unsigned char *> pkt_fields_pkt4 = {(unsigned char*)&opcode, sym_enc_iv_pkt4, tag_pkt4};
	vector<unsigned int> pkt_fields_pkt4_len = {OPCODE_LEN, sym_enc_dec_iv_len, TAG_LEN};
	
	unsigned int packet_size = load_in_buffer(packet, pkt_fields_pkt4, pkt_fields_pkt4_len, num_fields);

#pragma optimize("", off)
	memset(sym_enc_iv_pkt4, 0, sym_enc_dec_iv_len);
	memset(tag_pkt4, 0, TAG_LEN);
	memset(aad, 0, aad_size);

#pragma optimize("", on)
	free(sym_enc_iv_pkt4);
	free(tag_pkt4);
	free(aad);
	// -----------------

	// Send out packet 4
	//cout<<"<INFO> Sending REQ_PLAYERS_LIST_C_PKT\n";

	int ret = sendto(master_fd, packet, packet_size, 0,
				(struct sockaddr*)&sv_addr, sizeof(sv_addr));
	if( ret < 0 ){

		cerr<<"<ERR> Error sending REQ_PLAYERS_LIST_C_PKT\n";
		return false;

	}

	//cout << "<OK>   REQ_PLAYERS_LIST_C_PKT sent.\n\n";

	// Increment the counter of write ops
	incrementSeqWriteOps();
	// ----------------------------------

	return true;

}

map<string, string> Client::recvListOnlinePlayers(){

	unsigned char buffer_in[MAX_PACKET_SIZE];

	// Receive REP_PLAYERS_LIST_S_PKT
	memset(buffer_in, 0, MAX_PACKET_SIZE);

	int ret = recvfrom(master_fd, buffer_in, MAX_PACKET_SIZE, 0,
					(sockaddr*)&sv_addr, &len_sv_addr);

	if(ret < 0){

		cerr << "<ERR>  Error while receiving REP_PLAYERS_LIST_S_PKT\n\n";
		return {};

	}

	//cout << "<OK>   REP_PLAYERS_LIST_S_PKT received.\n\n";
	// --------------------------------

	// First, check the opcode
	uint16_t opcode = get_opcode(buffer_in);
	if(!opcode_is_ok(opcode, REP_PLAYERS_LIST_S_PKT) && !opcode_is_ok(opcode, ERR_INTERNAL_S_PKT)){

		cerr << "<ERR>  Wrong message arrived\n";
		return {};

	}
	// ------------------------

	if(opcode == ERR_INTERNAL_S_PKT){

		cout << "Server internal error, disconnecting\n\n";
		exit(1);
		
	} 

	// Declare useful variables
	unsigned char *sym_dec_iv_pkt5 = (unsigned char*)malloc(sym_enc_dec_iv_len);
	unsigned char *tag_pkt5 = (unsigned char*)malloc(TAG_LEN);
	if(!sym_dec_iv_pkt5 || !tag_pkt5){

		cerr << "<ERR> malloc() returned NULL, disconnecting!\n\n";
		logout();
		exit(1);
				
	}	

	unsigned char *cphr_buf_pkt5= NULL;
	unsigned int cphr_buf_pkt5_len;
	// ------------------------

	// Retrieve fixed length fields from packet 5
	uint16_t num_fields = 4;
	vector<unsigned char *> pkt_fields_pkt5 = {sym_dec_iv_pkt5, (unsigned char*)&cphr_buf_pkt5_len, 
												cphr_buf_pkt5, tag_pkt5};

	vector<unsigned int> pkt_fields_pkt5_len= {sym_enc_dec_iv_len, sizeof(cphr_buf_pkt5_len),
												0, TAG_LEN};

	get_fixed_len_fields(pkt_fields_pkt5, pkt_fields_pkt5_len, buffer_in, num_fields, true);
	// -------------------------------------------

	// Allocate space for buffers of variable length fields
	cphr_buf_pkt5_len = ntohs(cphr_buf_pkt5_len);
	cphr_buf_pkt5 = (unsigned char*)malloc(cphr_buf_pkt5_len);
	if(!cphr_buf_pkt5){

		cerr << "<ERR> malloc() returned NULL, disconnecting!\n\n";
		exit(1);
				
	}	
	// -----------------------------------------------------

	// Retrieve variable length fields from packet 5
	pkt_fields_pkt5 = {NULL, NULL, 
						cphr_buf_pkt5, NULL};
	pkt_fields_pkt5_len = {sym_enc_dec_iv_len, sizeof(cphr_buf_pkt5_len), 
							cphr_buf_pkt5_len, TAG_LEN};

	get_variable_len_fields(pkt_fields_pkt5, pkt_fields_pkt5_len, buffer_in, num_fields);
	// ---------------------------------------------

	// Declare variables for symmetric decryption + authentication
	unsigned char *clear_buf_pkt5 = NULL;
	unsigned int aad_size_pkt5 = OPCODE_LEN + sizeof(seq_read_ops); 
	unsigned char *aad_pkt5 = (unsigned char *)malloc(aad_size_pkt5);
	if(!aad_pkt5){

		cerr << "<ERR> malloc() returned NULL, disconnecting!\n\n";
		logout();
		exit(1);
				
	}	

	// Concatenate AAD fields
	num_fields = 2;

	vector<unsigned char *> aad_fields_pkt5 = {(unsigned char*)&opcode, (unsigned char*)&seq_read_ops};
	vector<unsigned int> aad_fields_pkt5_len = {OPCODE_LEN, sizeof(seq_read_ops)};

	aad_size_pkt5 = load_in_buffer(aad_pkt5, aad_fields_pkt5, aad_fields_pkt5_len, num_fields);
	// ------------------------

	// Apply AES_GCM and verify the tag, put the clear text in clear_buf_pkt5
	int clear_size_pkt5 = sym_dec_and_auth(session_key, sym_dec_iv_pkt5, cphr_buf_pkt5, cphr_buf_pkt5_len,
											clear_buf_pkt5, aad_pkt5, aad_size_pkt5, tag_pkt5);
	// ------------------------	

	// If the tag is valid, the number of read ops is correct --> message is fresh
	//cout << "<OK>   Message is fresh!\n\n";
	incrementSeqReadOps();

	// Get the num of online players from clear_buf_pkt5
	uint16_t num_of_online_players = get_num_of_online_players(clear_buf_pkt5);

	map<string, string> list_of_online_players_menu = 
		print_and_store_online_players_menu(clear_buf_pkt5 + sizeof(uint16_t), num_of_online_players);


#pragma optimize("", off)
	memset(sym_dec_iv_pkt5, 0, sym_enc_dec_iv_len);
	memset(tag_pkt5, 0, TAG_LEN);
	memset(cphr_buf_pkt5, 0, cphr_buf_pkt5_len);
	memset(aad_pkt5, 0, aad_size_pkt5);
	memset(clear_buf_pkt5, 0, clear_size_pkt5);

#pragma optimize("", on)
	free(sym_dec_iv_pkt5);
	free(tag_pkt5);
	free(cphr_buf_pkt5);
	free(aad_pkt5);
	free(clear_buf_pkt5);

	return list_of_online_players_menu;
}

bool Client::sendChallengeRequest(const char *player_to_challenge){

	unsigned char packet[MAX_PACKET_SIZE];
	memset(packet, 0, MAX_PACKET_SIZE); // Cleaning the buffer

	// I need to authenticate the sequence number to avoid replay attacks, or reordering. 
	unsigned char *sym_enc_iv = NULL; 

	uint16_t opcode = REQ_CHALLENGE_C_PKT;

	unsigned int aad_size = OPCODE_LEN + sizeof(seq_write_ops);
	unsigned char *aad = (unsigned char *)malloc(aad_size);
	unsigned char *tag = NULL;
	unsigned char *cphr_buf = NULL;
	unsigned int clear_size = MAX_USERNAME_LEN;
	unsigned char *clear_buf = (unsigned char *)malloc(clear_size);
	if(!aad || !clear_buf){

		cerr << "<ERR> malloc() returned NULL, disconnecting!\n\n";
		logout();
		exit(1);
				
	}	

	// Concatenate AAD fields (Opcode, seq_write_ops)
	uint16_t num_fields = 2;

	vector<unsigned char *> aad_fields = {(unsigned char*)&opcode, (unsigned char*)&seq_write_ops};
	vector<unsigned int> aad_fields_len = {OPCODE_LEN, sizeof(seq_write_ops)};

	aad_size = load_in_buffer(aad, aad_fields, aad_fields_len, num_fields);
	// ----------------------------------------------

	// Fill the clear buffer to be encrypted
	memcpy(clear_buf, player_to_challenge, MAX_USERNAME_LEN);
	// -------------------------------------

	// Apply AES_GCM and get the ciphertext, the tag and the IV
	unsigned int CPHR_LEN = sym_enc_and_auth(session_key, sym_enc_iv, clear_buf,
												clear_size, cphr_buf, aad, aad_size, tag);
	// --------------------------------------------------------

	// Convert the cphr len to be sent over the nw
	unsigned int cphr_len = htons(CPHR_LEN);
	// -------------------------------------------

	// Prepare packet REQ_CHALLENGE_C
	opcode = htons(opcode);

	num_fields = 5;

	vector<unsigned char *> pkt_fields = {(unsigned char*)&opcode, sym_enc_iv,(unsigned char*)&cphr_len, 
											cphr_buf, tag};
	vector<unsigned int> pkt_fields_len = {OPCODE_LEN, sym_enc_dec_iv_len, sizeof(cphr_len), 
											CPHR_LEN, TAG_LEN};
	
	int packet_size = load_in_buffer(packet, pkt_fields, pkt_fields_len, num_fields);


#pragma optimize("", off)
	memset(sym_enc_iv, 0, sym_enc_dec_iv_len);
	memset(tag, 0, TAG_LEN);
	memset(cphr_buf, 0, CPHR_LEN);
#pragma optimize("", on)
	free(sym_enc_iv);
	free(tag);
	free(cphr_buf);
	// ------------------------------------

	// Send out REQ_CHALLENGE_C_PKT
	//cout<<"<INFO> Sending REQ_CHALLENGE_C_PKT\n";

	int ret = sendto(master_fd, packet , packet_size, 0,
					(struct sockaddr*)&sv_addr, sizeof(sv_addr));
	if( ret < 0 ){

		cerr<<"<ERR> Error sending REQ_CHALLENGE_C_PKT\n";
		return false;

	}

	//cout << "<OK>   REQ_CHALLENGE_C_PKT sent.\n\n";

	// Increment the counter of write ops
	incrementSeqWriteOps();
	// ------------------

#pragma optimize("", off)
	memset(aad, 0, aad_size);
	memset(clear_buf, 0, clear_size);
#pragma optimize("", on)
	free(aad);
	free(clear_buf);

	return true;

}

int Client::recvChallengeResponse(){

	unsigned char buffer_in[MAX_PACKET_SIZE];

	// Receive message
	memset(buffer_in, 0, MAX_PACKET_SIZE);

	int ret = recvfrom(master_fd, buffer_in, MAX_PACKET_SIZE, 0,
						(sockaddr*)&sv_addr, &len_sv_addr);

	if(ret < 0){

		cerr << "<ERR>  Error while receiving packet\n\n";
		logout();
		exit(1);

	}

	//cout << "<OK>   Packet received.\n\n";

	// First, check the opcode
	uint16_t opcode = get_opcode(buffer_in);
	if((opcode != FWD_ACC_CHALLENGE_S_PKT) && (opcode != FWD_REF_CHALLENGE_S_PKT) 
		&& (opcode != PLAYER_NOT_AVAILABLE_S_PKT) && (opcode != ERR_SEND_S_PKT) 
		&& (opcode != ERR_INTERNAL_S_PKT)){

		cerr << "<ERR>  Wrong message arrived (should have arrived FWD_ACC_CHALLENGE_S_PKT"
					" or FWD_REF_CHALLENGE_S_PKT or PLAYER_NOT_AVAILABLE_S_PKT or ERR_SEND_S_PKT)\n\n";
		logout();
		exit(1);

	}

	switch (opcode){

		case ERR_INTERNAL_S_PKT:

			cout << "Server internal error, disconnecting.\n";

			exit(1);

		case ERR_SEND_S_PKT:

			cout << "<ERR>  Server error in sending response\n";

			return -1;

		case FWD_ACC_CHALLENGE_S_PKT:
			// The challenger player enters here
			handleAcceptedChallenge(buffer_in);

			return FWD_ACC_CHALLENGE_S_PKT;
		
		case FWD_REF_CHALLENGE_S_PKT:

			handleRefusedChallenge(buffer_in, opcode);

			return FWD_REF_CHALLENGE_S_PKT;

		case PLAYER_NOT_AVAILABLE_S_PKT:

			handleWaitingPlayerPacket(buffer_in, opcode);

			return PLAYER_NOT_AVAILABLE_S_PKT;
		
		default:
			break;
	}
	
	
	return -1;
}

int Client::recvMessage(int sock_recv, unsigned char*& buffer_in_out){

	int ret;

	unsigned char buffer_in[MAX_PACKET_SIZE];

	sockaddr_in connecting_addr;
    socklen_t connecting_addr_len = sizeof(connecting_addr);
    memset(&connecting_addr, 0, sizeof(connecting_addr));

	// Receive message
	memset(buffer_in, 0, MAX_PACKET_SIZE);

	if(sock_recv != master_fd){

		ret = recvfrom(sock_recv, buffer_in, MAX_PACKET_SIZE, 0,
					(sockaddr*)&peer_addr, &len_peer_addr);

	} else {

		ret = recvfrom(sock_recv, buffer_in, MAX_PACKET_SIZE, 0,
						(sockaddr*)&connecting_addr, &connecting_addr_len);
	}

	if(ret < 0){

		cerr << "<ERR>  Error while receiving packet\n\n";
		cerr << "errno is: " << errno << endl;
		exit(1);

	}
	// --------------------------------

	memcpy(buffer_in_out, buffer_in, ret);

	// First, check the opcode
	uint16_t opcode = get_opcode(buffer_in);

	switch (opcode){

		case FWD_REQ_CHALLENGE_S_PKT:
			// Request to challenge from another player (forwarded by the server)
			
			return FWD_REQ_CHALLENGE_S_PKT;

		case FWD_ACC_CHALLENGE_S_PKT:
			// The challenged player enters here, receiving the peer's pubkey and (IP, port)

			return FWD_ACC_CHALLENGE_S_PKT;

		case PLAYER1_HELLO_P_PKT:
		{ 	
			cout << "Arrived PLAYER1_HELLO_P_PKT\n\n";
			peer_fd = socket(AF_INET, SOCK_DGRAM, 0);
			connect(peer_fd,(struct sockaddr*)&connecting_addr, sizeof(connecting_addr));

			return PLAYER1_HELLO_P_PKT;
		}

		case PLAYER2_HELLO_P_PKT:
		{
			cout << "Arrived PLAYER2_HELLO_P_PKT\n\n";
			peer_fd = socket(AF_INET, SOCK_DGRAM, 0);
			connect(peer_fd,(struct sockaddr*)&connecting_addr, sizeof(connecting_addr));
			return PLAYER2_HELLO_P_PKT;
		}
		case END_HANDSHAKE_P_PKT:

			return END_HANDSHAKE_P_PKT;

		case MOVE_P_PKT:

			return MOVE_P_PKT;

		default:
			cerr << "<ERR>  Wrong message arrived\n";
			break;
	}
	// ------------------------ 

	return -1;

}

void Client::handleChallengeRequest(unsigned char* buffer_in){

	// Declare useful variables
	uint16_t opcode = FWD_REQ_CHALLENGE_S_PKT;
	unsigned char *sym_dec_iv = (unsigned char*)malloc(sym_enc_dec_iv_len);
	unsigned char *tag = (unsigned char*)malloc(TAG_LEN);
	if(!sym_dec_iv || !tag){

		cerr << "<ERR> malloc() returned NULL, disconnecting!\n\n";
		logout();
		exit(1);
				
	}

	unsigned char *cphr_buf= NULL; 
	unsigned int cphr_buf_len;
	// ------------------------

	// Retrieve fixed length fields from packet
	uint16_t num_fields = 4;
	vector<unsigned char *> pkt_fields = {sym_dec_iv, (unsigned char*)&cphr_buf_len, cphr_buf, tag};

	vector<unsigned int> pkt_fields_len= {sym_enc_dec_iv_len, sizeof(cphr_buf_len), 0, TAG_LEN};

	get_fixed_len_fields(pkt_fields, pkt_fields_len, buffer_in, num_fields, true);
	// -------------------------------------------

	// Allocate space for buffers of variable length fields
	cphr_buf_len = ntohs(cphr_buf_len);
	cphr_buf = (unsigned char*)malloc(cphr_buf_len);
	if(!cphr_buf){

		cerr << "<ERR> malloc() returned NULL, disconnecting!\n\n";
		logout();
		exit(1);
				
	}
	// -----------------------------------------------------

	// Retrieve variable length fields from packet 5
	pkt_fields = {NULL, NULL, cphr_buf, NULL};
	pkt_fields_len = {sym_enc_dec_iv_len, sizeof(cphr_buf_len), cphr_buf_len, TAG_LEN};

	get_variable_len_fields(pkt_fields, pkt_fields_len, buffer_in, num_fields);
	// ---------------------------------------------

	// Declare variables for symmetric decryption + authentication
	unsigned char *clear_buf = NULL; 
	unsigned int aad_size = OPCODE_LEN + sizeof(seq_read_ops); 
	unsigned char *aad = (unsigned char *)malloc(aad_size);
	if(!aad){

		cerr << "<ERR> malloc() returned NULL, disconnecting!\n\n";
		logout();
		exit(1);
				
	}
	// ------------------------------------------------------------

	// Concatenate AAD fields
	num_fields = 2;

	vector<unsigned char *> aad_fields = {(unsigned char*)&opcode, (unsigned char*)&seq_read_ops};
	vector<unsigned int> aad_fields_len = {OPCODE_LEN, sizeof(seq_read_ops)};

	aad_size = load_in_buffer(aad, aad_fields, aad_fields_len, num_fields);
	// ------------------------

	// Apply AES_GCM and verify the tag, put the clear text in clear_buf_pkt5
	int clear_size = sym_dec_and_auth(session_key, sym_dec_iv, cphr_buf, cphr_buf_len,
										clear_buf, aad, aad_size, tag);

#pragma optimize("", off)
	memset(sym_dec_iv, 0, sym_enc_dec_iv_len);
	memset(tag, 0, TAG_LEN);
	memset(cphr_buf, 0, cphr_buf_len);
	memset(aad, 0, aad_size);
#pragma optimize("", on)										
	free(sym_dec_iv);
	free(tag);
	free(cphr_buf);
	free(aad);
	// ------------------------

	// If the tag is valid, check the number of read ops
	//cout << "<OK>   Message is fresh!\n\n";
	incrementSeqReadOps();

	unsigned char *requesting_player = (unsigned char*)malloc(MAX_USERNAME_LEN);
	if(!requesting_player){

		cerr << "<ERR> malloc() returned NULL, disconnecting!\n\n";
		logout();
		exit(1);
				
	}

	strncpy((char *)requesting_player, (const char*)clear_buf, MAX_USERNAME_LEN);
	requesting_player[MAX_USERNAME_LEN-1] = '\0';

	string choice;
	while (1){
	
		cout << "\n\nChallenge request from '" << requesting_player << "' \n" ;
		cout << "Accept(Y/y) or refuse(N/n) > ";
		cout.flush();
		getline(cin, choice);
		if(!cin){ 
		
			cerr<<"Error during input\n"; 
			exit(1);

		}

		if(!(choice.compare("Y")==0) && !(choice.compare("y")==0) && 
			!(choice.compare("N")==0) && !(choice.compare("n")==0)){

				cout << "Choice not allowed!\n";
				continue;

		}

		uint16_t opcode_reply;

		if(choice.compare("Y")==0 || choice.compare("y")==0){
			// Accept the challenge
			opcode_reply = ACCEPT_CHALLENGE_C_PKT;

			cout << "Challenge accepted !\n\n";
			sendReplyToChallenge(requesting_player, opcode_reply);

			return;
		}

		if(choice.compare("N")==0 || choice.compare("n")==0){
			// Refuse the challenge
			opcode_reply = REFUSE_CHALLENGE_C_PKT;
			sendReplyToChallenge(requesting_player, opcode_reply);

			return;
		}

		
		
	}

#pragma optimize("", off)
	memset(requesting_player, 0, MAX_USERNAME_LEN);
	memset(clear_buf, 0, clear_size);
#pragma optimize("", on)
	free(requesting_player);
	free(clear_buf);

}

void Client::sendReplyToChallenge(unsigned char *challenger_player, uint16_t opcode){

	unsigned char packet[MAX_PACKET_SIZE];
	memset(packet, 0, MAX_PACKET_SIZE); // Cleaning the buffer

	// I need to authenticate the sequence number to avoid replay attacks, or reordering. 

	unsigned char *sym_enc_iv = NULL; 
	unsigned int aad_size = OPCODE_LEN + sizeof(seq_write_ops);
	unsigned char *aad = (unsigned char *)malloc(aad_size);
	unsigned char *tag = NULL;
	unsigned char *cphr_buf = NULL;
	unsigned int clear_size = MAX_USERNAME_LEN;
	unsigned char *clear_buf = (unsigned char *)malloc(clear_size);
	if(!aad || !clear_buf){

		cerr << "<ERR> malloc() returned NULL, disconnecting!\n\n";
		logout();
		exit(1);
				
	}									

	// Concatenate AAD fields (Opcode, seq_write_ops)
	uint16_t num_fields = 2;

	vector<unsigned char *> aad_fields = {(unsigned char*)&opcode, (unsigned char*)&seq_write_ops};
	vector<unsigned int> aad_fields_len = {OPCODE_LEN, sizeof(seq_write_ops)};

	aad_size = load_in_buffer(aad, aad_fields, aad_fields_len, num_fields);
	// ----------------------------------------------

	// Fill the clear buffer to be encrypted
	memcpy(clear_buf, challenger_player, MAX_USERNAME_LEN);
	// -------------------------------------

	// Apply AES_GCM and get the ciphertext, the tag and the IV
	unsigned int CPHR_LEN = sym_enc_and_auth(session_key, sym_enc_iv, clear_buf,
												clear_size, cphr_buf, aad, aad_size, tag);

#pragma optimize("", off)
	memset(aad, 0, aad_size);
	memset(clear_buf, 0, clear_size);
#pragma optimize("", on)
	free(aad);
	free(clear_buf);
	// --------------------------------------------------------

	// Convert the cphr len to be sent over the nw
	unsigned int cphr_len = htons(CPHR_LEN);
	// --------------------------------------------

	// Prepare packet ACCEPT/REFUSE_CHALLENGE_C_PKT
	opcode = htons(opcode);

	num_fields = 5;

	vector<unsigned char *> pkt_fields = {(unsigned char*)&opcode, sym_enc_iv, (unsigned char*)&cphr_len, 
											cphr_buf, tag};
	vector<unsigned int> pkt_fields_len = {OPCODE_LEN, sym_enc_dec_iv_len, sizeof(cphr_len), 
											CPHR_LEN, TAG_LEN};
	
	int packet_size = load_in_buffer(packet, pkt_fields, pkt_fields_len, num_fields);

#pragma optimize("", off)
	memset(sym_enc_iv, 0, sym_enc_dec_iv_len);
	memset(tag, 0, TAG_LEN);
	memset(cphr_buf, 0, CPHR_LEN);
#pragma optimize("", on)
	free(sym_enc_iv);
	free(tag);
	free(cphr_buf);

	// ------------------------------------

	// Send out ACCEPT/REFUSE_CHALLENGE_C_PKT
	//cout<<"<INFO> Sending " << ((opcode == ACCEPT_CHALLENGE_C_PKT)? "ACCEPT_CHALLENGE_C_PKT" : "REFUSE_CHALLENGE_C_PKT") << "\n\n";

	int ret = sendto(master_fd, packet, packet_size, 0,
					(struct sockaddr*)&sv_addr, sizeof(sv_addr));
	if( ret < 0 ){

		cerr<<"<ERR> Error sending "<< ((ntohs(opcode) == ACCEPT_CHALLENGE_C_PKT)? "ACCEPT_CHALLENGE_C_PKT" : 
																			"REFUSE_CHALLENGE_C_PKT") << "\n\n";
		exit(1);

	}

	//cout << "<OK>  "<< ((ntohs(opcode) == ACCEPT_CHALLENGE_C_PKT)? "ACCEPT_CHALLENGE_C_PKT" : 
	//																"REFUSE_CHALLENGE_C_PKT") <<" sent.\n\n";

	// Increment the counter of write ops
	incrementSeqWriteOps();
	// ------------------
}

void Client::handleAcceptedChallenge(unsigned char* buffer_in){

	// Declare useful variables
	uint16_t opcode = FWD_ACC_CHALLENGE_S_PKT;
	unsigned char *sym_dec_iv = (unsigned char*)malloc(sym_enc_dec_iv_len);
	unsigned char *tag = (unsigned char*)malloc(TAG_LEN);
	if(!sym_dec_iv || !tag){

		cerr << "<ERR> malloc() returned NULL, disconnecting!\n\n";
		logout();
		exit(1);
				
	}
	unsigned char *cphr_buf= NULL; 
	unsigned int cphr_buf_len;
	unsigned int peer_pubkey_size;
	unsigned char *peer_pubkey_buf = NULL;
	// ------------------------

	// Retrieve fixed length fields from packet 5
	uint16_t num_fields = 6;
	vector<unsigned char *> pkt_fields = {sym_dec_iv,
											(unsigned char*)&peer_pubkey_size,
											peer_pubkey_buf,	 
											(unsigned char*)&cphr_buf_len, cphr_buf, tag};

	vector<unsigned int> pkt_fields_len= {sym_enc_dec_iv_len,
											sizeof(peer_pubkey_size),
											0,
											sizeof(cphr_buf_len), 0, TAG_LEN};

	get_fixed_len_fields(pkt_fields, pkt_fields_len, buffer_in, num_fields, true);
	// -------------------------------------------

	// Allocate space for buffers of variable length fields
	cphr_buf_len = ntohs(cphr_buf_len);
	cphr_buf = (unsigned char*)malloc(cphr_buf_len);
	peer_pubkey_size = ntohs(peer_pubkey_size);
	peer_pubkey_buf = (unsigned char*)malloc(peer_pubkey_size);
	if(!cphr_buf || !peer_pubkey_buf){

		cerr << "<ERR> malloc() returned NULL, disconnecting!\n\n";
		logout();
		exit(1);
				
	}
	// -----------------------------------------------------

	// Retrieve variable length fields
	pkt_fields = {NULL, NULL, 
					peer_pubkey_buf, NULL,
					cphr_buf, NULL};
	pkt_fields_len = {sym_enc_dec_iv_len, sizeof(peer_pubkey_size), 
						peer_pubkey_size, sizeof(cphr_buf_len), 
						cphr_buf_len, TAG_LEN};

	get_variable_len_fields(pkt_fields, pkt_fields_len, buffer_in, num_fields);

	// ---------------------------------------------
	
	// Declare variables for symmetric decryption + authentication
	unsigned char *clear_buf = NULL; 
	if(OPCODE_LEN > UINT_MAX - sizeof(seq_read_ops) - peer_pubkey_size){

		cerr << "<ERR>  Too big number\n";
		exit(1);
	}

	unsigned int aad_size = OPCODE_LEN + sizeof(seq_read_ops) + peer_pubkey_size; 
	unsigned char *aad = (unsigned char *)malloc(aad_size);
	if(!aad){

		cerr << "<ERR> malloc() returned NULL, disconnecting!\n\n";
		logout();
		exit(1);
				
	}
	// ------------------------------------------------------------
	
	// Concatenate AAD fields
	num_fields = 3;

	vector<unsigned char *> aad_fields = {(unsigned char*)&opcode, (unsigned char*)&seq_read_ops, 
											peer_pubkey_buf};
	vector<unsigned int> aad_fields_len = {OPCODE_LEN, sizeof(seq_read_ops), 
											peer_pubkey_size};

	aad_size = load_in_buffer(aad, aad_fields, aad_fields_len, num_fields);
	// ------------------------

	// Apply AES_GCM and verify the tag, put the clear text in clear_buf
	int clear_size = sym_dec_and_auth(session_key, sym_dec_iv, cphr_buf, cphr_buf_len,
										clear_buf, aad, aad_size, tag);

#pragma optimize("", off)
	memset(sym_dec_iv, 0, sym_enc_dec_iv_len);
	memset(tag, 0, TAG_LEN);
	memset(cphr_buf, 0, cphr_buf_len);
	memset(aad, 0, aad_size);
#pragma optimize("", on)
	free(sym_dec_iv);
	free(tag);
	free(cphr_buf);
	free(aad);
	// ------------------------

	// If the tag is valid, the number of read ops is correct

	incrementSeqReadOps();

	opponent_pubkey = d2i_PUBKEY(NULL, (const unsigned char **)&peer_pubkey_buf, (long)peer_pubkey_size);

	// Retrieve decrypted fields
	unsigned char *peer_username = (unsigned char *)malloc(MAX_USERNAME_LEN);
	unsigned char *peer_IP_address = (unsigned char *)malloc(INET_ADDRSTRLEN);
	if(!peer_username || !peer_IP_address){

		cerr << "<ERR> malloc() returned NULL, disconnecting!\n\n";
		logout();
		exit(1);
				
	}
	unsigned short peer_port;

	num_fields = 3;
	
	vector<unsigned char *> clear_fields = {(unsigned char*)peer_username, 
											(unsigned char*)peer_IP_address, 
											(unsigned char*)&peer_port};
	vector<unsigned int> clear_fields_len = {MAX_USERNAME_LEN, 
											INET_ADDRSTRLEN, 
											sizeof(peer_port)};

	get_fixed_len_fields(clear_fields, clear_fields_len, clear_buf, num_fields, false);
	// ----------------------------

	strncpy((char*)opponent, (const char*)peer_username, MAX_USERNAME_LEN);
	opponent[MAX_USERNAME_LEN-1] = '\0';

	memset(&peer_addr, 0, sizeof(peer_addr)); // Cleaning the buffer 
	peer_addr.sin_family = AF_INET;
	peer_addr.sin_port = peer_port;
	inet_pton(AF_INET, (const char*)peer_IP_address, &peer_addr.sin_addr);
	len_peer_addr = sizeof(peer_addr);

#pragma optimize("", off)
	memset(peer_username, 0, MAX_USERNAME_LEN);
	memset(peer_IP_address, 0, INET_ADDRSTRLEN);
	memset(clear_buf, 0, clear_size);
#pragma optimize("", on)
	free(peer_username);
	free(peer_IP_address);
	free(clear_buf);
	
}

void Client::handleRefusedChallenge(unsigned char* buffer_in, uint16_t opcode){

	// cout << "Arrived FWD_REF_CHALLENGE_S_PKT\n\n";

	// Declare useful variables
	unsigned char *sym_dec_iv = (unsigned char*)malloc(sym_enc_dec_iv_len);
	unsigned char *tag = (unsigned char*)malloc(TAG_LEN);
	if(!sym_dec_iv || !tag){

		cerr << "<ERR> malloc() returned NULL, disconnecting!\n\n";
		logout();
		exit(1);
				
	}
	// ------------------------

	// Retrieve fixed length fields from packet FWD_REF_CHALLENGE_S
    uint16_t num_fields = 2;
    vector<unsigned char *> pkt_fields = {sym_dec_iv, tag};

    vector<unsigned int> pkt_fields_len = {sym_enc_dec_iv_len, TAG_LEN};

    get_fixed_len_fields(pkt_fields, pkt_fields_len, buffer_in, num_fields, true);
    // ------------------------------------------

	unsigned char *_dummy_clear_buf = NULL; // In packet FWD_REF_CHALLENGE_S there's no ciphertext
    unsigned int aad_size = OPCODE_LEN + sizeof(seq_read_ops); 
    unsigned char *aad = (unsigned char *)malloc(aad_size);
	if(!aad){

		cerr << "<ERR> malloc() returned NULL, disconnecting!\n\n";
		logout();
		exit(1);
				
	}

	// Concatenate AAD fields
    num_fields = 2;

    vector<unsigned char *> aad_fields = {(unsigned char*)&opcode, (unsigned char*)&seq_read_ops};
    vector<unsigned int> aad_fields_len = {OPCODE_LEN, sizeof(seq_read_ops)};

    aad_size = load_in_buffer(aad, aad_fields, aad_fields_len, num_fields);
    // ------------------------

	// Apply AES_GCM and verify the tag
    sym_dec_and_auth(session_key, sym_dec_iv, NULL, 0,
                        _dummy_clear_buf, aad, aad_size, tag);

#pragma optimize("", off)
	memset(sym_dec_iv, 0, sym_enc_dec_iv_len);
	memset(tag, 0, TAG_LEN);
	memset(aad, 0, aad_size);
#pragma optimize("", on)
	free(sym_dec_iv);
	free(tag);
	free(aad);
    // -------------------------------

	// If the tag is valid, the number of read ops is correct
	//cout << "<OK>   Message is fresh!\n\n";
	incrementSeqReadOps();
}

void Client::handleWaitingPlayerPacket(unsigned char *buffer_in, uint16_t opcode){

	int ret;

	// Declare useful variables
    unsigned char *sym_dec_iv = (unsigned char*)malloc(sym_enc_dec_iv_len);
    unsigned char *tag = (unsigned char*)malloc(TAG_LEN);
    if(!sym_dec_iv || !tag) {
		
        cerr << "<ERR> malloc() returned NULL, disconnecting!\n";
        exit(1);

    }
    // ------------------------

	// Retrieve fixed length fields from packet 4
    uint16_t num_fields = 2;
    vector<unsigned char *> pkt_fields = {sym_dec_iv, tag};

    vector<unsigned int> pkt_fields_len = {sym_enc_dec_iv_len, TAG_LEN};

    get_fixed_len_fields(pkt_fields, pkt_fields_len, buffer_in, num_fields, true);
    // ------------------------------------------

	unsigned char *_dummy_clear_buf = NULL; // In this packet there's no ciphertext
    unsigned int aad_size = OPCODE_LEN + sizeof(seq_read_ops); 
    unsigned char *aad = (unsigned char *)malloc(aad_size);
    if(!aad) {
		
        cerr << "<ERR> malloc() returned NULL, disconnecting!\n";
        exit(1);

    }

	// Concatenate AAD fields
    num_fields = 2;

    vector<unsigned char *> aad_fields = {(unsigned char*)&opcode, (unsigned char*)&seq_read_ops};
    vector<unsigned int> aad_fields_len = {OPCODE_LEN, sizeof(seq_read_ops)};

    aad_size = load_in_buffer(aad, aad_fields, aad_fields_len, num_fields);
    // ------------------------

	// Apply AES_GCM and verify the tag
    sym_dec_and_auth(session_key, sym_dec_iv, NULL, 0, _dummy_clear_buf, aad, aad_size, tag);

#pragma optimize("", off)
    memset(sym_dec_iv, 0, sym_enc_dec_key_len);
    memset(tag, 0, TAG_LEN);
    memset(aad, 0, aad_size);
#pragma optimize("", on)
    free(sym_dec_iv);
    free(tag);
    free(aad);
    // ------------------------

	// If the tag is valid, check the number of read ops
    //cout << "<OK>   Message is fresh!\n\n";
    incrementSeqReadOps();
    // -------------------------------------------------
}

bool Client::logout(){

	int ret;

	uint16_t opcode = htons(LOG_OUT_C_PKT);
	ret = sendto(master_fd, (unsigned char*)&opcode, sizeof(uint16_t), 0, 
					(struct sockaddr*)&sv_addr, sizeof(sv_addr));
	if(ret <= 0){

		cerr << "<ERR>  Error sending out LOG_OUT_C_PKT\n\n";
		return false;

	}

	cout << "\nBye bye!\n";

	free(session_key);
	EVP_PKEY_free(user_prvkey);	

	return true;
}

bool Client::player1P2PAuthentication(){

	match_seq_read_ops = 0;
	match_seq_write_ops = 0;

	last_nonce_user = (unsigned char *)malloc(NONCE_LEN);
	match_session_key = (unsigned char *)malloc(sym_enc_dec_key_len);

  	// Player1 sends out the opcode and his nonce
	int ret; 

	unsigned char packet[MAX_PACKET_SIZE]; // Packet to send
    unsigned char *buffer_in = (unsigned char*)malloc(MAX_PACKET_SIZE); // Incoming packet
	if(!buffer_in){

		cerr << "<ERR>  malloc() returned NULL, disconnecting!\n\n";
		logout();
		exit(1);
				
	}

	generate_random_quantity(last_nonce_user, NONCE_LEN);

	uint16_t opcode = htons(PLAYER1_HELLO_P_PKT); // Operative code for hello_c packet

	memset(packet, 0, MAX_PACKET_SIZE); // Clean the buffer

	uint16_t num_fields = 2;

	vector<unsigned char *> p1_hello_pkt_fields = {(unsigned char*)&opcode, last_nonce_user};
	vector<unsigned int> p1_hello_pkt_fields_len= {OPCODE_LEN, NONCE_LEN};

	unsigned int packet_size = load_in_buffer(packet, p1_hello_pkt_fields, p1_hello_pkt_fields_len, num_fields);
	// ----------------------------------------------------------------------

	// Send out PLAYER1_HELLO_P_PKT

	ret = sendto(master_fd, packet, packet_size, 0, (struct sockaddr*)&peer_addr, sizeof(peer_addr));
    if(ret < 0){

        cerr<<"<ERR>  PLAYER1_HELLO message not sent. ret = "<<ret<<endl;
        return false;

    }

	cout << "<OK>   PLAYER1_HELLO message sent!"<<endl;
	// -----------------------------

	// Receive PLAYER2_HELLO_P_PKT

	int recvd_opcode = recvMessage(master_fd, buffer_in);
	if(!(recvd_opcode == PLAYER2_HELLO_P_PKT) ){

		cerr << "<ERR>  Wrong message received (shoud have received PLAYER2_HELLO_P_PKT)\n\n";
		return false;

	}

	cout << "<OK>   Received PLAYER2_HELLO_P_PKT\n\n";
	
	// --------------------------

	// Declare some useful variables
	unsigned int signature_len_recv;
	unsigned int player2_dh_pubkey_size;
	unsigned char player2_nonce[NONCE_LEN];
	unsigned char *signature = NULL;
	unsigned char *player2_dh_pubkey_buf = NULL;
	// ------------------------------
	
	// Retrieve fixed length fields from packet 2
	num_fields = 5;
	vector<unsigned char *> p2_hello_pkt_fields = {player2_nonce, (unsigned char*)&signature_len_recv,
													signature, (unsigned char*)&player2_dh_pubkey_size,
													player2_dh_pubkey_buf};

	vector<unsigned int> p2_hello_pkt_fields_len = {NONCE_LEN, sizeof(signature_len_recv),
													0, sizeof(player2_dh_pubkey_size), 
													0};

	get_fixed_len_fields(p2_hello_pkt_fields, p2_hello_pkt_fields_len, buffer_in, num_fields, true);
	// ------------------------------------------

	// Allocate space for buffers of variable length fields
	player2_dh_pubkey_size = ntohs(player2_dh_pubkey_size);
	player2_dh_pubkey_buf = (unsigned char*)malloc(player2_dh_pubkey_size);
	signature_len_recv = ntohs(signature_len_recv);
	signature = (unsigned char*)malloc(signature_len_recv);
	if(!player2_dh_pubkey_buf || !signature){

		cerr << "<ERR>  malloc() returned NULL, disconnecting!\n\n";
		logout();
		exit(1);
				
	}
	// -----------------------------------------------------

	// Retrieve variable length fields from packet 2
	p2_hello_pkt_fields = {NULL, NULL,  
							signature, NULL,
							player2_dh_pubkey_buf};
	p2_hello_pkt_fields_len = {NONCE_LEN, sizeof(signature_len_recv),
								signature_len_recv, sizeof(player2_dh_pubkey_size), 
								player2_dh_pubkey_size};

	get_variable_len_fields(p2_hello_pkt_fields, p2_hello_pkt_fields_len, buffer_in, num_fields);

#pragma optimize("", off)
	memset(buffer_in, 0, MAX_PACKET_SIZE);
#pragma optimize("", on)
	free(buffer_in);
	// ---------------------------------------------

	// Compose the message to be verified (nonce user + server dh ephemeral key)
	if(NONCE_LEN > UINT_MAX - player2_dh_pubkey_size){

		cerr << "<ERR>  Too big number\n";
		exit(1);

	}
	unsigned int cleartext_to_verify_size = NONCE_LEN + player2_dh_pubkey_size;
	unsigned char *cleartext_to_verify = (unsigned char *)malloc(cleartext_to_verify_size);
	if(!cleartext_to_verify){

		cerr << "<ERR>  malloc() returned NULL, disconnecting!\n\n";
		logout();
		exit(1);
				
	}
	memset(cleartext_to_verify, 0, cleartext_to_verify_size); // Cleaning the buffer;

	num_fields = 2;

	vector<unsigned char *> cleartext_to_verify_fields = {last_nonce_user, player2_dh_pubkey_buf};
	vector<unsigned int> cleartext_to_verify_fields_len = {NONCE_LEN, player2_dh_pubkey_size};

	load_in_buffer(cleartext_to_verify, cleartext_to_verify_fields, 
					cleartext_to_verify_fields_len, num_fields);

	if(!signature_is_verified(cleartext_to_verify, cleartext_to_verify_size, signature, 
								signature_len_recv, opponent_pubkey)){

		cerr << "<ERR> Signature is not valid!\n\n";
		exit(1);

	}
	cout << "<OK>   Signature is valid!\n\n";

#pragma optimize("", off)
	memset(last_nonce_user, 0, NONCE_LEN);
	memset(signature, 0, signature_len_recv);
	memset(cleartext_to_verify, 0, cleartext_to_verify_size);
#pragma optimize("", on)
	free(last_nonce_user);
	free(signature);
	free(cleartext_to_verify);

	// Deserialize player2 DH ephemeral key
	EVP_PKEY *player2_dh_pubkey = NULL;
	player2_dh_pubkey = d2i_PUBKEY(NULL, (const unsigned char **)&player2_dh_pubkey_buf, (long)player2_dh_pubkey_size);
	if(!player2_dh_pubkey){

		cerr << "<ERR>  Error deserializing player 2 DH ephemeral key\n";
		return false;

	}

	cout << "<OK>   Player 2 DH ephemeral key deserialization done!\n\n";
	// ----------------------------------

	// Since the signature is verified the message is fresh (the user nonce is in the signature)

	// Player 1 has to send the END_HANDSHAKE_P_PKT

	// This function returns my dh ephemeral (public) key
	string player1_dh_prvkey_file_name = CLIENT_PUBKEY_DIR_PATH + username + "_dh_key.pem";
	EVP_PKEY* player1_dh_prvkey = create_and_store_dh_prvkey(player1_dh_prvkey_file_name.c_str());

	if(!player1_dh_prvkey){

		cerr << "<ERR>  Error creating and storing dh private key!\n";
		return false;

	}
	
	cout << "<OK>   DH private key retrieved!\n\n";

	EVP_PKEY* player1_dh_pubkey = load_dh_pubkey(player1_dh_prvkey_file_name.c_str());
	if(!player1_dh_pubkey){

		cerr << "<ERR>  Error retrieving dh pubkey!\n";
		return false;

	}

	cout << "<OK>   DH public key retrieved!\n\n";


	// Serialize the DH ephemeral key to be sent over socket
	unsigned char* player1_dh_pubkey_buf = NULL;
	unsigned int PLAYER1_DH_PUBKEY_SIZE = i2d_PUBKEY(player1_dh_pubkey, &player1_dh_pubkey_buf);
	unsigned int player1_dh_pubkey_size = htons(PLAYER1_DH_PUBKEY_SIZE);
	if(NONCE_LEN > UINT_MAX - PLAYER1_DH_PUBKEY_SIZE){

		cerr << "<ERR>  Too big num\n";
		exit(1);

	}
	unsigned int cleartext_dig_sig_size = NONCE_LEN + PLAYER1_DH_PUBKEY_SIZE; // Size of stuffs to be digitally signed
	unsigned char *cleartext_dig_sig = (unsigned char *)malloc(cleartext_dig_sig_size);
	if(!cleartext_dig_sig || !player1_dh_pubkey_buf) {
		
		cerr << "<ERR> malloc for END_HANDSHAKE_P_PKT returned NULL!\n";
		logout();
		exit(1);

	}
	// -----------------------------------------------------

	unsigned int SIGNATURE_LEN;

	// Digitally sign the opponent player nonce + the user dh ephemeral key
	num_fields = 2;

	vector<unsigned char *> dig_sig_fields = {player2_nonce, player1_dh_pubkey_buf};
	vector<unsigned int> dig_sig_fields_len = {NONCE_LEN, PLAYER1_DH_PUBKEY_SIZE};

	load_in_buffer(cleartext_dig_sig, dig_sig_fields, dig_sig_fields_len, num_fields);

	unsigned char *dig_sig = (unsigned char *)malloc(EVP_PKEY_size(user_prvkey));
	if(!dig_sig){

		cerr << "<ERR> malloc(dig_sig END_HANDSHAKE_P_PKT ) returned NULL!\n";
		logout();
		exit(1);

	}

	dig_sig = digitally_sign(cleartext_dig_sig, cleartext_dig_sig_size, SIGNATURE_LEN, user_prvkey);
	if(!dig_sig){

		cerr << "<ERR>  Error generating the signature for PLAYER2_HELLO_P_PKT!\n";
		return false;

	}

	cout << "<OK>   Signature for END_HANDSHAKE_P_PKT generated!\n\n";
	
#pragma optimize("", off)
	memset(cleartext_dig_sig, 0, cleartext_dig_sig_size);
#pragma optimize("", on)
	free(cleartext_dig_sig);
	// ------------------------------------------------------------

	// Convert the signature len to be sent over the nw
	unsigned int signature_len = htons(SIGNATURE_LEN);
	// -------------------------------------------------

	// Prepare PLAYER1_HELLO_P_PKT to be sent
	memset(packet, 0, MAX_PACKET_SIZE); // Cleaning the buffer
	
	opcode = htons(END_HANDSHAKE_P_PKT); // Operative code for hello_c packet

	num_fields = 5;

	vector<unsigned char *> pkt_fields_send = {(unsigned char*)&opcode, 
												(unsigned char*)&signature_len, dig_sig,
												(unsigned char*)&player1_dh_pubkey_size, 
												player1_dh_pubkey_buf};
	vector<unsigned int> pkt_fields_len_send = {OPCODE_LEN, 
												sizeof(signature_len), SIGNATURE_LEN, 
												sizeof(player1_dh_pubkey_size), 
												PLAYER1_DH_PUBKEY_SIZE};


	packet_size = load_in_buffer(packet, pkt_fields_send, pkt_fields_len_send, num_fields);

#pragma optimize("", off)
	memset(dig_sig, 0, SIGNATURE_LEN);
	memset(player1_dh_pubkey_buf, 0, PLAYER1_DH_PUBKEY_SIZE);
#pragma optimize("", on)
	free(dig_sig);
	free(player1_dh_pubkey_buf);
	// ------------------------------------------

	// Send out END_HANDSHAKE_P_PKT
    cout<<"<INFO> Sending END_HANDSHAKE_P_PKT"<<endl;

    ret = sendto(peer_fd, packet, packet_size, 0, (struct sockaddr*)&peer_addr, sizeof(peer_addr));// PROVA, (struct sockaddr*)&peer_addr, sizeof(peer_addr));
    if( ret < 0 ){

        cerr<<"<ERR>  Error sending END_HANDSHAKE_P_PKT\n";
		cout << "Errno is: " << errno << endl;
        return false;

    }

    cout << "<OK>   END_HANDSHAKE_P_PKT sent.\n\n";
    // -----------------

	// Generate the dh secret
	unsigned char *dh_secret = NULL;

	size_t dh_secret_len = generate_dh_secret(dh_secret, player1_dh_prvkey, player2_dh_pubkey);

	// We will use the hash of the shared secret as a key for AES_GCM
	unsigned char *shared_secret_digest = NULL;
	unsigned int shared_secret_digest_len;

	compute_hash(shared_secret_digest, shared_secret_digest_len, dh_secret, (unsigned int)dh_secret_len);

	memcpy(match_session_key, shared_secret_digest, sym_enc_dec_key_len);
	// --------------------------

#pragma optimize("", off)
	memset(dh_secret, 0, dh_secret_len);
	memset(shared_secret_digest, 0, shared_secret_digest_len);
#pragma optimize("", on)
	free(dh_secret);
	free(shared_secret_digest);	

	EVP_PKEY_free(player2_dh_pubkey);

	return true;

}

bool Client::player2P2PAuthentication(unsigned char* buffer_in){

	match_seq_read_ops = 0;
	match_seq_write_ops = 0;
	last_nonce_user = (unsigned char *)malloc(NONCE_LEN);
	match_session_key = (unsigned char *)malloc(sym_enc_dec_key_len);

	int ret;
	
	unsigned char packet[MAX_PACKET_SIZE];

	// Get the peer's nonce

	uint16_t num_fields = 1;
	unsigned char *player1_nonce = (unsigned char*)malloc(NONCE_LEN);
	if(!player1_nonce){

		cerr << "<ERR>  malloc() returned NULL, disconnecting!\n\n";
		logout();
		exit(1);
				
	}
	
	vector<unsigned char *> pkt_fields_recv= {player1_nonce};
	vector<unsigned int> pkt_fields_len_recv = {NONCE_LEN};

	get_fixed_len_fields(pkt_fields_recv, pkt_fields_len_recv, buffer_in, num_fields, true);

	// ---------------------

	// Generate PLAYER2_HELLO_P_PKT

	generate_random_quantity(last_nonce_user, NONCE_LEN);

	// This function returns my dh ephemeral (public) key
	string player2_dh_prvkey_file_name = CLIENT_PUBKEY_DIR_PATH + username + "_dh_key.pem";
	EVP_PKEY* player2_dh_prvkey = create_and_store_dh_prvkey(player2_dh_prvkey_file_name.c_str());

	if(!player2_dh_prvkey){

		cerr << "<ERR>  Error creating and storing dh private key!\n";
		return false;

	}

	cout << "<OK>   DH private key retrieved!\n\n";

	EVP_PKEY* player2_dh_pubkey = load_dh_pubkey(player2_dh_prvkey_file_name.c_str());
	if(!player2_dh_pubkey){

		cerr << "<ERR>  Error retrieving dh pubkey!\n";
		return false;

	}

	cout << "<OK>   DH public key retrieved!\n\n";

	// Serialize the DH ephemeral key to be sent over socket
	unsigned char* player2_dh_pubkey_buf = NULL;
	unsigned int PLAYER2_DH_PUBKEY_SIZE = i2d_PUBKEY(player2_dh_pubkey, &player2_dh_pubkey_buf);
	unsigned int player2_dh_pubkey_size = htons(PLAYER2_DH_PUBKEY_SIZE);
	if(NONCE_LEN > UINT_MAX - PLAYER2_DH_PUBKEY_SIZE){

		cerr << "<ERR>  Too big num\n";
		exit(1);
		
	}
	unsigned int cleartext_dig_sig_size = NONCE_LEN + PLAYER2_DH_PUBKEY_SIZE; // Size of stuffs to be digitally signed
	unsigned char *cleartext_dig_sig = (unsigned char *)malloc(cleartext_dig_sig_size);
	if(!cleartext_dig_sig || !player2_dh_pubkey_buf) {
		
		cerr << "<ERR> malloc() returned NULL, disconnecting!\n";
		logout();
		exit(1);

	}
	// -----------------------------------------------------

	unsigned int SIGNATURE_LEN;

	// Digitally sign the opponent player nonce + the user dh ephemeral key
	num_fields = 2;

	vector<unsigned char *> dig_sig_fields = {player1_nonce, player2_dh_pubkey_buf};
	vector<unsigned int> dig_sig_fields_len = {NONCE_LEN, PLAYER2_DH_PUBKEY_SIZE};

	load_in_buffer(cleartext_dig_sig, dig_sig_fields, dig_sig_fields_len, num_fields);

	unsigned char *dig_sig = (unsigned char *)malloc(EVP_PKEY_size(user_prvkey));
	if(!dig_sig){

		cerr << "<ERR> malloc(dig_sig PLAYER2_HELLO_P_PKT ) returned NULL!\n";
		logout();
		exit(1);

	}

	dig_sig = digitally_sign(cleartext_dig_sig, cleartext_dig_sig_size, SIGNATURE_LEN, user_prvkey);
	if(!dig_sig){

		cerr << "<ERR>  Error generating the signature for PLAYER2_HELLO_P_PKT!\n";
		return false;

	}

	cout << "<OK>   Signature for PLAYER2_HELLO_P_PKT generated!\n\n";

#pragma optimize("", off)
	memset(player1_nonce, 0, NONCE_LEN);
	memset(cleartext_dig_sig, 0, cleartext_dig_sig_size);
#pragma optimize("", on)
	free(player1_nonce);
	free(cleartext_dig_sig);

	// ------------------------------------------------------------
	
	// Convert the signature len to be sent over the nw
	unsigned int signature_len = htons(SIGNATURE_LEN);
	// -------------------------------------------------

	// Prepare PLAYER2_HELLO_P_PKT to be sent
	memset(packet, 0, MAX_PACKET_SIZE); // Cleaning the buffer
	
	uint16_t opcode = htons(PLAYER2_HELLO_P_PKT); // Operative code for hello_c packet

	num_fields = 6;

	vector<unsigned char *> pkt_fields_send = {(unsigned char*)&opcode, last_nonce_user, 
												(unsigned char*)&signature_len, dig_sig,
												(unsigned char*)&player2_dh_pubkey_size, 
												player2_dh_pubkey_buf};
	vector<unsigned int> pkt_fields_len_send = {OPCODE_LEN, NONCE_LEN, 
												sizeof(signature_len), SIGNATURE_LEN, 
												sizeof(player2_dh_pubkey_size), 
												PLAYER2_DH_PUBKEY_SIZE};


	unsigned int packet_size = load_in_buffer(packet, pkt_fields_send, pkt_fields_len_send, num_fields);

#pragma optimize("", off)
	memset(dig_sig, 0, SIGNATURE_LEN);
	memset(player2_dh_pubkey_buf, 0, PLAYER2_DH_PUBKEY_SIZE);
#pragma optimize("", on)
	free(dig_sig);
	free(player2_dh_pubkey_buf);
	// ------------------------------------------

	// Send out PLAYER2_HELLO_P_PKT
    cout<<"<INFO> Sending PLAYER2_HELLO_P_PKT"<<endl;

    ret = send(peer_fd, packet, packet_size, 0);
    if( ret < 0 ){

        cerr<<"<ERR> Error sending PLAYER2_HELLO_P_PKT\n";
		cout << "Errno is: " << errno << endl;
        return false;

    }

    cout << "<OK>   PLAYER2_HELLO_P_PKT sent.\n\n";
	// -----------------

	// Receive END_HANDSHAKE_P_PKT
	memset(buffer_in, 0, MAX_PACKET_SIZE);
	int recvd_opcode = recvMessage(master_fd, buffer_in);

	if(!(recvd_opcode == END_HANDSHAKE_P_PKT) ){

		cerr << "<ERR>  Wrong message received (shoud have received PLAYER2_HELLO_P_PKT)\n\n";
		return false;

	}

	cout << "<ERR>  Received END_HANDSHAKE_P_PKT\n\n";

	// --------------------------

	// Declare some useful variables
	unsigned int signature_len_recv;
	unsigned int player1_dh_pubkey_size;
	unsigned char *signature_recv = NULL;
	unsigned char *player1_dh_pubkey_buf = NULL;
	// ------------------------------

	// Retrieve fixed length fields from packet 2
	num_fields = 4;
	vector<unsigned char *> end_handshake_pkt_fields = {(unsigned char*)&signature_len_recv, signature_recv, 
														(unsigned char*)&player1_dh_pubkey_size, player1_dh_pubkey_buf};

	vector<unsigned int> end_handshake_pkt_fields_len = {sizeof(signature_len_recv), 0, 
														sizeof(player1_dh_pubkey_size), 0};

	get_fixed_len_fields(end_handshake_pkt_fields, end_handshake_pkt_fields_len, buffer_in, num_fields, true);
	// ------------------------------------------

	// Allocate space for buffers of variable length fields
	player1_dh_pubkey_size = ntohs(player1_dh_pubkey_size);
	player1_dh_pubkey_buf = (unsigned char*)malloc(player1_dh_pubkey_size);
	signature_len_recv = ntohs(signature_len_recv);
	signature_recv = (unsigned char*)malloc(signature_len_recv);
	if(!player1_dh_pubkey_buf || !signature_recv) {
		
		cerr << "<ERR> malloc() returned NULL, disconnecting!\n";
		logout();
		exit(1);

	}
	// -----------------------------------------------------

	// Retrieve variable length fields from packet 2
	end_handshake_pkt_fields = {NULL, signature_recv, 
								NULL, player1_dh_pubkey_buf};
	end_handshake_pkt_fields_len = {sizeof(signature_len_recv), signature_len_recv, 
									sizeof(player1_dh_pubkey_size), player1_dh_pubkey_size};

	get_variable_len_fields(end_handshake_pkt_fields, end_handshake_pkt_fields_len, buffer_in, num_fields);
	// ---------------------------------------------
	
	// Compose the message to be verified (nonce user + server dh ephemeral key)
	if(NONCE_LEN > UINT_MAX - player1_dh_pubkey_size){

		cerr << "<ERR>  Too big num\n";
		exit(1);
		
	}
	unsigned int cleartext_to_verify_size = NONCE_LEN + player1_dh_pubkey_size;
	unsigned char *cleartext_to_verify = (unsigned char *)malloc(cleartext_to_verify_size);
	if(!cleartext_to_verify) {
		
		cerr << "<ERR> malloc() returned NULL, disconnecting!\n";
		logout();
		exit(1);

	}
	memset(cleartext_to_verify, 0, cleartext_to_verify_size); // Cleaning the buffer;

	num_fields = 2;

	vector<unsigned char *> cleartext_to_verify_fields = {last_nonce_user, player1_dh_pubkey_buf};
	vector<unsigned int> cleartext_to_verify_fields_len = {NONCE_LEN, player1_dh_pubkey_size};

	load_in_buffer(cleartext_to_verify, cleartext_to_verify_fields, 
					cleartext_to_verify_fields_len, num_fields);
	// -----------------------------------------------------------------------------

	// Verify the signature

	if(!signature_is_verified(cleartext_to_verify, cleartext_to_verify_size, signature_recv, 
								signature_len_recv, opponent_pubkey)){

		cerr << "<ERR> Signature is not valid!\n\n";
		return false;

	}
	cout << "<OK>   Signature is valid!\n\n";

#pragma optimize("", off)
	memset(last_nonce_user, 0, NONCE_LEN);
	memset(signature_recv, 0, signature_len_recv);
	memset(cleartext_to_verify, 0, cleartext_to_verify_size);
#pragma optimize("", on)
	free(last_nonce_user);
	free(signature_recv);
	free(cleartext_to_verify);
	// ---------------------

	// Deserialize player2 DH ephemeral key
	EVP_PKEY *player1_dh_pubkey = NULL;
	player1_dh_pubkey = d2i_PUBKEY(NULL, (const unsigned char **)&player1_dh_pubkey_buf, (long)player1_dh_pubkey_size);
	if(!player1_dh_pubkey){

		cerr << "<ERR>  Error deserializing Player 1 DH ephemeral key\n";
		return false;

	}

	cout << "<OK>   Player 1 DH ephemeral key deserialization done!\n\n";
	// ----------------------------------

	// At this point both players know each other's DH ephemeral key
	// --> They can generate the shared secret
	
	// Generate the dh secret
	unsigned char *dh_secret = NULL;

	size_t dh_secret_len = generate_dh_secret(dh_secret, player2_dh_prvkey, player1_dh_pubkey);

	// We will use the hash of the shared secret as a key for AES_GCM
	unsigned char *shared_secret_digest = NULL;
	unsigned int shared_secret_digest_len;

	compute_hash(shared_secret_digest, shared_secret_digest_len, dh_secret, (unsigned int)dh_secret_len);

	memcpy(match_session_key, shared_secret_digest, sym_enc_dec_key_len);
	// --------------------------

#pragma optimize("", off)
	memset(dh_secret, 0, dh_secret_len);
	memset(shared_secret_digest, 0, shared_secret_digest_len);
#pragma optimize("", on)
	free(dh_secret);
	free(shared_secret_digest);

	return true;
}

void Client::playP2PMatch(bool firstToPlay){

	int ret;

	string opponent_str((char*)opponent);
	FourInARow gameBoard(opponent_str);
	clearScreen();
	cout << gameBoard.toString() << endl;

	while(true){

		if(firstToPlay){

			if(!handleUserTurn(gameBoard))
				return;
			if(!handleOpponentTurn(gameBoard))
				return;

		} else {

			if(!handleOpponentTurn(gameBoard))
				return;

			if(!handleUserTurn(gameBoard))
				return;
			
		}

	} 

}

bool Client::handleOpponentTurn(FourInARow &gameBoard){

	unsigned char *buffer_in = (unsigned char*)malloc(MAX_PACKET_SIZE);
	if(!buffer_in) {
		
		cerr << "<ERR> malloc() returned NULL, disconnecting!\n";
		logout();
		exit(1);

	}

	cout << "Waiting for " << gameBoard.getOpponent() << "'s move..." << endl;

	if(!recvMessage(master_fd, buffer_in) == MOVE_P_PKT){

		cerr << "<ERR>  Wrong message received (should have arrived MOVE_P_PKT)\n\n";
		return false;

	}

	uint16_t column_index = recvMoveMessage(buffer_in);

	if(!gameBoard.opponentTurn(column_index))
		return false;

	clearScreen();
	cout << gameBoard.toString() << endl;

	if (gameBoard.isMatchFinished()) {
		printMatchResult(gameBoard.getResult());
		cout << "Returning to the main menu...\n" << endl;
		return false;
	}

#pragma optimize("", off)
	memset(buffer_in, 0, MAX_PACKET_SIZE);
#pragma optimize("", on)
	free(buffer_in);

	return true;
}

bool Client::handleUserTurn(FourInARow &gameBoard){

	uint8_t column = gameBoard.userTurn();
	clearScreen();
	cout << gameBoard.toString() << endl;
	sendMoveMessage(column);

	if (gameBoard.isMatchFinished()) {
		printMatchResult(gameBoard.getResult());
		cout << "Returning to the main menu...\n" << endl;
		return false;
	}

	return true;
}

void Client::sendMoveMessage(const uint16_t column_index){

	int ret;

	unsigned char packet[MAX_PACKET_SIZE]; // Packet to send
	memset(packet, 0, MAX_PACKET_SIZE); // Cleaning the buffer

	// I need to authenticate the sequence number to avoid replay attacks, or reordering. 
	unsigned char *sym_enc_iv = NULL; 

	uint16_t opcode = MOVE_P_PKT;

	unsigned int aad_size = OPCODE_LEN + sizeof(match_seq_write_ops);
	unsigned char *aad = (unsigned char*)malloc(aad_size);
	unsigned char *tag = NULL;
	unsigned char *cphr_buf = NULL;
	unsigned int clear_size = sizeof(uint16_t);
	unsigned char *clear_buf = (unsigned char *)malloc(clear_size);
	if(!aad || !clear_buf) {
		
		cerr << "<ERR> malloc() returned NULL, disconnecting!\n";
		logout();
		exit(1);

	}

	// Concatenate AAD fields (Opcode, seq_write_ops)
	uint16_t num_fields = 2;

	vector<unsigned char *> aad_fields = {(unsigned char*)&opcode, (unsigned char*)&match_seq_write_ops};
	vector<unsigned int> aad_fields_len = {OPCODE_LEN, sizeof(match_seq_write_ops)};

	aad_size = load_in_buffer(aad, aad_fields, aad_fields_len, num_fields);
	// ----------------------------------------------

	// Fill the clear buffer to be encrypted
	memcpy(clear_buf, &column_index, MAX_USERNAME_LEN);
	// -------------------------------------

	// Apply AES_GCM and get the ciphertext, the tag and the IV
	unsigned int CPHR_LEN = sym_enc_and_auth(match_session_key, sym_enc_iv, clear_buf,
												clear_size, cphr_buf, aad, aad_size, tag);

#pragma optimize("", off)
	memset(aad, 0, aad_size);
	memset(clear_buf, 0, clear_size);
#pragma optimize("", on)
	free(aad);
	free(clear_buf);
	// ---------------------------------------------------------

	// Convert the cphr len to be sent over the nw
	unsigned int cphr_len = htons(CPHR_LEN);
	// -------------------------------------------

	// Prepare packet MOVE_P_PKT
	opcode = htons(opcode);

	num_fields = 5;

	vector<unsigned char *> pkt_fields = {(unsigned char*)&opcode, sym_enc_iv, (unsigned char*)&cphr_len, 
											cphr_buf, tag};
	vector<unsigned int> pkt_fields_len = {OPCODE_LEN, sym_enc_dec_iv_len, sizeof(cphr_len), 
											CPHR_LEN, TAG_LEN};
	
	int packet_size = load_in_buffer(packet, pkt_fields, pkt_fields_len, num_fields);

#pragma optimize("", off)
	memset(sym_enc_iv, 0, sym_enc_dec_iv_len);
	memset(tag, 0, TAG_LEN);
	memset(cphr_buf, 0, CPHR_LEN);
#pragma optimize("", on)
	free(sym_enc_iv);
	free(tag);	
	free(cphr_buf);	
	// ------------------------------------

	// Send out MOVE_P_PKT
	// cout<<"<INFO> Sending MOVE_P_PKT\n";

	ret = sendto(master_fd, packet , packet_size, 0,
					(struct sockaddr*)&peer_addr, sizeof(peer_addr));
	if( ret < 0 ){

		cerr<<"<ERR> Error sending MOVE_P_PKT\n";
		exit(1);

	}

	// cout << "<OK>   MOVE_P_PKT sent.\n\n";

	// Increment the counter of write ops
	match_seq_write_ops++;
	// ------------------
}

uint16_t Client::recvMoveMessage(unsigned char* buffer_in){

	// Declare useful variables
	unsigned char *sym_dec_iv = (unsigned char*)malloc(sym_enc_dec_iv_len);
	unsigned char *tag = (unsigned char*)malloc(TAG_LEN);
	if(!sym_dec_iv || !tag) {
		
		cerr << "<ERR> malloc() returned NULL, disconnecting!\n";
		logout();
		exit(1);

	}
	
	unsigned char *cphr_buf = NULL; 
	unsigned int cphr_buf_len;
	// ------------------------

	// Retrieve fixed length fields from MOVE_PKT
	uint16_t num_fields = 4;
	vector<unsigned char *> pkt_fields = {sym_dec_iv, (unsigned char*)&cphr_buf_len, cphr_buf, tag};

	vector<unsigned int> pkt_fields_len= {sym_enc_dec_iv_len, sizeof(cphr_buf_len), 0, TAG_LEN};

	get_fixed_len_fields(pkt_fields, pkt_fields_len, buffer_in, num_fields, true);
	// -------------------------------------------

	// Allocate space for buffers of variable length fields
	cphr_buf_len = ntohs(cphr_buf_len);
	cphr_buf = (unsigned char*)malloc(cphr_buf_len);
	if(!cphr_buf) {
		
		cerr << "<ERR> malloc() returned NULL, disconnecting!\n";
		logout();
		exit(1);

	}
	// -----------------------------------------------------

	// Retrieve variable length fields
	pkt_fields = {NULL, NULL, cphr_buf, NULL};
	pkt_fields_len = {sym_enc_dec_iv_len, sizeof(cphr_buf_len), cphr_buf_len, TAG_LEN};

	get_variable_len_fields(pkt_fields, pkt_fields_len, buffer_in, num_fields);
	// ---------------------------------------------

	// Declare variables for symmetric decryption + authentication
	unsigned char *clear_buf = NULL; 
	unsigned int aad_size = OPCODE_LEN + sizeof(match_seq_read_ops); 
	unsigned char *aad = (unsigned char *)malloc(aad_size);
	if(!aad) {
		
		cerr << "<ERR> malloc() returned NULL, disconnecting!\n";
		logout();
		exit(1);

	}

	// Concatenate AAD fields
	num_fields = 2;

	uint16_t opcode = MOVE_P_PKT;

	vector<unsigned char *> aad_fields = {(unsigned char*)&opcode, (unsigned char*)&match_seq_read_ops};
	vector<unsigned int> aad_fields_len = {OPCODE_LEN, sizeof(match_seq_read_ops)};

	aad_size = load_in_buffer(aad, aad_fields, aad_fields_len, num_fields);

	// ------------------------

	// Apply AES_GCM and verify the tag, put the clear text in clear_buf
	int clear_size = sym_dec_and_auth(match_session_key, sym_dec_iv, cphr_buf, cphr_buf_len,
											clear_buf, aad, aad_size, tag);

#pragma optimize("", off)
	memset(sym_dec_iv, 0, sym_enc_dec_iv_len);
	memset(tag, 0, TAG_LEN);
	memset(cphr_buf, 0, cphr_buf_len);
	memset(aad, 0, aad_size);	
#pragma optimize("", on)
	free(sym_dec_iv);
	free(tag);
	free(cphr_buf);
	free(aad);
	
	// ------------------------

	// If the tag is valid, the number of read ops is correct

	//cout << "<OK>   Message is fresh!\n\n";
	match_seq_read_ops++;

	uint16_t column_index; 

	memcpy(&column_index, clear_buf, sizeof(uint16_t));

#pragma optimize("", off)
	memset(clear_buf, 0, clear_size);
#pragma optimize("", on)
	free(clear_buf);
	
	return column_index;
}

void Client::sendP2PMatchFinished(){

	int ret;

	unsigned char packet[MAX_PACKET_SIZE]; // Packet to send
	memset(packet, 0, MAX_PACKET_SIZE); // Cleaning the buffer

	// I need to authenticate the sequence number to avoid replay attacks, or reordering. 
	unsigned char *sym_enc_iv = NULL; 

	uint16_t opcode = P2P_MATCH_FINISHED_C_PKT;

	unsigned int aad_size = OPCODE_LEN + sizeof(seq_write_ops);
	unsigned char *aad = (unsigned char*)malloc(aad_size);
	unsigned char *tag = NULL;
	unsigned char *cphr_buf = NULL;
	unsigned int clear_size = MAX_USERNAME_LEN;
	unsigned char *clear_buf = (unsigned char *)malloc(clear_size);
	if(!aad || !clear_buf) {
		
		cerr << "<ERR> malloc() returned NULL, disconnecting!\n";
		logout();
		exit(1);

	}

	// Concatenate AAD fields (Opcode, seq_write_ops)
	uint16_t num_fields = 2;

	vector<unsigned char *> aad_fields = {(unsigned char*)&opcode, (unsigned char*)&seq_write_ops};
	vector<unsigned int> aad_fields_len = {OPCODE_LEN, sizeof(seq_write_ops)};

	aad_size = load_in_buffer(aad, aad_fields, aad_fields_len, num_fields);
	// ----------------------------------------------

	// Fill the clear buffer to be encrypted
	memcpy(clear_buf, &opponent, MAX_USERNAME_LEN);
	// -------------------------------------

	// Apply AES_GCM and get the ciphertext, the tag and the IV
	unsigned int CPHR_LEN = sym_enc_and_auth(session_key, sym_enc_iv, clear_buf,
												clear_size, cphr_buf, aad, aad_size, tag);

#pragma optimize("", off)
	memset(aad, 0, aad_size);
	memset(clear_buf, 0, clear_size);
#pragma optimize("", on)
	free(aad);
	free(clear_buf);

	// --------------------------------------------------------

	// Convert the cphr len to be sent over the nw
	unsigned int cphr_len = htons(CPHR_LEN);
	// -------------------------------------------

	// Prepare packet P2P_MATCH_FINISHED_C_PKT
	opcode = htons(opcode);

	num_fields = 5;

	vector<unsigned char *> pkt_fields = {(unsigned char*)&opcode, sym_enc_iv, (unsigned char*)&cphr_len, 
											cphr_buf, tag};
	vector<unsigned int> pkt_fields_len = {OPCODE_LEN, sym_enc_dec_iv_len, sizeof(cphr_len), 
											CPHR_LEN, TAG_LEN};
	
	int packet_size = load_in_buffer(packet, pkt_fields, pkt_fields_len, num_fields);

#pragma optimize("", off)
	memset(tag, 0, TAG_LEN);
	memset(cphr_buf, 0, CPHR_LEN);
	memset(sym_enc_iv, 0, sym_enc_dec_iv_len);
#pragma optimize("", on)
	free(tag);
	free(cphr_buf);
	free(sym_enc_iv);
	// ------------------------------------

	// Send out P2P_MATCH_FINISHED_C_PKT
	// cout<<"<INFO> Sending P2P_MATCH_FINISHED_C_PKT\n";

	ret = sendto(master_fd, packet , packet_size, 0,
					(struct sockaddr*)&sv_addr, sizeof(sv_addr));
	if( ret < 0 ){

		cerr<<"<ERR> Error sending P2P_MATCH_FINISHED_C_PKT\n";
		exit(1);

	}

	// Increment the counter of write ops
	incrementSeqWriteOps();
	// ------------------

#pragma optimize("", off)
	memset(opponent, 0, MAX_USERNAME_LEN);
	memset(last_nonce_user, 0, NONCE_LEN);
	memset(match_session_key, 0, sym_enc_dec_key_len);
	memset(&peer_addr, 0, sizeof(peer_addr));
	memset(&len_peer_addr, 0, sizeof(len_peer_addr));
#pragma optimize("", on)
	EVP_PKEY_free(opponent_pubkey);	
	free(last_nonce_user);
	free(match_session_key);

}