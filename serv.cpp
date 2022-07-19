#include <iostream>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <map>
#include <stdlib.h>
#include <unistd.h>
#include "utils/shared-constants.h"
#include "utils/shared-functions.h"
using namespace std;

bool opcode_is_ok(uint16_t arrived_opcode, unsigned int correct_opcode){

    if(arrived_opcode != correct_opcode)
		return false;

	return true;
}

int pubkey_encrypt(unsigned char *clear_buf, int clear_size, EVP_PKEY * pubkey, 
					unsigned char *cphr_buf, unsigned char *iv, int iv_len, 
					unsigned char *encrypted_key, int encrypted_key_len, int block_size, const EVP_CIPHER *cipher){

	int cphr_len;
	
	int ret;

	int update_len = 0;
	int total_len = 0;
	
	// create the envelope context
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if(!ctx){
	
		cerr << "Error: EVP_CIPHER_CTX_new returned NULL\n";
		exit(1); 
		
	}
	
	// check for possible integer overflow in (clear_size + block_size)
    // (possible if the plaintext is too big, assume non-negative clear_size and block_size):
	if(clear_size > INT_MAX - block_size){
	
		cerr <<"Error: integer overflow (file too big?)\n";
		exit(1); 
		
	}

	// encrypt the plaintext:
    // (perform a single update on the whole plaintext, 
    // assuming that the plaintext is not huge)
	ret = EVP_SealInit(ctx, cipher, &encrypted_key, &encrypted_key_len, iv, &pubkey, 1);
	if(ret <= 0){
	
		cerr << "Error: EVP_SealInit failed!";
		exit(1);
	
	}
	
	ret = EVP_SealUpdate(ctx, cphr_buf, &update_len, clear_buf, clear_size);
	if(ret == 0){
	
		cerr << "Error: EVP_SealUpdate failed!";
		exit(1);
	
	}
	
	total_len += update_len;
	
	ret = EVP_SealFinal(ctx, cphr_buf + total_len, &update_len);
	if(ret == 0){
	
		cerr << "Error: EVP_SealFinal failed!";
		exit(1);
	
	}
	
	total_len += update_len;

	cphr_len = total_len;

	return cphr_len;
}

EVP_PKEY * read_pubkey(char *pubkey_file_name){

	EVP_PKEY *pubkey = NULL;

	string pubkey_file_name_str(pubkey_file_name);
	string pubkey_file_path = "server_files/";
	pubkey_file_path.append(pubkey_file_name_str);

	// load the public key:
	FILE* pubkey_file = fopen(pubkey_file_path.c_str(), "r");
	if(!pubkey_file){
	
		cerr << "<ERR> Cannot open file '" << pubkey_file_name << "' (file does not exist ?)";
		//exit(1);

	}
	
	pubkey = PEM_read_PUBKEY(pubkey_file, NULL, NULL, NULL);
	if(!pubkey){
	
		cerr << "<ERR> PEM_read_PUBKEY failed!";
		//exit(1);

	}
	
	fclose(pubkey_file);

	return pubkey;
}

int main(int argc, char* argv[]){

	RAND_poll();

    fd_set master; // Main set
    fd_set read_fds; // Reading set
    int fdmax; // Max descriptors num

    /* Azzero i set */
    FD_ZERO(&master);
    FD_ZERO(&read_fds);
    
	int ret, listener;
	socklen_t addrlen; 
	sockaddr_in my_addr, connecting_addr;

	unsigned char buffer_in[MAX_PACKET_SIZE];
    vector<string> online_users;
    map<int,int> client_state; // clients are mapped through their corresponding socket
    map<int, unsigned char[NONCE_LEN]> nonce_sv_per_client;
    map<int, EVP_PKEY*> user_pubkey;
    map<int, EVP_PKEY*> sv_dh_prvkey_per_client;
    map<int, string> usernames;

    uint16_t opcode;
    int num_fields; 

	// Create socket
	listener = socket(AF_INET,SOCK_DGRAM,0); 
	cout<<"<INFO> Listening socket created\n";

	// Create binding address
	memset(&my_addr, 0, sizeof(my_addr)); // Cleaning the buffer 
	my_addr.sin_family = AF_INET;
	my_addr.sin_port = htons(SERVER_PORT);
	my_addr.sin_addr.s_addr = INADDR_ANY;

	memset(&connecting_addr, 0, sizeof(connecting_addr));

	ret = bind(listener, (sockaddr*)&my_addr, sizeof(my_addr) );
    if( ret < 0 ){
		cerr<<"<ERR> Bind failed\n";
		exit(1);
	}

    FD_SET(listener, &master); // Add listener to the main set
    fdmax = listener; // Keep trace of the greates
	
	addrlen = sizeof(connecting_addr);
	
	// Load server private key 
	EVP_PKEY* sv_prvkey = load_privkey(SERVER_PRIVKEY_FILE_PATH);

	//Load server certificate
	cout<<"<INFO> Loading my certificate "<< endl;

	X509* sv_cert = NULL;
	FILE* sv_cert_file = fopen(SERVER_CERT_FILE_NAME, "r");
	if(!sv_cert_file){
		
		cerr<<" <ERR> Error opening file "<< SERVER_CERT_FILE_NAME <<" (not existing ?)\n"; 
		exit(1);
	}

	sv_cert = PEM_read_X509(sv_cert_file, NULL, NULL, NULL);
	if(!sv_cert){
		
		cerr<<" <ERR> Error reading the server certificate\n"; 
		exit(1);
	}

	fclose(sv_cert_file);

	while(1){

		memset(buffer_in, 0, MAX_PACKET_SIZE); //Cleaning the buffer

		// Receiving the hello_c message
		cout<<"<DBG>  Waiting hello_client messages\n";

        read_fds = master;
        select(fdmax + 1, &read_fds, NULL, NULL, NULL);

        for(int i = 0; i <= fdmax; i++) { // Iterave over the whole set
		
            if(FD_ISSET(i, &read_fds)) {
                
                if(i == listener) { // It is the listener

                    cout << "Arrivato messaggio\n";

                    ret = recvfrom(listener, buffer_in, MAX_PACKET_SIZE, 0,
                                (sockaddr*)&connecting_addr, &addrlen);
                    if(ret < 0){

                        cerr << "<ERR>  Error while receiving the hello packet\n";
                        exit(1);

                    }

                    // Declare the variables to store the fields contained in the packet
                    
                    char *username = (char *)malloc(MAX_USERNAME_LEN);
                    unsigned char *nonce_user = (unsigned char *)malloc(NONCE_LEN);

                    opcode = get_opcode(buffer_in);

                    if(!opcode_is_ok(opcode, HELLO_C_PKT)){

                        cerr << "<ERR>  Wrong message arrived\n";
                        exit(1);

                    }

		            num_fields = 2;

		            vector<unsigned char *> pkt_fields_pkt1 = {(unsigned char *)username, nonce_user};

		            vector<unsigned int> pkt_fields_len_pkt1 = {MAX_USERNAME_LEN, NONCE_LEN};

		            get_variable_len_fields(pkt_fields_pkt1, pkt_fields_len_pkt1, buffer_in, num_fields);

		            cout << "<INFO> Connected client is: " << username << "\n";

		            string username_str(username);

		            string user_pubkey_file_name = username_str + "_pubkey.pem";

                    int new_sd;
                    sockaddr_in son_addr;

			        new_sd = socket(AF_INET,SOCK_DGRAM,0);

                    int client = new_sd; 
                    usernames[client] = username_str;

                    // Load the user public key from file
                    user_pubkey[client] = read_pubkey((char*)user_pubkey_file_name.c_str());
                    if(!user_pubkey[client]){

                        cerr << " <ERR> Public key of user " << username << " not found (user not subscribed?)\n";
                        exit(1);

                    }
                    // ---------------------------

			        // Create binding address 
			        memset(&son_addr, 0, sizeof(son_addr)); // Cleaning the buffer 
			        son_addr.sin_family = AF_INET;

			        ret = bind(new_sd, (sockaddr*)&son_addr, sizeof(son_addr) );

                    if( ret < 0 ){
                        cerr<<"<ERR> Bind failed\n";
                        exit(1);
                    }
                    // ---------------------------------------
                    
                    // connect to client
                    ret = connect(new_sd, (struct sockaddr *)&connecting_addr, addrlen);
                    if(ret < 0){

                        cout << "<ERR>  Connect Failed \n";
                        exit(1);

                    } 

                    FD_SET(new_sd, &master); // Aggiungo il listener al set

                    if(new_sd > fdmax){ 

                        fdmax = new_sd;

                    }
			        // Retrieve certificate size
			        unsigned char* sv_cert_buf = NULL;
			        unsigned int SV_CERT_SIZE = i2d_X509(sv_cert, &sv_cert_buf);
			        unsigned int sv_cert_size = htons(SV_CERT_SIZE);
			        // --------------------------

			        // Convert the certificate size (in nw mode) to a string of chars to be encrypted
			        unsigned char sv_cert_size_char[sizeof(unsigned int)];
			        memset(&sv_cert_size_char, 0, sizeof(unsigned int));
			        memcpy(sv_cert_size_char, &sv_cert_size, sizeof(unsigned int));
			        // -------------------------------------------------------------------------------			

			        // Packet 2: packet format: | Opcode (2 bytes) | cert size (2 bytes) | Certificate | Ns (2 bytes) | Dig sig len |
			        //							| Dig sig | DH ephemeral key len | DH ephemeral key

			        // I need DH params to put my ephemeral key into the packet
			        string sv_dh_privkey_file_name(SERVER_DH_KEY_FILE_PATH);

			        // Create and store the dh private key
			        sv_dh_prvkey_per_client[client] = create_and_store_dh_prvkey(sv_dh_privkey_file_name.c_str());
                    if(!sv_dh_prvkey_per_client[client]){

                        cerr << "<ERR>  Error retrieving dh private key!\n";
                        exit(1);

                    } else {

                        cout << "<OK>   DH private key retrieved!\n\n";
                    }
                    // -----------------------------------

                    // Load the dh public (ephemeral) key
                    EVP_PKEY* sv_dh_pubkey = load_dh_pubkey(sv_dh_privkey_file_name.c_str());
                    if(!sv_dh_pubkey){

                        cerr << "<ERR>  Error retrieving dh pubkey!\n";
                        exit(1);

                    } else {

                        cout << "<OK>   DH public key retrieved!\n\n";

                    }
			        // -----------------------------------

                    // Serialize the DH ephemeral key to be sent over socket
                    unsigned char* sv_dh_pubkey_buf = NULL;
                    unsigned int SV_DH_PUBKEY_SIZE = i2d_PUBKEY(sv_dh_pubkey, &sv_dh_pubkey_buf);
                    // ------------------------------------------------------

			        unsigned int sv_dh_pubkey_size = htons(SV_DH_PUBKEY_SIZE);
			        unsigned int clear_size = NONCE_LEN + SV_DH_PUBKEY_SIZE; // Size of stuffs to be digitally signed
			        unsigned char *sv_dh_pubkey_size_char = (unsigned char *)malloc(sizeof(unsigned int)); // To be put in the packet
			        unsigned char *clear_buf = (unsigned char *)malloc(clear_size);
			        memset(sv_dh_pubkey_size_char, 0, sizeof(unsigned int));
			        memcpy(sv_dh_pubkey_size_char, &(sv_dh_pubkey_size), sizeof(unsigned int));

                    // Digitally sign the user nonce + server DH ephemeral key
                    
                    unsigned int SIGNATURE_LEN;

                    // Generate the server random nonce Ns
                    ret = RAND_bytes(nonce_sv_per_client[client], NONCE_LEN);
                    if(ret != 1){

                        cerr << "<ERR> Error generating nonce!\n";
                        exit(1);

                    }
                    // -----------------------------------

                    // Digitally sign the user nonce + the server dh ephemeral key
                    num_fields = 2;

                    vector<unsigned char *> dig_sig_fields_pkt2 = {nonce_user, sv_dh_pubkey_buf};
                    vector<unsigned int> dig_sig_fields_len_pkt2 = {NONCE_LEN, SV_DH_PUBKEY_SIZE};

                    load_in_buffer(clear_buf, dig_sig_fields_pkt2, dig_sig_fields_len_pkt2, num_fields);

                    unsigned char *signature = (unsigned char *)malloc(EVP_PKEY_size(sv_prvkey));
                    if(!signature){

                        cerr << "<ERR> malloc(signature) returned NULL!\n";
                        exit(1);

                    }
                    
                    signature = digitally_sign(clear_buf, clear_size, SIGNATURE_LEN, sv_prvkey);
                    // --------------------------------------------------------------

                    if(!signature){

                        cerr << "<ERR>  Error generating the signature!\n";
                        exit(1);

                    }

                    // Convert the signature len to be sent over the nw
                    unsigned int signature_len = htons(SIGNATURE_LEN);
                    unsigned char *signature_len_char = (unsigned char *)malloc(sizeof(unsigned int)); // To be put in the packet
                    memset(signature_len_char, 0, sizeof(unsigned int));
                    memcpy(signature_len_char, &(signature_len), sizeof(unsigned int));
                    // -------------------------------------------------

                    // Array to store the sending packet
                    unsigned char packet[MAX_PACKET_SIZE];  
                    memset(&packet, 0, MAX_PACKET_SIZE); // Cleaning the buffer

                    opcode = htons(CERT_S_PKT); // Operative code for hello_c packet
                    
                    num_fields = 8;

                    vector<unsigned char *> pkt_fields_pkt2 = {(unsigned char*)&opcode, (unsigned char*)sv_cert_size_char, 
                                                                sv_cert_buf, nonce_sv_per_client[client], 
                                                                signature_len_char, signature,
                                                                sv_dh_pubkey_size_char, sv_dh_pubkey_buf};
                    vector<unsigned int> pkt_fields_len_pkt2 = {OPCODE_LEN, sizeof(unsigned int), 
                                                                    SV_CERT_SIZE, NONCE_LEN, 
                                                                    sizeof(unsigned int), SIGNATURE_LEN, 
                                                                    sizeof(unsigned int), SV_DH_PUBKEY_SIZE};

                    unsigned int packet_size = load_in_buffer(packet, pkt_fields_pkt2, pkt_fields_len_pkt2, num_fields);

                    // Send out packet 2
                    cout<<"<INFO> Sending the certificate along with dig sig AND DH ephemeral key to the client"<<endl;

                    ret = send(new_sd, packet , packet_size, 0);
                    if( ret < 0 ){

                        cerr<<"<ERR> Error sending the size of the certificate\n";
                        exit(1);

                    } else {

                        cout << "<OK>   Packet 2 sent.\n\n";

                    }
                    // -----------------

                    // Store the current state for the client
                    client_state[new_sd] = CERT_S_PKT;
                } else { 
                    // This is another, already connected, socket

                    int client = i;

			        memset(buffer_in, 0, MAX_PACKET_SIZE); // Cleaning the buffer

			        ret = recv(i, buffer_in, MAX_PACKET_SIZE, 0);
                    if(ret <= 0){

                        cerr<<"<ERR> Error receiving packet\n";
                        exit(1);

                    } else {

                        cout << "<OK>   Packet received.\n\n";

                    }
			        // -----------------

                    // First check the opcode

                    opcode = get_opcode(buffer_in);
                    
                    if(!opcode_is_ok(opcode, client_state[client]+1)){

                        cerr << "<ERR>  Wrong message arrived from this client\n";
                        exit(1);

                    }
			        // ------------------------

                    switch(opcode){

                        case HELLO_DONE_C_PKT:
                            
                            // Declare some useful variables
                            unsigned int user_dh_pubkey_size;
                            unsigned char *user_dh_pubkey_buf = NULL;
                            unsigned char *dig_sig_pkt3 = NULL;
                            unsigned int dig_sig_len_pkt3;

                            // Retrieve fixed length fields from packet 3
                            num_fields = 4;
                            vector<unsigned char *> pkt_fields_pkt3 = {(unsigned char*)&dig_sig_len_pkt3, dig_sig_pkt3, 
                                                                        (unsigned char*)&user_dh_pubkey_size, user_dh_pubkey_buf};

                            vector<unsigned int> pkt_fields_len_pkt3 = {sizeof(unsigned int), 0, 
                                                                        sizeof(unsigned int), 0};

                            get_fixed_len_fields(pkt_fields_pkt3, pkt_fields_len_pkt3, buffer_in, num_fields);
                            // ------------------------------------------

                            // Allocate space for buffers of variable length fields
                            dig_sig_len_pkt3 = ntohs(dig_sig_len_pkt3);
                            dig_sig_pkt3 = (unsigned char*)malloc(dig_sig_len_pkt3);
                            user_dh_pubkey_size = ntohs(user_dh_pubkey_size);
                            user_dh_pubkey_buf = (unsigned char*)malloc(user_dh_pubkey_size);

                            if(!dig_sig_pkt3 || !user_dh_pubkey_buf){

                                cerr << "<ERR>  malloc packet 3 returned NULL!\n\n";
                                exit(1);

                            }
                            // -----------------------------------------------------

                            // Retrieve variable length fields from packet 3
                            pkt_fields_pkt3 = {NULL, dig_sig_pkt3, 
                                                NULL, user_dh_pubkey_buf};

                            pkt_fields_len_pkt3 = {sizeof(unsigned int), dig_sig_len_pkt3, 
                                                    sizeof(unsigned int), user_dh_pubkey_size};

                            get_variable_len_fields(pkt_fields_pkt3, pkt_fields_len_pkt3, buffer_in, num_fields);
                            // ---------------------------------------------

                            // Compose the message to be verified (nonce user + server dh ephemeral key)
                            unsigned int cleartext_to_verify_pkt3_size = NONCE_LEN + user_dh_pubkey_size;
                            unsigned char *cleartext_to_verify_pkt3 = (unsigned char *)malloc(cleartext_to_verify_pkt3_size);
                            memset(cleartext_to_verify_pkt3, 0, cleartext_to_verify_pkt3_size); // Cleaning the buffer;

                            num_fields = 2;

                            vector<unsigned char *> cleartext_to_verify_pkt3_fields = {nonce_sv_per_client[client], user_dh_pubkey_buf};
                            vector<unsigned int> cleartext_to_verify_pkt3_fields_len = {NONCE_LEN, user_dh_pubkey_size};

                            load_in_buffer(cleartext_to_verify_pkt3, cleartext_to_verify_pkt3_fields, 
                                            cleartext_to_verify_pkt3_fields_len, num_fields);
                            // --------------------------------------------------------------------------

                            // Verify the signature
                            if(!signature_is_verified(cleartext_to_verify_pkt3, cleartext_to_verify_pkt3_size, dig_sig_pkt3, 
                                                        dig_sig_len_pkt3, user_pubkey[client])){

                                cerr << "<ERR> Signature in packet 3 is not valid!\n\n";
                                exit(1);

                            } else {

                                cout << "<OK>   Signature in packet 3 is valid!\n\n";
                                // Since the signature is verified the message is fresh (the server nonce is in the signature)

                            }
                            // --------------------

                            // Deserialize user DH ephemeral key
                            EVP_PKEY *user_dh_pubkey = NULL;
                            user_dh_pubkey = d2i_PUBKEY(NULL, (const unsigned char **)&user_dh_pubkey_buf, (long)user_dh_pubkey_size);
                            if(!user_dh_pubkey){

                                cerr << "<ERR>  Error deserializing user DH ephemeral key\n";
                                exit(1);

                            } else {

                                cout << "<OK>   User DH ephemeral key deserialization done!\n\n";

                            }
                            // ----------------------------------

                            online_users.push_back(usernames[client]);

                            for(string user : online_users)
                                cout << user << "\n";

                            // At this point client and server both knows each other's DH ephemeral key
                            // --> They can generate the shared secret

                            // Generate the dh secret
                            unsigned char *dh_secret = NULL;

                            size_t dh_secret_len = generate_dh_secret(dh_secret, sv_dh_prvkey_per_client[client], user_dh_pubkey);

                            client_state[client] = HELLO_DONE_C_PKT;

                    }
                }
            }
                    
			
			
			// ----------------------

			// Store the user among the online users

			// At this point client and server share the dh secret
			// --> They can use (a part of) it as a session key (GCM)

			// Send the list of online players 


			//close(son_sd);
			
		}
		
	}

	return 0;
}

