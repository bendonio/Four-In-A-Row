#include "server-class.h"
#include "./shared-constants.h"
#include "./shared-functions.h"
using namespace std;

// ---------------------------------------
// 				UTILITY
// ---------------------------------------

bool user_already_logged_in(string username, map<int, string> logged_users, vector<string> online_users){

    for(const auto& logged_user : logged_users){

        if(((string)logged_user.second).compare(username) == 0)
            return true;
    }

    /*for(string online_user : online_users){

        if(online_user.compare(username) == 0)
            return true;
    }*/

    return false;
}
// -------------------------------------------------------------------------------------------------

// ---------------------------------------
// 	   CLASS FUNCTIONS IMPLEMENTATION
// ---------------------------------------

Server::Server(){

    // Create the connection
    if(!makeConnection()){

        cerr << "<ERR>  Error creating the connection!\n";
        exit(1);
    }

    // Load server private key 
    string sv_password; 

    setStdinEcho(false);
	cout<<"Please, insert your private key password > ";
	getline(cin, sv_password);
	if(!cin){ 
		
		cerr<<"<ERR>  Error during input\n"; 
		exit(1);

	}
    setStdinEcho(true);

	cout<< endl << endl;
    sv_prvkey = load_privkey(SERVER_PRIVKEY_FILE_PATH, sv_password);
    if(!sv_prvkey){

        cerr << "<ERR>  Error loading server private key!\n";
        exit(1);
    }

    // Load server certificate
	cout<<"<INFO> Loading my certificate "<< endl;

    sv_cert = load_certificate(SERVER_CERT_FILE_NAME);
	if(!sv_cert){
        cerr << "<ERR>  Error loading server certificate!\n";
        exit(1);
    }
}

bool Server::makeConnection(){

    // Create socket
	listener = socket(AF_INET,SOCK_DGRAM,0); 
	cout<<"<INFO> Listening socket created\n";

	// Create binding address
	memset(&sv_addr, 0, sizeof(sv_addr)); // Cleaning the buffer 
	sv_addr.sin_family = AF_INET;
	sv_addr.sin_port = htons(SERVER_PORT);
	sv_addr.sin_addr.s_addr = INADDR_ANY;

    int ret = bind(listener, (sockaddr*)&sv_addr, sizeof(sv_addr) );
    if( ret < 0 ){
		cerr<<"<ERR> Bind failed\n";
		return false;
	}

    FD_SET(listener, &master); // Add listener to the main set
    fdmax = listener; // Keep trace of the greates

    return true;

}

void Server::serverSelect(){

    read_fds = master;

    if(select(fdmax+1, &read_fds, NULL, NULL, NULL) < 0){

        cout << "<ERR>  Error in select!\n";
    }

}

bool Server::fdIsSet(int socket){

    return FD_ISSET(socket, &read_fds);
}

bool Server::acceptConnection(){

    unsigned char buffer_in[MAX_PACKET_SIZE];
    unsigned char packet[MAX_PACKET_SIZE];
    memset(buffer_in, 0, MAX_PACKET_SIZE);
    memset(packet, 0, MAX_PACKET_SIZE);

    sockaddr_in connecting_addr;
    socklen_t connecting_addr_len = sizeof(connecting_addr);
    memset(&connecting_addr, 0, sizeof(connecting_addr));

    int ret = recvfrom(listener, buffer_in, MAX_PACKET_SIZE, 0,
                        (sockaddr*)&connecting_addr, &connecting_addr_len);
    if(ret < 0){

        cerr << "<ERR>  Error while receiving the hello packet\n";
        sendErrorMessage(ERR_CONNECTION_S_PKT, listener, &connecting_addr);
        return false;
    }

    char cl_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(connecting_addr.sin_addr), cl_ip, INET_ADDRSTRLEN);


    cout << "<INFO> Connected client IP address: " << cl_ip << endl;
    cout << "<INFO> Connected client IP port: " << ntohs(connecting_addr.sin_port) << endl;

    // Declare the variables to store the fields contained in the packet
                    
    char *username = (char *)malloc(MAX_USERNAME_LEN);
    unsigned char *nonce_user = (unsigned char *)malloc(NONCE_LEN);
    if(!username || !nonce_user) {
		
		cerr << "<ERR> malloc() returned NULL, disconnecting!\n";
		sendErrorMessage(ERR_CONNECTION_S_PKT, listener, &connecting_addr);
        return false;
	}

    uint16_t opcode = get_opcode(buffer_in);

    if(!opcode_is_ok(opcode, HELLO_C_PKT)){

        cerr << "<ERR>  Wrong message arrived\n";
        sendErrorMessage(ERR_CONNECTION_S_PKT, listener, &connecting_addr);
        return false;
    }

    uint16_t num_fields = 2;

    vector<unsigned char *> pkt_fields = {(unsigned char *)username, nonce_user};

    vector<unsigned int> pkt_fields_len = {MAX_USERNAME_LEN, NONCE_LEN};

    get_variable_len_fields(pkt_fields, pkt_fields_len, buffer_in, num_fields);

    // Create new socket to handle this client
    int new_sd;
    sockaddr_in son_addr;

    new_sd = socket(AF_INET,SOCK_DGRAM,0);

    int client = new_sd; 

    // Create binding address 
    memset(&son_addr, 0, sizeof(son_addr)); // Cleaning the buffer 

    if( ret < 0 ){
        
        cerr<<"<ERR> Bind failed\n";
        sendErrorMessage(ERR_CONNECTION_S_PKT, listener, &connecting_addr);
        return false;

    }
    // ---------------------------------------

    if(user_already_logged_in(username, usernames, online_users)){
        // Send an error message
        // In the packet there will be the user nonce digitally signed

        cout << "\n<INFO> User already logged-in/online\n";

        // Generate signature over the user nonce
        unsigned char *signature = (unsigned char *)malloc(EVP_PKEY_size(sv_prvkey));
        if(!signature) {
		
            cerr << "<ERR> malloc() returned NULL, disconnecting!\n";
            sendErrorMessage(ERR_CONNECTION_S_PKT, listener, &connecting_addr);
            return false;

        }
        unsigned int SIGNATURE_LEN;
        unsigned int signature_len;

        signature = digitally_sign(nonce_user, NONCE_LEN, SIGNATURE_LEN, sv_prvkey);
        signature_len = htons(SIGNATURE_LEN);
        if(!signature){

            cerr << "<ERR>  Error generating the signature!\n";
            sendErrorMessage(ERR_CONNECTION_S_PKT, listener, &connecting_addr);
            return false;

        }

        opcode = htons(ERR_USER_LOGGED_S_PKT);
        // ---------------------------------------

        // Retrieve certificate size
        unsigned char* sv_cert_buf = NULL;
        unsigned int SV_CERT_SIZE = i2d_X509(sv_cert, &sv_cert_buf);
        unsigned int sv_cert_size = htons(SV_CERT_SIZE);
        // --------------------------

        // Prepare the packet
        num_fields = 5;

        vector<unsigned char *> pkt_fields_pkt51 = {(unsigned char*)&opcode, (unsigned char*)&sv_cert_size, 
                                                    sv_cert_buf, (unsigned char*)&signature_len, signature};
        vector<unsigned int> pkt_fields_pkt51_len = {OPCODE_LEN, sizeof(unsigned int), 
                                                        SV_CERT_SIZE, sizeof(unsigned int), SIGNATURE_LEN};

        unsigned int packet_size = load_in_buffer(packet, pkt_fields_pkt51, pkt_fields_pkt51_len, num_fields);
        
        // Send out packet ERR_USER_LOGGED_S
        cout<<"<INFO> Sending the ERR_USER_LOGGED_S_PKT"<<endl;

        ret = sendto(client, packet, packet_size, 0,    
                    (struct sockaddr*)&connecting_addr, sizeof(connecting_addr));
        if( ret < 0 ){

            cerr<<"<ERR> Error sending the ERR_USER_LOGGED_S_PKT\n";
            sendErrorMessage(ERR_CONNECTION_S_PKT, client, &connecting_addr);
            return false;

        }

        cout << "<OK>   ERR_USER_LOGGED_S_PKT sent.\n\n";
        

#pragma optimize("", off)
        memset(signature, 0, SIGNATURE_LEN);
#pragma optimize("", on)
        free(signature);

        return true;

    }

    cout << "<INFO> Connected client is: " << username << "\n";

    string username_str(username);

    string user_pubkey_file_name = username_str + "_pubkey.pem";


    // Load the user public key from file
    user_pubkey[client] = read_user_pubkey((char*)user_pubkey_file_name.c_str());
    if(!user_pubkey[client]){

        cerr << " <ERR> Public key of user " << username << " not found (user not subscribed?)\n";
        sendErrorMessage(ERR_CONNECTION_S_PKT, client, &connecting_addr);
        return false;

    }
    // ---------------------------

    // connect to client
    ret = connect(client, (struct sockaddr *)&connecting_addr, sizeof(connecting_addr));
    if(ret < 0){

        cout << "<ERR>  Connect failed \n";
        sendErrorMessage(ERR_CONNECTION_S_PKT, client, &connecting_addr);
        return false;

    } 

    FD_SET(new_sd, &master); // Add the new socket to the set

    if(new_sd > fdmax){ 

        fdmax = new_sd;

    }

    usernames[client] = username_str;
    socket_per_username[username_str] = client;
    client_last_opcode[client] = HELLO_C_PKT;

    string client_IP_address_str(cl_ip);
    client_IP_address[client] = client_IP_address_str;
    client_port[client] = connecting_addr.sin_port;

    if(!sendCertificate(client, nonce_user)){

        clientLogOut(client);
        sendErrorMessage(ERR_CONNECTION_S_PKT, client, &connecting_addr);
        return false;

    }

#pragma optimize("", off)
    memset(nonce_user, 0, NONCE_LEN);
    memset(username, 0, MAX_USERNAME_LEN);
#pragma optimize("", on)
    free(nonce_user);
    free(username);

    return true;
}

void Server::sendErrorMessage(uint16_t err_opcode, int client, sockaddr_in *client_addr = NULL){

    int ret;

	uint16_t opcode = htons(err_opcode);

    if(client_addr == NULL){

        ret = send(client, (unsigned char*)&opcode, sizeof(uint16_t), 0);

    } else {

	    ret = sendto(client, (unsigned char*)&opcode, sizeof(uint16_t), 0, 
					(struct sockaddr*)client_addr, sizeof(sockaddr_in));
    
    }
	if(ret <= 0){

		cerr << "<ERR>  Error sending out packet " << err_opcode << "\n\n";
		exit(1);

	}   
}

bool Server::sendCertificate(int client, unsigned char* nonce_user){

    unsigned char packet[MAX_PACKET_SIZE];

    // Retrieve certificate size
    unsigned char* sv_cert_buf = NULL;
    unsigned int SV_CERT_SIZE = i2d_X509(sv_cert, &sv_cert_buf);
    unsigned int sv_cert_size = htons(SV_CERT_SIZE);
    // --------------------------

    // Packet 2: packet format: | Opcode (2 bytes) | cert size (2 bytes) | Certificate | Ns (2 bytes) | Dig sig len |
    //							| Dig sig | DH ephemeral key len | DH ephemeral key

    // I need DH params to put my ephemeral key into the packet
    string sv_dh_privkey_file_name(SERVER_DH_KEY_FILE_PATH);

    // Create and store the dh private key
    sv_dh_prvkey_per_client[client] = create_and_store_dh_prvkey(sv_dh_privkey_file_name.c_str());
    if(!sv_dh_prvkey_per_client[client]){

        cerr << "<ERR>  Error retrieving dh private key!\n";
        return false;

    }

    cout << "<OK>   DH private key retrieved!\n\n";
    // -----------------------------------

    // Load the dh public (ephemeral) key
    EVP_PKEY* sv_dh_pubkey = load_dh_pubkey(sv_dh_privkey_file_name.c_str());
    if(!sv_dh_pubkey){

        cerr << "<ERR>  Error retrieving dh pubkey!\n";
        return false;

    }

    cout << "<OK>   DH public key retrieved!\n\n";
    // -----------------------------------

    // Serialize the DH ephemeral key to be sent over socket
    unsigned char* sv_dh_pubkey_buf = NULL;
    unsigned int SV_DH_PUBKEY_SIZE = i2d_PUBKEY(sv_dh_pubkey, &sv_dh_pubkey_buf);
    // ------------------------------------------------------

    unsigned int sv_dh_pubkey_size = htons(SV_DH_PUBKEY_SIZE);
    if(NONCE_LEN > UINT_MAX - SV_DH_PUBKEY_SIZE);
    unsigned int clear_size = NONCE_LEN + SV_DH_PUBKEY_SIZE; // Size of stuffs to be digitally signed
    unsigned char *clear_buf = (unsigned char *)malloc(clear_size);
    if(!clear_buf) {
		
        cerr << "<ERR> malloc() returned NULL, disconnecting!\n";
        return false;

    }

    // Digitally sign the user nonce + server DH ephemeral key
    
    unsigned int SIGNATURE_LEN;

    // Generate the server random nonce Ns
    generate_random_quantity(nonce_sv_per_client[client], NONCE_LEN);
    // -----------------------------------

    // Digitally sign the user nonce + the server dh ephemeral key
    uint16_t num_fields = 2;

    vector<unsigned char *> dig_sig_fields_pkt2 = {nonce_user, sv_dh_pubkey_buf};
    vector<unsigned int> dig_sig_fields_len_pkt2 = {NONCE_LEN, SV_DH_PUBKEY_SIZE};

    load_in_buffer(clear_buf, dig_sig_fields_pkt2, dig_sig_fields_len_pkt2, num_fields);

    unsigned char *signature = (unsigned char *)malloc(EVP_PKEY_size(sv_prvkey));
    if(!signature){

        cerr << "<ERR> malloc(signature) returned NULL!\n";
        return false;

    }
    
    signature = digitally_sign(clear_buf, clear_size, SIGNATURE_LEN, sv_prvkey);
    if(!signature){

        cerr << "<ERR>  Error generating the signature!\n";
        return false;

    }

#pragma optimize("", off)
    memset(clear_buf, 0, clear_size);
#pragma optimize("", on)
    free(clear_buf);
    // --------------------------------------------------------------

    // Convert the signature len to be sent over the nw
    unsigned int signature_len = htons(SIGNATURE_LEN);
    // -------------------------------------------------

    memset(&packet, 0, MAX_PACKET_SIZE); // Cleaning the buffer

    uint16_t opcode = htons(HELLO_S_PKT); // Operative code for hello_c packet
    
    num_fields = 8;

    vector<unsigned char *> pkt_fields_pkt2 = {(unsigned char*)&opcode, (unsigned char*)&sv_cert_size, 
                                                sv_cert_buf, nonce_sv_per_client[client], 
                                                (unsigned char*)&sv_dh_pubkey_size, sv_dh_pubkey_buf,
                                                (unsigned char*)&signature_len, signature};
    vector<unsigned int> pkt_fields_len_pkt2 = {OPCODE_LEN, sizeof(unsigned int), 
                                                    SV_CERT_SIZE, NONCE_LEN, 
                                                    sizeof(unsigned int), SV_DH_PUBKEY_SIZE,
                                                    sizeof(unsigned int), SIGNATURE_LEN};

    unsigned int packet_size = load_in_buffer(packet, pkt_fields_pkt2, pkt_fields_len_pkt2, num_fields);

    // Send out packet 2
    cout<<"<INFO> Sending the certificate along with dig sig AND DH ephemeral key to the client"<<endl;

    int ret = send(client, packet , packet_size, 0);
    if( ret < 0 ){

        cerr<<"<ERR> Error sending HELLO_S_PKT\n";
        return false;

    }

    cout << "<OK>   HELLO_S_PKT sent.\n\n";


#pragma optimize("", off)
    memset(signature, 0, SIGNATURE_LEN);
    memset(sv_dh_pubkey_buf, 0, SV_DH_PUBKEY_SIZE); 
    memset(sv_cert_buf, 0, SV_CERT_SIZE);
#pragma optimize("", on)
    free(signature);
    free(sv_dh_pubkey_buf);
    free(sv_cert_buf);
    // -----------------

    // Store the current state for the client
    client_state[client] = CONNECTED;
    client_last_opcode[client] = HELLO_S_PKT;

    return true;
}

void Server::clientLogOut(int client){

    string username = usernames[client];

    // Let's clean all the info stored for this client
    cout << "Player to logout is: " << username << "\n\n";

    for (auto online_user = online_users.begin(); online_user != online_users.end(); ++online_user) {
        if (*online_user == username) {
            online_users.erase(online_user);
            online_user--;
        }
    }
   
    client_state.erase(client);  
    client_last_opcode.erase(client);
    nonce_sv_per_client.erase(client);
    user_pubkey.erase(client);
    sv_dh_prvkey_per_client.erase(client);
    usernames.erase(client);
    socket_per_username.erase(username);
    session_key.erase(client);
    client_IP_address.erase(client);
    client_port.erase(client);
    seq_read_ops.erase(client);
    seq_write_ops.erase(client);
    pending_challenge_request.erase(client);

    close(client); // Close the socket
    FD_CLR(client, &master);    // Remove socket from the set

    cout << "<INFO> Client '"<< username << "' logged-out!\n\n";

}

bool Server::clientAllowedOpcode(int client, uint16_t opcode){

    if(client_state[client] != ON_LINE){


        if(opcode_is_ok(opcode, client_last_opcode[client]+1) || (opcode == LOG_OUT_C_PKT)){


            return true;

        }

        if((client_state[client] == IN_A_MATCH) && (opcode == P2P_MATCH_FINISHED_C_PKT)){

            return true;
        }

    }

    unordered_set<uint16_t> online_user_allowed_opcodes = {REQ_PLAYERS_LIST_C_PKT, REQ_CHALLENGE_C_PKT, 
                                                            ACCEPT_CHALLENGE_C_PKT, REFUSE_CHALLENGE_C_PKT, 
                                                            LOG_OUT_C_PKT};

    if (online_user_allowed_opcodes.find(opcode) != online_user_allowed_opcodes.end()) {
        
        return true;
    }

    cerr << "<ERR>  Wrong message arrived from this client\n";
    return false;
}

void Server::completeAuthentication(int client, unsigned char* buffer_in){

    // Declare some useful variables
    unsigned int user_dh_pubkey_size;
    unsigned char *user_dh_pubkey_buf = NULL;
    unsigned char *dig_sig = NULL;
    unsigned int dig_sig_len;

    // Retrieve fixed length fields
    uint16_t num_fields = 4;
    vector<unsigned char *> pkt_fields = {(unsigned char*)&user_dh_pubkey_size, user_dh_pubkey_buf, 
                                            (unsigned char*)&dig_sig_len, dig_sig};

    vector<unsigned int> pkt_fields_len = {sizeof(unsigned int), 0, 
                                            sizeof(unsigned int), 0};

    get_fixed_len_fields(pkt_fields, pkt_fields_len, buffer_in, num_fields, true);
    // ------------------------------------------

    // Allocate space for buffers of variable length fields
    dig_sig_len = ntohs(dig_sig_len);
    dig_sig = (unsigned char*)malloc(dig_sig_len);
    user_dh_pubkey_size = ntohs(user_dh_pubkey_size);
    user_dh_pubkey_buf = (unsigned char*)malloc(user_dh_pubkey_size);

    if(!dig_sig || !user_dh_pubkey_buf){

        cerr << "<ERR>  malloc packet 3 returned NULL!\n\n";
        clientLogOut(client);
        sendErrorMessage(ERR_AUTHENTICATION_S_PKT, client);
        return;

    }
    // -----------------------------------------------------

    // Retrieve variable length fields from packet 3
    pkt_fields = {NULL, user_dh_pubkey_buf, 
                    NULL, dig_sig};

    pkt_fields_len = {sizeof(unsigned int), user_dh_pubkey_size, 
                        sizeof(unsigned int), dig_sig_len};

    get_variable_len_fields(pkt_fields, pkt_fields_len, buffer_in, num_fields);
    // ---------------------------------------------

    // Compose the message to be verified (nonce user + server dh ephemeral key)
    if(NONCE_LEN > UINT_MAX - user_dh_pubkey_size){

        cerr << "<ERR>  Number is to big for malloc, disconnecting\n";
        clientLogOut(client);
        sendErrorMessage(ERR_AUTHENTICATION_S_PKT, client);
        return;

    }
    unsigned int cleartext_to_verify_size = NONCE_LEN + user_dh_pubkey_size;
    unsigned char *cleartext_to_verify = (unsigned char *)malloc(cleartext_to_verify_size);
    if(!cleartext_to_verify) {
		
        cerr << "<ERR> malloc() returned NULL, disconnecting!\n";
        clientLogOut(client);
        sendErrorMessage(ERR_AUTHENTICATION_S_PKT, client);
        return;

    }
    memset(cleartext_to_verify, 0, cleartext_to_verify_size); // Cleaning the buffer;

    num_fields = 2;

    vector<unsigned char *> cleartext_to_verify_fields = {nonce_sv_per_client[client], user_dh_pubkey_buf};
    vector<unsigned int> cleartext_to_verify_fields_len = {NONCE_LEN, user_dh_pubkey_size};

    load_in_buffer(cleartext_to_verify, cleartext_to_verify_fields, 
                    cleartext_to_verify_fields_len, num_fields);
    // --------------------------------------------------------------------------

    // Verify the signature
    if(!signature_is_verified(cleartext_to_verify, cleartext_to_verify_size, dig_sig, 
                                dig_sig_len, user_pubkey[client])){

        cerr << "<ERR> Signature in packet 3 is not valid!\n\n";
        clientLogOut(client);
        sendErrorMessage(ERR_AUTHENTICATION_S_PKT, client);
        return;

    }

    cout << "<OK>   Signature in packet 3 is valid!\n\n";
    // ---------------------

    // Since the signature is verified the message is fresh (the server nonce is in the signature)

    // Deserialize user DH ephemeral key
    EVP_PKEY *user_dh_pubkey = NULL;
    user_dh_pubkey = d2i_PUBKEY(NULL, (const unsigned char **)&user_dh_pubkey_buf, (long)user_dh_pubkey_size);
    if(!user_dh_pubkey){

        cerr << "<ERR>  Error deserializing user DH ephemeral key\n";
        clientLogOut(client);
        sendErrorMessage(ERR_AUTHENTICATION_S_PKT, client);
        return;

    }

#pragma optimize("", off)
    memset(dig_sig, 0, dig_sig_len);
    memset(cleartext_to_verify, 0, cleartext_to_verify_size);
#pragma optimize("", on)
    free(dig_sig);
    free(cleartext_to_verify);

    //cout << "<OK>   User DH ephemeral key deserialization done!\n\n";
    // ----------------------------------

    if ( find(online_users.begin(), online_users.end(), usernames[client]) == online_users.end() )
        online_users.push_back(usernames[client]);

    seq_read_ops[client] = 0;
    seq_write_ops[client] = 0;

    // At this point client and server both knows each other's DH ephemeral key
    // --> They can generate the shared secret

    // Generate the dh secret
    unsigned char *dh_secret = NULL;

    size_t dh_secret_len = generate_dh_secret(dh_secret, sv_dh_prvkey_per_client[client], user_dh_pubkey);

    unsigned char *shared_secret_digest = NULL;
    unsigned int shared_secret_digest_len; 

    compute_hash(shared_secret_digest, shared_secret_digest_len, dh_secret, (unsigned int)dh_secret_len);
    
    session_key[client] = (unsigned char *)malloc(sym_enc_dec_key_len);
    if(!session_key[client]) {
		
        cerr << "<ERR> malloc() returned NULL, disconnecting!\n";
        clientLogOut(client);
        sendErrorMessage(ERR_AUTHENTICATION_S_PKT, client);
        return;

    }

    memcpy(session_key[client], shared_secret_digest, sym_enc_dec_key_len);

    EVP_PKEY_free(user_dh_pubkey);

#pragma optimize("", off)
    memset(shared_secret_digest, 0, shared_secret_digest_len);
    memset(dh_secret, 0, dh_secret_len);
#pragma optimize("", on)
    free(shared_secret_digest);
    free(dh_secret);

    client_state[client] = ON_LINE;

}

void Server::load_list_of_online_players(unsigned char *& list_of_online_players_out, string current_player_username){

    uint16_t index = 0;

    uint16_t list_size = (online_users.size() - 1) * MAX_USERNAME_LEN;

    memset(list_of_online_players_out, 0, list_size);

    cout << "Online users size is: " << online_users.size() << endl;

    for(string player_username : online_users){

        // Add the username to the list only if it is not the current player
        int player_socket = socket_per_username[player_username];
        int player_state = client_state[player_socket];

        if((player_username.compare(current_player_username) != 0) && (player_state == ON_LINE)){
            // If this is not the current player, and the player is online add it to the list
            
            memcpy(list_of_online_players_out + index, player_username.c_str(), player_username.size()+1);

            index += MAX_USERNAME_LEN;

        }
    }
}

void Server::sendOnlinePlayersList(int client, unsigned char* buffer_in, uint16_t opcode){

    int ret;

    // Declare useful variables
    unsigned char *sym_dec_iv = (unsigned char*)malloc(sym_enc_dec_iv_len);
    unsigned char *tag_recv = (unsigned char*)malloc(TAG_LEN);
    if(!sym_dec_iv || !tag_recv) {
		
        cerr << "<ERR> malloc() returned NULL, disconnecting!\n";
        sendErrorMessage(ERR_INTERNAL_S_PKT, client);
        clear();
        exit(1);

    }
    // ------------------------

    // Retrieve fixed length fields from packet 4
    uint16_t num_fields = 2;
    vector<unsigned char *> pkt_fields_recv = {sym_dec_iv, tag_recv};

    vector<unsigned int> pkt_fields_recv_len = {sym_enc_dec_iv_len, TAG_LEN};

    get_fixed_len_fields(pkt_fields_recv, pkt_fields_recv_len, buffer_in, num_fields, true);
    // ------------------------------------------

    unsigned char *_dummy_clear_buf = NULL; // In packet 4 there's no ciphertext
    unsigned int aad_recv_size = OPCODE_LEN + sizeof(seq_read_ops.at(client)); 
    unsigned char *aad_recv = (unsigned char *)malloc(aad_recv_size);
    if(!aad_recv) {
		
        cerr << "<ERR> malloc() returned NULL, disconnecting!\n";
        sendErrorMessage(ERR_INTERNAL_S_PKT, client);
        clear();
        exit(1);

    }

    // Concatenate AAD fields
    num_fields = 2;

    vector<unsigned char *> aad_recv_fields = {(unsigned char*)&opcode, (unsigned char*)&seq_read_ops.at(client)};
    vector<unsigned int> aad_recv_fields_len = {OPCODE_LEN, sizeof(seq_read_ops.at(client))};

    aad_recv_size = load_in_buffer(aad_recv, aad_recv_fields, aad_recv_fields_len, num_fields);
    // ------------------------

    // Apply AES_GCM and verify the tag
    sym_dec_and_auth(session_key[client], sym_dec_iv, NULL, 0,
                        _dummy_clear_buf, aad_recv, aad_recv_size, tag_recv);

#pragma optimize("", off)
    memset(sym_dec_iv, 0, sym_enc_dec_key_len);
    memset(tag_recv, 0, TAG_LEN);
    memset(aad_recv, 0, aad_recv_size);
#pragma optimize("", on)
    free(sym_dec_iv);
    free(tag_recv);
    free(aad_recv);
    // ------------------------

    // If the tag is valid, check the number of read ops
    cout << "<OK>   Message is fresh!\n\n";
    incrementSeqReadOps(client);
    // -------------------------------------------------

    // If everything is ok, send out REP_PLAYERS_LIST_S_PKT

    // Declare some useful variables
    if((online_users.size()-1) > (UINT_MAX / MAX_USERNAME_LEN) ){

        cerr << "<ERR>  Number is too big for malloc, disconnecting\n";
        sendErrorMessage(ERR_INTERNAL_S_PKT, client);
        clear();
        exit(1);

    }
    unsigned int list_of_online_players_len = (online_users.size()-1)*MAX_USERNAME_LEN;
    unsigned char *list_of_online_players = (unsigned char *)malloc(list_of_online_players_len);
    if(!list_of_online_players) {
		
        cerr << "<ERR> malloc() returned NULL, disconnecting!\n";
        sendErrorMessage(ERR_INTERNAL_S_PKT, client);
        clear();
        exit(1);

    }

    // -----------------------------

    load_list_of_online_players(list_of_online_players, usernames[client]);
    
    // I need to authenticate the sequence number to avoid replay attacks, or reordering. 
    unsigned char *sym_enc_iv = NULL; 

    opcode = REP_PLAYERS_LIST_S_PKT;

    unsigned int aad_send_size = OPCODE_LEN + sizeof(seq_write_ops.at(client));
    unsigned char *aad_send = (unsigned char *)malloc(aad_send_size);
    unsigned char *tag_send = NULL;
    unsigned char *cphr_buf = NULL;

    if((sizeof(unsigned int)) > UINT_MAX - list_of_online_players_len){

        cerr << "<ERR>  Number is too big for malloc, disconnecting\n";
        sendErrorMessage(ERR_INTERNAL_S_PKT, client);
        clear();
        exit(1);

    }
    unsigned int clear_size = (sizeof(unsigned int)) + list_of_online_players_len;
    unsigned char *clear_buf = (unsigned char *)malloc(clear_size);
    if(!aad_send || !clear_buf) {
		
        cerr << "<ERR> malloc() returned NULL, disconnecting!\n";
        sendErrorMessage(ERR_INTERNAL_S_PKT, client);
        clear();
        exit(1);

    }

    // Concatenate AAD fields (Opcode, seq_write_ops) 
    num_fields = 2;

    vector<unsigned char *> aad_send_fields = {(unsigned char*)&opcode, 
                                                (unsigned char*)&seq_write_ops.at(client)};
    vector<unsigned int> aad_send_fields_len = {OPCODE_LEN, 
                                                sizeof(seq_write_ops.at(client))};

    aad_send_size = load_in_buffer(aad_send, aad_send_fields, aad_send_fields_len, num_fields);
    // ----------------------------------------------

    // Concatenate fields to be encrypted (num online players, list of online players) 
    num_fields = 2;

    uint16_t num_online_players = online_users.size() - 1; // Everyone but me

    vector<unsigned char *> clear_fields = {(unsigned char*)&num_online_players, list_of_online_players};
    vector<unsigned int> clear_fields_len = {sizeof(num_online_players), list_of_online_players_len};

    clear_size = load_in_buffer(clear_buf, clear_fields, clear_fields_len, num_fields);
    // -------------------------------------------------------------------------------

    // Apply AES_GCM and get the ciphertext, the tag and the IV
    unsigned int CPHR_LEN = sym_enc_and_auth(session_key[client], sym_enc_iv, clear_buf,
                        clear_size, cphr_buf, aad_send, aad_send_size, tag_send);

#pragma optimize("", off)
    memset(list_of_online_players, 0, list_of_online_players_len);
    memset(aad_send, 0, aad_send_size);
    memset(clear_buf, 0, clear_size);
#pragma optimize("", on)
    free(list_of_online_players);
    free(aad_send);
    free(clear_buf);
    // --------------------------------------------------------

    // Convert the cphr len to be sent over the nw
    unsigned int cphr_len = htons(CPHR_LEN);
    //--------------------------------------------------

    // Prepare packet REP_PLAYERS_LIST_S
    unsigned char packet[MAX_PACKET_SIZE];
    memset(packet, 0, MAX_PACKET_SIZE); // Cleaning the buffer

    opcode = htons(opcode);

    num_fields = 5;

    vector<unsigned char *> pkt_fields_send = {(unsigned char*)&opcode, sym_enc_iv, 
                                                (unsigned char*)&cphr_len, 
                                                cphr_buf, tag_send};
    vector<unsigned int> pkt_fields_send_len = {OPCODE_LEN, sym_enc_dec_iv_len, 
                                                sizeof(cphr_len), 
                                                CPHR_LEN, TAG_LEN};
    
    int packet_size = load_in_buffer(packet, pkt_fields_send, pkt_fields_send_len, num_fields);

#pragma optimize("", off)
    memset(sym_enc_iv, 0, sym_enc_dec_iv_len);
    memset(tag_send, 0, TAG_LEN);
    memset(cphr_buf, 0, CPHR_LEN);
#pragma optimize("", on)
    free(sym_enc_iv);
    free(tag_send);
    free(cphr_buf);
    // ------------------------------------

    // Send out REP_PLAYERS_LIST_S_PKT
    cout<<"<INFO> Sending REP_PLAYERS_LIST_S_PKT\n";

    ret = send(client, packet , packet_size, 0);
    if( ret < 0 ){

        cerr<<"<ERR> Error sending REP_PLAYERS_LIST_S_PKT\n";
        sendErrorMessage(ERR_INTERNAL_S_PKT, client);
        clear();
        exit(1);

    }

    cout << "<OK>   REP_PLAYERS_LIST_S_PKT sent.\n\n";

    // Increment the counter of write ops
    incrementSeqWriteOps(client);
    // ------------------
}

void Server::forwardChallengeRequest(int client, unsigned char* buffer_in, uint16_t arrived_opcode){

    int ret;

    // Declare useful variables
    unsigned char *sym_dec_iv = (unsigned char*)malloc(sym_enc_dec_iv_len);
    unsigned char *tag_recv = (unsigned char*)malloc(TAG_LEN);
    if(!sym_dec_iv || !tag_recv) {
		
        cerr << "<ERR> malloc() returned NULL, disconnecting!\n";
        sendErrorMessage(ERR_INTERNAL_S_PKT, client);
        clear();
        exit(1);

    }
    unsigned char *cphr_buf_recv = NULL; 
	unsigned int cphr_buf_len;
    // ------------------------

    // Retrieve fixed length fields from packet
	uint16_t num_fields = 4;
	vector<unsigned char *> pkt_fields_recv = {sym_dec_iv, (unsigned char*)&cphr_buf_len, cphr_buf_recv, 
                                                tag_recv};

	vector<unsigned int> pkt_fields_recv_len = {sym_enc_dec_iv_len, sizeof(cphr_buf_len), 0, 
                                                TAG_LEN};

	get_fixed_len_fields(pkt_fields_recv, pkt_fields_recv_len, buffer_in, num_fields, true);

    // Allocate space for buffers of variable length fields
	cphr_buf_len = ntohs(cphr_buf_len);
	cphr_buf_recv = (unsigned char*)malloc(cphr_buf_len);
    if(!cphr_buf_recv) {
		
        cerr << "<ERR> malloc() returned NULL, disconnecting!\n";
        sendErrorMessage(ERR_INTERNAL_S_PKT, client);
        clear();
        exit(1);

    }
	// -----------------------------------------------------

    // Retrieve variable length fields
	pkt_fields_recv = {NULL, NULL, 
					    cphr_buf_recv, NULL};
	pkt_fields_recv_len = {sym_enc_dec_iv_len, sizeof(cphr_buf_len), 
                            cphr_buf_len, TAG_LEN};

	get_variable_len_fields(pkt_fields_recv, pkt_fields_recv_len, buffer_in, num_fields);
	// ---------------------------------------------

    // Declare variables for symmetric decryption + authentication
	unsigned char *clear_buf_recv = NULL; 
	unsigned int aad_recv_size = OPCODE_LEN + sizeof(seq_read_ops.at(client)); 
	unsigned char *aad_recv = (unsigned char *)malloc(aad_recv_size);
    if(!aad_recv) {
		
        cerr << "<ERR> malloc() returned NULL, disconnecting!\n";
        sendErrorMessage(ERR_INTERNAL_S_PKT, client);
        clear();
        exit(1);

    }
    // -----------------------------------------------------------

    // Concatenate AAD fields
	num_fields = 2;

	vector<unsigned char *> aad_recv_fields = {(unsigned char*)&arrived_opcode, 
                                                (unsigned char*)&seq_read_ops.at(client)};
	vector<unsigned int> aad_recv_fields_len = {OPCODE_LEN, 
                                                sizeof(seq_read_ops.at(client))};

	aad_recv_size = load_in_buffer(aad_recv, aad_recv_fields, aad_recv_fields_len, num_fields);
	// ------------------------

    // Apply AES_GCM and verify the tag, put the clear text in clear_buf_recv
	unsigned int clear_size_recv = sym_dec_and_auth(session_key[client], sym_dec_iv, cphr_buf_recv, cphr_buf_len,
									                clear_buf_recv, aad_recv, aad_recv_size, tag_recv);
    
#pragma optimize("", off)
    memset(sym_dec_iv, 0, sym_enc_dec_key_len);
    memset(tag_recv, 0, TAG_LEN);
    memset(cphr_buf_recv, 0, cphr_buf_len);
    memset(aad_recv, 0, aad_recv_size);
#pragma optimize("", on)
    free(sym_dec_iv);
    free(tag_recv);
    free(cphr_buf_recv);
    free(aad_recv);
	// ------------------------	

    // If the tag is valid, the number of read ops is correct
    cout << "<OK>   Message is fresh!\n\n";
    incrementSeqReadOps(client);

    unsigned char* player_to_challenge = (unsigned char*)malloc(MAX_USERNAME_LEN);
    if(!player_to_challenge) {
		
        cerr << "<ERR> malloc() returned NULL, disconnecting!\n";
        sendErrorMessage(ERR_INTERNAL_S_PKT, client);
        clear();
        exit(1);

    }
    strncpy((char*)player_to_challenge, (const char*)clear_buf_recv, MAX_USERNAME_LEN);
    player_to_challenge[MAX_USERNAME_LEN-1] = '\0';

#pragma optimize("", off)
    memset(clear_buf_recv, 0, MAX_USERNAME_LEN);
#pragma optimize("", on)
    free(clear_buf_recv);

    cout << "<INFO> Player '"<< usernames[client] << "' wants to challenge '" << player_to_challenge << "' !\n\n";

    // Forward the challenge request to the correct player 
    unsigned char packet[MAX_PACKET_SIZE];
	memset(packet, 0, MAX_PACKET_SIZE); // Cleaning the buffer

    unsigned char *sym_enc_iv = NULL;

    // Retrieve the socket of the requested client
    string challenged_username((char*)player_to_challenge); 
    int challenged_client = socket_per_username[challenged_username];

    if(client_state[challenged_client] == WAITING_CHALLENGE_REP){

        sendWaitingPlayerPacket(client, usernames[client]);

        return;

    }

#pragma optimize("", off)
     memset(player_to_challenge, 0, MAX_USERNAME_LEN);
#pragma optimize("", on)
    free(player_to_challenge);

	uint16_t opcode = FWD_REQ_CHALLENGE_S_PKT;
    
    unsigned int aad_size = OPCODE_LEN + sizeof(seq_write_ops.at(challenged_client));
	unsigned char *aad = (unsigned char *)malloc(aad_size);
	unsigned char *tag = NULL;
	unsigned char *cphr_buf_send = NULL;
	unsigned int clear_size = MAX_USERNAME_LEN;
	unsigned char *clear_buf_send = (unsigned char *)malloc(clear_size);
    if(!aad || !clear_buf_send) {
		
        cerr << "<ERR> malloc() returned NULL, disconnecting!\n";
        sendErrorMessage(ERR_INTERNAL_S_PKT, client);
        clear();
        exit(1);

    }

    // Concatenate AAD fields (Opcode, seq_write_ops) 
	num_fields = 2;

	vector<unsigned char *> aad_fields = {(unsigned char*)&opcode, 
                                            (unsigned char*)&seq_write_ops.at(challenged_client)};
	vector<unsigned int> aad_fields_len = {OPCODE_LEN, 
                                            sizeof(seq_write_ops.at(challenged_client))};

	aad_size = load_in_buffer(aad, aad_fields, aad_fields_len, num_fields);
    // ----------------------------------------------

    // Fill the clear buffer to be encrypted
    memcpy(clear_buf_send, usernames[client].c_str(), MAX_USERNAME_LEN);
	// -------------------------------------

    // Apply AES_GCM and get the ciphertext, the tag and the IV
	unsigned int CPHR_LEN = sym_enc_and_auth(session_key[challenged_client], sym_enc_iv, clear_buf_send,
												clear_size, cphr_buf_send, aad, aad_size, tag);

#pragma optimize("", off)
    memset(aad, 0, aad_size);
    memset(clear_buf_send, 0, clear_size);
#pragma optimize("", on)
    free(aad);
    free(clear_buf_send);
    // --------------------------------------------------------

    // Convert the cphr len to be sent over the nw
	unsigned int cphr_len = htons(CPHR_LEN);
    // -------------------------------------------

    // Prepare packet FWD_REQ_CHALLENGE_S
	opcode = htons(opcode);

	num_fields = 5;

    vector<unsigned char *> pkt_fields_send = {(unsigned char*)&opcode, sym_enc_iv, (unsigned char*)&cphr_len, 
											    cphr_buf_send, tag};
	vector<unsigned int> pkt_fields_send_len = {OPCODE_LEN, sym_enc_dec_iv_len, sizeof(cphr_len), 
											    CPHR_LEN, TAG_LEN};
	
	int packet_size = load_in_buffer(packet, pkt_fields_send, pkt_fields_send_len, num_fields);

#pragma optimize("", off)
    memset(sym_enc_iv, 0, sym_enc_dec_iv_len);
    memset(tag, 0, TAG_LEN);
    memset(cphr_buf_send, 0, CPHR_LEN);
#pragma optimize("", on)
    free(sym_enc_iv);
    free(tag);
    free(cphr_buf_send);
    // ------------------------------------

	// Send out FWD_REQ_CHALLENGE_S
	//cout<<"<INFO> Sending FWD_REQ_CHALLENGE_S\n";

    ret = send(challenged_client, packet, packet_size, 0);
	if( ret < 0 ){

		cerr<<"<ERR> Error sending FWD_REQ_CHALLENGE_S\n";
        sendErrorMessage(ERR_SEND_S_PKT, client);
        return;

	}

    cout <<"<INFO> FWD_REQ_CHALLENGE_S sent!\n";

	// Increment the counter of write ops
	incrementSeqWriteOps(challenged_client);
    // -----------------------------------

    // Store the pending request from this client
    pending_challenge_request[client] = socket_per_username[challenged_username];

    client_state[client] = WAITING_CHALLENGE_REP;
    client_state[challenged_client] = WAITING_CHALLENGE_REP;
    string challenger_username = usernames[client];

    for (auto user = online_users.begin(); user != online_users.end(); ++user) {
        if (*user == challenged_username) {

            online_users.erase(user);
            user--;
            
        }
        if (*user == challenger_username) {

            online_users.erase(user);
            user--;
        }
        
    }
	// ----------------------------

}

void Server::sendWaitingPlayerPacket(int challenger_client, string challenger_username){

    int ret;

    unsigned char packet[MAX_PACKET_SIZE];

    // I need to authenticate the sequence number to avoid replay attacks, or reordering. 
    unsigned char *sym_enc_iv = NULL; 

    uint16_t opcode = PLAYER_NOT_AVAILABLE_S_PKT;

    unsigned int aad_size = OPCODE_LEN + sizeof(seq_write_ops.at(challenger_client));
    unsigned char *aad = (unsigned char *)malloc(aad_size);
    unsigned char *tag = NULL;
    unsigned char *_dummy_cphr = NULL;
    if(!aad) {
		
        cerr << "<ERR> malloc() returned NULL, disconnecting!\n";
        sendErrorMessage(ERR_INTERNAL_S_PKT, challenger_client);
        exit(1);

    }

    // Concatenate AAD fields (Opcode, seq_write_ops) 
	uint16_t num_fields = 2;

	vector<unsigned char *> aad_fields = {(unsigned char*)&opcode, 
                                            (unsigned char*)&seq_write_ops.at(challenger_client)};
	vector<unsigned int> aad_fields_len = {OPCODE_LEN, 
                                            sizeof(seq_write_ops.at(challenger_client))};

	aad_size = load_in_buffer(aad, aad_fields, aad_fields_len, num_fields);
	// ----------------------------------------------

    // Apply AES_GCM and get the tag and the IV
	sym_enc_and_auth(session_key[challenger_client], sym_enc_iv, NULL, 0, _dummy_cphr, aad, aad_size, tag);
	// ----------------------------------------

	// Prepare packet 
	memset(packet, 0, MAX_PACKET_SIZE); // Cleaning the buffer

	opcode = htons(opcode);

	num_fields = 3;
	
	vector<unsigned char *> pkt_fields = {(unsigned char*)&opcode, sym_enc_iv, tag};
	vector<unsigned int> pkt_fields_len = {OPCODE_LEN, sym_enc_dec_iv_len, TAG_LEN};
	
	unsigned int packet_size = load_in_buffer(packet, pkt_fields, pkt_fields_len, num_fields);

#pragma optimize("", off)
	memset(sym_enc_iv, 0, sym_enc_dec_iv_len);
	memset(tag, 0, TAG_LEN);
	memset(aad, 0, aad_size);

#pragma optimize("", on)
	free(sym_enc_iv);
	free(tag);
	free(aad);
	// -----------------

    // Send out PLAYER_NOT_AVAILABLE_S_PKT 
	//cout<<"<INFO> Sending PLAYER_NOT_AVAILABLE_S_PKT\n";

	ret = send(challenger_client, packet, packet_size, 0);
	if( ret < 0 ){

		cerr<<"<ERR> Error sending PLAYER_NOT_AVAILABLE_S_PKT\n";
		sendErrorMessage(ERR_SEND_S_PKT, challenger_client);
        return;

	}

	cout << "<OK>   PLAYER_NOT_AVAILABLE_S_PKT sent.\n\n";

	// Increment the counter of write ops
	incrementSeqWriteOps(challenger_client);
    // -----------------------------------
}

void Server::recvReplyToChallenge(int client, unsigned char* buffer_in, uint16_t arrived_opcode){

    int ret;

    // Declare useful variables
    unsigned char *sym_dec_iv = (unsigned char*)malloc(sym_enc_dec_iv_len);
    unsigned char *tag_recv = (unsigned char*)malloc(TAG_LEN);
    if(!sym_dec_iv || !tag_recv) {
		
        cerr << "<ERR> malloc() returned NULL, disconnecting!\n";

        int challenger;
        bool found = false;

        for(int i = 0; i < pending_challenge_request.size() && !found ; i++){

            if(pending_challenge_request.at(i) == client){
                challenger = i;
                found = true;
            }
        }
        sendErrorMessage(ERR_INTERNAL_S_PKT, client);
        sendErrorMessage(ERR_INTERNAL_S_PKT, challenger);
        exit(1);

    }
    unsigned char *cphr_buf_recv = NULL; 
	unsigned int cphr_buf_len;
    // ------------------------

    // Retrieve fixed length fields from packet
	uint16_t num_fields = 4;
	vector<unsigned char *> pkt_fields_recv = {sym_dec_iv, (unsigned char*)&cphr_buf_len, 
                                                cphr_buf_recv, tag_recv};

	vector<unsigned int> pkt_fields_recv_len = {sym_enc_dec_iv_len, sizeof(cphr_buf_len), 
                                                0, TAG_LEN};

	get_fixed_len_fields(pkt_fields_recv, pkt_fields_recv_len, buffer_in, num_fields, true);

    // Allocate space for buffers of variable length fields
	cphr_buf_len = ntohs(cphr_buf_len);
	cphr_buf_recv = (unsigned char*)malloc(cphr_buf_len);
    if(!cphr_buf_recv) {
		
        cerr << "<ERR> malloc() returned NULL, disconnecting!\n";
        bool found = false;
        int challenger;
        for(int i = 0; i < pending_challenge_request.size() && !found ; i++){

            if(pending_challenge_request.at(i) == client){
                challenger = i;
                found = true;
            }
        }

        sendErrorMessage(ERR_INTERNAL_S_PKT, client);
        sendErrorMessage(ERR_INTERNAL_S_PKT, challenger);
        exit(1);    

    }
	// -----------------------------------------------------

    // Retrieve variable length fields from packet 5
	pkt_fields_recv = {NULL, NULL, cphr_buf_recv, NULL};
	pkt_fields_recv_len = {sym_enc_dec_iv_len, sizeof(cphr_buf_len), cphr_buf_len, TAG_LEN};

	get_variable_len_fields(pkt_fields_recv, pkt_fields_recv_len, buffer_in, num_fields);
	// ----------------------------------------------

    // Declare variables for symmetric decryption + authentication
	unsigned char *clear_buf_recv = NULL;
	unsigned int aad_recv_size = OPCODE_LEN + sizeof(seq_read_ops.at(client)); 
	unsigned char *aad_recv = (unsigned char *)malloc(aad_recv_size);
    if(!aad_recv) {
		
        cerr << "<ERR> malloc() returned NULL, disconnecting!\n";
        bool found = false;
        int challenger;
        for(int i = 0; i < pending_challenge_request.size() && !found ; i++){

            if(pending_challenge_request.at(i) == client){
                challenger = i;
                found = true;
            }
        }

        sendErrorMessage(ERR_INTERNAL_S_PKT, client);
        sendErrorMessage(ERR_INTERNAL_S_PKT, challenger);
        exit(1);

    }
    // -----------------------------------------------------------

    // Concatenate AAD fields
	num_fields = 2;

	vector<unsigned char *> aad_recv_fields = {(unsigned char*)&arrived_opcode, 
                                                (unsigned char*)&seq_read_ops.at(client)};
	vector<unsigned int> aad_recv_fields_len = {OPCODE_LEN, 
                                                sizeof(seq_read_ops.at(client))};

	aad_recv_size = load_in_buffer(aad_recv, aad_recv_fields, aad_recv_fields_len, num_fields);
	// ------------------------

    // Apply AES_GCM and verify the tag, put the clear text in clear_buf_recv
	unsigned int clear_size_recv = sym_dec_and_auth(session_key[client], sym_dec_iv, cphr_buf_recv, cphr_buf_len,
									                clear_buf_recv, aad_recv, aad_recv_size, tag_recv);

#pragma optimize("", off)
    memset(sym_dec_iv, 0, sym_enc_dec_iv_len);
    memset(tag_recv, 0, TAG_LEN);
    memset(cphr_buf_recv, 0, cphr_buf_len);
    memset(aad_recv, 0, aad_recv_size);
#pragma optimize("", on)
    free(sym_dec_iv);
    free(tag_recv);
    free(cphr_buf_recv);
    free(aad_recv);
	// ------------------------	

    // If the tag is valid, the number of read ops is correct
    cout << "<OK>   Message is fresh!\n\n";

    incrementSeqReadOps(client);

    unsigned char* challenger_player = (unsigned char*)malloc(MAX_USERNAME_LEN);
    if(!challenger_player) {
		
        cerr << "<ERR> malloc() returned NULL, disconnecting!\n";
        bool found = false;
        int challenger;
        for(int i = 0; i < pending_challenge_request.size() && !found ; i++){

            if(pending_challenge_request.at(i) == client){
                challenger = i;
                found = true;
            }
        }

        sendErrorMessage(ERR_INTERNAL_S_PKT, client);
        sendErrorMessage(ERR_INTERNAL_S_PKT, challenger);
        exit(1);

    }
    strncpy((char*)challenger_player, (const char*)clear_buf_recv, MAX_USERNAME_LEN);
    challenger_player[MAX_USERNAME_LEN-1] = '\0';
    string challenger_player_str((char*)challenger_player);

    int challenger = socket_per_username[challenger_player_str];
    // Check if the challenge request exists
    if(!(pending_challenge_request[challenger] == client )){

        cerr << "<ERR>  Challenge request not existing!\n";
        exit(1);
    }

    if(arrived_opcode == ACCEPT_CHALLENGE_C_PKT){

        handleAcceptedChallenge(client, challenger);
    
    }

    if(arrived_opcode == REFUSE_CHALLENGE_C_PKT){
        
        handleRefusedChallenge(client, challenger);

    }

#pragma optimize("", off)
    memset(challenger_player, 0, MAX_USERNAME_LEN);
    memset(clear_buf_recv, 0, MAX_USERNAME_LEN);
#pragma optimize("", on)
    free(challenger_player);
    free(clear_buf_recv);

}

void Server::handleAcceptedChallenge(int client, int challenger){

    // Send the packet to both the peers

    // As for the challenger, we forward the ACCEPT packet, and we also put the challenged player pubkey and (IP, port)

    unsigned char packet[MAX_PACKET_SIZE];
	memset(packet, 0, MAX_PACKET_SIZE); // Cleaning the buffer

    // Since the challenged player accepted the challenge, the server can send the challenged player's pubkey
    // in this message (AAD) together with the IP address

    // Serialize the challenged player pubkey to be sent over socket
    unsigned char* challenged_player_pubkey_buf = NULL;
    unsigned int CHALLENGED_PLAYER_PUBKEY_SIZE = i2d_PUBKEY(user_pubkey[client], &challenged_player_pubkey_buf);
    unsigned int challenged_player_pubkey_size = htons(CHALLENGED_PLAYER_PUBKEY_SIZE);
    // ------------------------------------------------------

    // I need to authenticate the sequence number to avoid replay attacks, or reordering. 
	unsigned char *sym_enc_iv = NULL;

    uint16_t opcode = FWD_ACC_CHALLENGE_S_PKT;

    if(OPCODE_LEN > UINT_MAX - sizeof(seq_write_ops.at(challenger)) - CHALLENGED_PLAYER_PUBKEY_SIZE){

        cerr << "<ERR>  Number is too big for malloc, disconnecting\n";
        sendErrorMessage(ERR_INTERNAL_S_PKT, client);
        sendErrorMessage(ERR_INTERNAL_S_PKT, challenger);
        exit(1);

    }
    unsigned int aad_size_to_challenger = OPCODE_LEN + sizeof(seq_write_ops.at(challenger)) + 
                                            CHALLENGED_PLAYER_PUBKEY_SIZE;
	unsigned char *aad_to_challenger = (unsigned char *)malloc(aad_size_to_challenger);
	unsigned char *tag = NULL;
	unsigned char *cphr_buf_send = NULL;
    if(MAX_USERNAME_LEN > UINT_MAX - INET_ADDRSTRLEN - sizeof(client_port[client])){

        cerr << "<ERR>  Number is too big for malloc, disconnecting\n";
        sendErrorMessage(ERR_INTERNAL_S_PKT, client);
        sendErrorMessage(ERR_INTERNAL_S_PKT, challenger);
        exit(1);
        
    }
	unsigned int clear_size = MAX_USERNAME_LEN + INET_ADDRSTRLEN + sizeof(client_port[client]);
	unsigned char *clear_buf_send = (unsigned char *)malloc(clear_size);
    if(!aad_to_challenger || !clear_buf_send) {
		
        cerr << "<ERR> malloc() returned NULL, disconnecting!\n";
        sendErrorMessage(ERR_INTERNAL_S_PKT, client);
        sendErrorMessage(ERR_INTERNAL_S_PKT, challenger);
        exit(1);

    }

    // Concatenate AAD fields (Opcode, seq_write_ops) 
	uint16_t num_fields = 3;

	vector<unsigned char *> aad_fields_to_challenger = {(unsigned char*)&opcode, 
                                                        (unsigned char*)&seq_write_ops.at(challenger), 
                                                        challenged_player_pubkey_buf};
	vector<unsigned int> aad_fields_to_challenger_len = {OPCODE_LEN, 
                                                        sizeof(seq_write_ops.at(challenger)), 
                                                        CHALLENGED_PLAYER_PUBKEY_SIZE};

	aad_size_to_challenger = load_in_buffer(aad_to_challenger, aad_fields_to_challenger, aad_fields_to_challenger_len, num_fields);
    // ----------------------------------------------

    // Fill the clear buffer to be encrypted
    num_fields = 3;

    vector<unsigned char *> clear_fields_send = {(unsigned char*)usernames[client].c_str(), 
                                                    (unsigned char*)client_IP_address[client].c_str(), 
                                                    (unsigned char*)&client_port[client]};
	vector<unsigned int> clear_fields_send_len = {MAX_USERNAME_LEN, 
                                                    INET_ADDRSTRLEN, 
                                                    sizeof(client_port[client])};

    clear_size = load_in_buffer(clear_buf_send, clear_fields_send, clear_fields_send_len, num_fields);
	// -------------------------------------

    // Apply AES_GCM and get the ciphertext, the tag and the IV
	unsigned int CPHR_LEN = sym_enc_and_auth(session_key[challenger], sym_enc_iv, clear_buf_send,
											    clear_size, cphr_buf_send, aad_to_challenger, 
                                                aad_size_to_challenger, tag);
    
#pragma optimize("", off)
    memset(aad_to_challenger, 0, aad_size_to_challenger);
    memset(clear_buf_send, 0, clear_size);
#pragma optimize("", on)
    free(aad_to_challenger);
    free(clear_buf_send);
    // --------------------------------------------------------

     // Convert the cphr len to be sent over the nw
	unsigned int cphr_len = htons(CPHR_LEN);
    // -------------------------------------------

    // Prepare packet FWD_ACC_CHALLENGE_S_PKT
	opcode = htons(opcode);

	num_fields = 7;

    vector<unsigned char *> pkt_fields_send = {(unsigned char*)&opcode, sym_enc_iv, 
                                                (unsigned char*)&challenged_player_pubkey_size,
                                                challenged_player_pubkey_buf, (unsigned char*)&cphr_len, 
											    cphr_buf_send, tag};
	vector<unsigned int> pkt_fields_send_len = {OPCODE_LEN, sym_enc_dec_iv_len,
                                                sizeof(challenged_player_pubkey_size),
                                                CHALLENGED_PLAYER_PUBKEY_SIZE, sizeof(cphr_len), 
											    CPHR_LEN, TAG_LEN};
	
	int packet_size = load_in_buffer(packet, pkt_fields_send, pkt_fields_send_len, num_fields);

#pragma optimize("", off)
    memset(sym_enc_iv, 0, sym_enc_dec_iv_len);
    memset(tag, 0, TAG_LEN);
    memset(cphr_buf_send, 0, CPHR_LEN);
#pragma optimize("", on)
    free(sym_enc_iv);
    free(tag);
    free(cphr_buf_send);

    // ------------------------------------

    // Send out FWD_ACC_CHALLENGE_S
	//cout<<"<INFO> Sending FWD_ACC_CHALLENGE_S_PKT\n";

    int ret = send(challenger, packet , packet_size, 0);
	if( ret < 0 ){

		cerr<<"<ERR> Error sending FWD_ACC_CHALLENGE_S_PKT\n";
        sendErrorMessage(ERR_SEND_S_PKT, client);
        sendErrorMessage(ERR_SEND_S_PKT, challenger);
        return;

	}

    //cout << "<OK>   FWD_ACC_CHALLENGE_S_PKT sent.\n\n";

    // Increment the counter of write ops
    incrementSeqWriteOps(challenger);
    // ----------------------------------

    client_state[challenger] = IN_A_MATCH;
	// ----------------------------

    // As for the challenged player, we send the FWD_ACC_CHALLENGE_S_PKT packet, together with 
    // the challenger player pubkey and (IP, port)

    int challenged = client;

    memset(packet, 0, MAX_PACKET_SIZE); // Cleaning the buffer

    // Serialize the challenger player pubkey to be sent over socket
    unsigned char* challenger_player_pubkey_buf = NULL;
    unsigned int CHALLENGER_PLAYER_PUBKEY_SIZE = i2d_PUBKEY(user_pubkey[challenger], 
                                                            &challenger_player_pubkey_buf);
    unsigned int challenger_player_pubkey_size = htons(CHALLENGER_PLAYER_PUBKEY_SIZE);
    // ------------------------------------------------------

    // I need to authenticate the sequence number to avoid replay attacks, or reordering. 
    opcode = FWD_ACC_CHALLENGE_S_PKT;

	unsigned char *sym_enc_iv_to_challenged = NULL;

    if(OPCODE_LEN > UINT_MAX - sizeof(seq_write_ops.at(challenged)) - CHALLENGER_PLAYER_PUBKEY_SIZE){

        cerr << "<ERR>  Number is too big for malloc, disconnecting\n";
        sendErrorMessage(ERR_INTERNAL_S_PKT, client);
        sendErrorMessage(ERR_INTERNAL_S_PKT, challenger);
        exit(1);

    }
    unsigned int aad_size_to_challenged = OPCODE_LEN + sizeof(seq_write_ops.at(challenged)) + 
                                            CHALLENGER_PLAYER_PUBKEY_SIZE;
	unsigned char *aad_to_challenged = (unsigned char *)malloc(aad_size_to_challenged);
	unsigned char *tag_to_challenged = NULL;
	unsigned char *cphr_buf_to_challenged = NULL;
	unsigned char *clear_buf_to_challenged = (unsigned char *)malloc(clear_size);
    if(!aad_to_challenged || !clear_buf_to_challenged) {
		
        cerr << "<ERR> malloc() returned NULL, disconnecting!\n";
        sendErrorMessage(ERR_INTERNAL_S_PKT, client);
        sendErrorMessage(ERR_INTERNAL_S_PKT, challenger);
        exit(1);

    }
    // -----------------------------------------------------------------------------------

    // Concatenate AAD fields (Opcode, seq_write_ops) 
	num_fields = 3;

	vector<unsigned char *> aad_fields_to_challenged = {(unsigned char*)&opcode, 
                                                        (unsigned char*)&seq_write_ops.at(challenged), 
                                                        challenger_player_pubkey_buf};
	vector<unsigned int> aad_fields_to_challenged_len = {OPCODE_LEN, 
                                                        sizeof(seq_write_ops.at(challenged)), 
                                                        CHALLENGER_PLAYER_PUBKEY_SIZE};

	aad_size_to_challenged = load_in_buffer(aad_to_challenged, aad_fields_to_challenged, 
                                            aad_fields_to_challenged_len, num_fields);

    // ----------------------------------------------

    // Fill the clear buffer to be encrypted
    num_fields = 3;

    vector<unsigned char *> clear_fields_to_challenged = {(unsigned char*)usernames[challenger].c_str(), 
                                                            (unsigned char*)client_IP_address[challenger].c_str(), 
                                                            (unsigned char*)&client_port[challenger]};
	vector<unsigned int> clear_fields_to_challenged_len = {MAX_USERNAME_LEN, 
                                                            INET_ADDRSTRLEN, 
                                                            sizeof(client_port[challenger])};

    clear_size = load_in_buffer(clear_buf_to_challenged, clear_fields_to_challenged, 
                                clear_fields_to_challenged_len, num_fields);
	// -------------------------------------

    // Apply AES_GCM and get the ciphertext, the tag and the IV
	CPHR_LEN = sym_enc_and_auth(session_key[challenged], sym_enc_iv_to_challenged, clear_buf_to_challenged,
								clear_size, cphr_buf_to_challenged, aad_to_challenged, aad_size_to_challenged, 
                                tag_to_challenged);

#pragma optimize("", off)
    memset(aad_to_challenged, 0, aad_size_to_challenged);
    memset(clear_buf_to_challenged, 0, clear_size);
#pragma optimize("", on)
    free(aad_to_challenged);
    free(clear_buf_to_challenged);
    // --------------------------------------------------------

    // Convert the cphr len to be sent over the nw
	cphr_len = htons(CPHR_LEN);
    // -------------------------------------------

    // Prepare packet FWD_ACC_CHALLENGE_S_PKT
    opcode = htons(opcode);

    num_fields = 7;

    pkt_fields_send = {(unsigned char*)&opcode, sym_enc_iv_to_challenged, 
                        (unsigned char*)&challenger_player_pubkey_size,
                        challenger_player_pubkey_buf, (unsigned char*)&cphr_len, 
                        cphr_buf_to_challenged, tag_to_challenged};
	pkt_fields_send_len = {OPCODE_LEN, sym_enc_dec_iv_len,
                            sizeof(challenger_player_pubkey_size),
                            CHALLENGER_PLAYER_PUBKEY_SIZE, sizeof(cphr_len), 
                            CPHR_LEN, TAG_LEN};
	
	packet_size = load_in_buffer(packet, pkt_fields_send, pkt_fields_send_len, num_fields);

#pragma optimize("", off)
    memset(sym_enc_iv_to_challenged, 0, sym_enc_dec_iv_len);
    memset(tag_to_challenged, 0, TAG_LEN);
    memset(cphr_buf_to_challenged, 0, CPHR_LEN);
#pragma optimize("", on)
    free(sym_enc_iv_to_challenged);
    free(tag_to_challenged);
    free(cphr_buf_to_challenged);    
    // ------------------------------------

    // Send out FWD_ACC_CHALLENGE_S
	cout<<"<INFO> Sending FWD_ACC_CHALLENGE_S_PKT to chellenged player\n";

    ret = send(challenged, packet , packet_size, 0);
	if( ret < 0 ){

		cerr<<"<ERR> Error sending FWD_ACC_CHALLENGE_S_PKT to chellenged player\n";
        sendErrorMessage(ERR_SEND_S_PKT, client);
        sendErrorMessage(ERR_SEND_S_PKT, challenger);
        return;

	}
    
    cout << "<OK>   FWD_ACC_CHALLENGE_S_PKT sent to chellenged player.\n\n";

    // Increment the counter of write ops
    incrementSeqWriteOps(challenged);
    // ----------------------------------

    // Remove the challenge from the pending ones
    pending_challenge_request.erase(challenger);
    client_state[challenged] = IN_A_MATCH;
	// ------------------------------------------
}

void Server::handleRefusedChallenge(int client, int challenger){;

    // Notify the client about the reply of the challenged user
    unsigned char packet[MAX_PACKET_SIZE];
	memset(packet, 0, MAX_PACKET_SIZE); // Cleaning the buffer

    // I need to authenticate the sequence number to avoid replay attacks, or reordering. 
	unsigned char *sym_enc_iv = NULL;

    uint16_t opcode = FWD_REF_CHALLENGE_S_PKT;

    unsigned int aad_size = OPCODE_LEN + sizeof(seq_write_ops.at(challenger));
	unsigned char *aad = (unsigned char *)malloc(aad_size);
    if(!aad) {
		
        cerr << "<ERR> malloc() returned NULL, disconnecting!\n";
        sendErrorMessage(ERR_INTERNAL_S_PKT, client);
        sendErrorMessage(ERR_INTERNAL_S_PKT, challenger);
        exit(1);

    }
	unsigned char *tag = NULL;
	unsigned char *_dummy_cphr_buf = NULL;

    // Concatenate AAD fields (Opcode, seq_write_ops) 
	uint16_t num_fields = 2;

	vector<unsigned char *> aad_fields = {(unsigned char*)&opcode, 
                                            (unsigned char*)&seq_write_ops.at(challenger)};
	vector<unsigned int> aad_fields_len = {OPCODE_LEN, 
                                            sizeof(seq_write_ops.at(challenger))};

	aad_size = load_in_buffer(aad, aad_fields, aad_fields_len, num_fields);
    // ----------------------------------------------
    
    // Apply AES_GCM and get the tag and the IV
	sym_enc_and_auth(session_key[challenger], sym_enc_iv, NULL,
						0, _dummy_cphr_buf, aad, aad_size, tag);

#pragma optimize("", off)
    memset(aad, 0, aad_size);
#pragma optimize("", on)
    free(aad);
    // --------------------------------------------------------

    // Prepare FWD_REF_CHALLENGE_S_PKT
    memset(packet, 0, MAX_PACKET_SIZE); // Cleaning the buffer

	opcode = htons(opcode);

	num_fields = 3;

    vector<unsigned char *> pkt_fields = {(unsigned char*)&opcode, sym_enc_iv, tag};
	vector<unsigned int> pkt_fields_len = {OPCODE_LEN, sym_enc_dec_iv_len, TAG_LEN};

    int packet_size = load_in_buffer(packet, pkt_fields, pkt_fields_len, num_fields);

#pragma optimize("", off)
    memset(tag, 0, TAG_LEN);
    memset(sym_enc_iv, 0, sym_enc_dec_iv_len);
#pragma optimize("", on)
    free(tag);
    free(sym_enc_iv);    
    // ------------------------------------

    // Send out FWD_ACC_CHALLENGE_S
	// cout<<"<INFO> Sending FWD_REF_CHALLENGE_S_PKT\n";

    int ret = send(challenger, packet , packet_size, 0);
	if( ret < 0 ){

		cerr<<"<ERR> Error sending FWD_REF_CHALLENGE_S_PKT\n";
        sendErrorMessage(ERR_SEND_S_PKT, client);
        sendErrorMessage(ERR_SEND_S_PKT, challenger);
        return;

	}

    //cout << "<OK>   FWD_REF_CHALLENGE_S_PKT sent.\n\n";

    // Increment the counter of write ops
    incrementSeqWriteOps(challenger);
    // ----------------------------------

    // Remove the challenge from the pending ones
    pending_challenge_request.erase(challenger);

    client_state[challenger] = ON_LINE;
    client_state[client] = ON_LINE;

    // Put challenger among online users
    if ( find(online_users.begin(), online_users.end(), usernames[challenger]) == online_users.end() )
        online_users.push_back(usernames[challenger]);
    // ---------------------------------

    // Put challenged among online users
    if ( find(online_users.begin(), online_users.end(), usernames[client]) == online_users.end() )
        online_users.push_back(usernames[client]);
    // ---------------------------------
}

void Server::handleMatchFinished(int client, unsigned char* buffer_in, uint16_t arrived_opcode){

    // Declare useful variables
	unsigned char *sym_dec_iv = (unsigned char*)malloc(sym_enc_dec_iv_len);
	unsigned char *tag = (unsigned char*)malloc(TAG_LEN);
    if(!sym_dec_iv || !tag) {
		
        cerr << "<ERR> malloc() returned NULL, disconnecting!\n";
        sendErrorMessage(ERR_INTERNAL_S_PKT, client);
        exit(1);

    }
	unsigned char *cphr_buf= NULL; 
	unsigned int cphr_buf_len;
	// ------------------------

    // Retrieve fixed length fields
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
        sendErrorMessage(ERR_INTERNAL_S_PKT, client);
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
	unsigned int aad_size = OPCODE_LEN + sizeof(seq_read_ops.at(client)); 
	unsigned char *aad = (unsigned char *)malloc(aad_size);
    if(!aad) {
		
        cerr << "<ERR> malloc() returned NULL, disconnecting!\n";
        sendErrorMessage(ERR_INTERNAL_S_PKT, client);
        exit(1);

    }
	// ------------------------------------------------------------

    // Concatenate AAD fields
	num_fields = 2;

    uint16_t opcode = P2P_MATCH_FINISHED_C_PKT; 

	vector<unsigned char *> aad_fields = {(unsigned char*)&opcode, (unsigned char*)&seq_read_ops.at(client)};
	vector<unsigned int> aad_fields_len = {OPCODE_LEN, sizeof(seq_read_ops.at(client))};

	aad_size = load_in_buffer(aad, aad_fields, aad_fields_len, num_fields);
	// ------------------------

    // Apply AES_GCM and verify the tag, put the clear text in clear_buf_pkt5
	int clear_size = sym_dec_and_auth(session_key[client], sym_dec_iv, cphr_buf, cphr_buf_len,
										clear_buf, aad, aad_size, tag);

#pragma optimize("", off)
    memset(sym_dec_iv, 0, sym_enc_dec_iv_len);
    memset(tag, 0, TAG_LEN);
    memset(cphr_buf, 0, cphr_buf_len);
    memset(aad, 0, aad_size);
    memset(clear_buf, 0, clear_size);
#pragma optimize("", on)
    free(sym_dec_iv);  
    free(tag);
    free(cphr_buf); 
    free(aad);   
    free(clear_buf);   
	// ------------------------

    // If the tag is valid, the number of read ops is correct --> message is fresh
    cout << "<OK>   Message is fresh!\n\n";

	incrementSeqReadOps(client);

    // Put client among online users
    if ( find(online_users.begin(), online_users.end(), usernames[client]) == online_users.end() )
        online_users.push_back(usernames[client]);
    // ------------------------------

    client_state[client] = ON_LINE;
    
}

void Server::clear(){

    EVP_PKEY_free(sv_prvkey);
    X509_free(sv_cert);
    online_users.clear();
    client_state.clear();
    client_last_opcode.clear();
    nonce_sv_per_client.clear();
    user_pubkey.clear();
    sv_dh_prvkey_per_client.clear();
    usernames.clear();
    socket_per_username.clear();
    client_IP_address.clear();
    client_port.clear();
    session_key.clear();
    seq_read_ops.clear();
    seq_write_ops.clear();
    pending_challenge_request.clear();
}