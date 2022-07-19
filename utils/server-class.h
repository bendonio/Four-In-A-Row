#ifndef CLIENT_CLASS_H
#define CLIENT_CLASS_H

#include <iostream>
#include <vector>
#include <algorithm>
#include <map>
#include <unordered_set>
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
#include "./shared-functions.h"
#include "./crypto.h"
using namespace std;


class Server {

 private:

    fd_set master; // Main set
    fd_set read_fds; // Reading set
    int fdmax; // Max descriptors num
    int listener;

    sockaddr_in sv_addr;

    EVP_PKEY* sv_prvkey;
    X509* sv_cert;

    vector<string> online_users; // Users already authenticated 
    map<int,int> client_state; // clients are mapped through their corresponding socket
    map<int,int> client_last_opcode;
    map<int, unsigned char[NONCE_LEN]> nonce_sv_per_client;
    map<int, EVP_PKEY*> user_pubkey;
    map<int, EVP_PKEY*> sv_dh_prvkey_per_client;
    map<int, string> usernames;
    map<string, int> socket_per_username;
    map<int, string> client_IP_address;
    map<int, unsigned short> client_port;
	map<int, unsigned char*> session_key;
	map<int, unsigned int> seq_read_ops;
	map<int, unsigned int> seq_write_ops;
    map<int, int> pending_challenge_request;  // <challenger socket, challenged socket>

public: 

    Server();

    bool makeConnection();

    void serverSelect();

    int getFdmax(){ return fdmax;}
    
    int getListener(){ return listener;}

    void incrementSeqReadOps(int client) {  if(seq_read_ops.at(client) == UINT_MAX){ 
                                                cerr << "<ERR>  Sequence number too big, disconnecting\n";
                                                clear();
                                                exit(1);
                                            }
                                            else 
                                                (seq_read_ops.at(client))++;}
  
    void incrementSeqWriteOps(int client) { if(seq_write_ops.at(client) == UINT_MAX){ 
                                                cerr << "<ERR>  Sequence number too big, disconnecting\n";
                                                clear();
                                                exit(1);}
                                            else 
                                                (seq_write_ops.at(client))++;}

    bool fdIsSet(int socket);

    bool acceptConnection();

    void sendErrorMessage(uint16_t err_opcode, int client, sockaddr_in *client_addr);

    bool sendCertificate(int client, unsigned char* nonce_user);

    void clientLogOut(int client);

    bool clientAllowedOpcode(int client, uint16_t opcode);

    void completeAuthentication(int client, unsigned char* buffer_in);

    void load_list_of_online_players(unsigned char *& list_of_online_players_out, string current_player_username);

    void sendOnlinePlayersList(int client, unsigned char* buffer_in, uint16_t opcode);

    void forwardChallengeRequest(int client, unsigned char* buffer_in, uint16_t opcode);

    void sendWaitingPlayerPacket(int challenger_client, string challenger_username);

    void recvReplyToChallenge(int client, unsigned char* buffer_in, uint16_t arrived_opcode);

    void handleAcceptedChallenge(int client, int challenger);

    void handleRefusedChallenge(int client, int challenger);

    void handleMatchFinished(int client, unsigned char* buffer_in, uint16_t arrived_opcode);

    void clear();

    //~Server();


};

#endif
