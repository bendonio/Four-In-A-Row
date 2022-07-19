#ifndef CLIENT_CLASS_H
#define CLIENT_CLASS_H

#include <iostream>
#include <vector>
#include <map>
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
#include "../game/FourInARow.h"
using namespace std;

class Client {

 private: 
 
  string username;
  string user_prvkey_file_name;
  EVP_PKEY *user_prvkey;

  struct sockaddr_in sv_addr;
  socklen_t len_sv_addr;
  struct sockaddr_in peer_addr;
  socklen_t len_peer_addr;
  struct sockaddr_in my_addr;
  socklen_t len_my_addr;
  int master_fd;
  int server_fd;
  int peer_fd;

  unsigned int seq_read_ops = 0;
	unsigned int seq_write_ops = 0;
  unsigned char* session_key = (unsigned char *)malloc(sym_enc_dec_key_len);

  unsigned char opponent[MAX_USERNAME_LEN];
  EVP_PKEY* opponent_pubkey;
  unsigned char *last_nonce_user = (unsigned char *)malloc(NONCE_LEN);
  unsigned char* match_session_key = (unsigned char *)malloc(sym_enc_dec_key_len);
  unsigned int match_seq_read_ops = 0;
	unsigned int match_seq_write_ops = 0;

 public:

  Client();

  Client(string);

  string getUsername(){ return username; }

  int getMasterFd(){ return master_fd; }

  void setUsername(string);

  void makeConnection();

  bool authentication(string password);

  /**
   * @brief Send to the server the request to get the list of online players
   * 
   * @return true on success
   * @return false on failure of the sendto() function
   */
  bool sendRequestListOnlinePlayers();

  map<string, string> recvListOnlinePlayers();

  bool sendChallengeRequest(const char *player_to_challenge);

  int recvChallengeResponse();
  
  //TODO: fare la logout prima di uscire
  void incrementSeqReadOps() { if(seq_read_ops == UINT_MAX){ 
                                  cerr << "<ERR>  Sequence number too big, disconnecting\n";
                                  logout();
                                  exit(1);
                                } else 
                                  seq_read_ops++;}
  
  void incrementSeqWriteOps() { if(seq_write_ops == UINT_MAX){ 
                                  cerr << "<ERR>  Sequence number too big, disconnecting\n";
                                  logout();
                                  exit(1);
                                } else 
                                  seq_write_ops++;}

  int recvMessage(int sock_recv, unsigned char*& buffer_in_out);

  /**
   * @brief 
   * 
   * @param buffer_in 
   * @param opcode 
   * @return true if I accept the challenge
   * @return false if I refuse the challenge
   */
  void handleChallengeRequest(unsigned char* buffer_in);

  void sendReplyToChallenge(unsigned char* buffer_in, uint16_t opcode);

  void handleAcceptedChallenge(unsigned char* buffer_in);

  void handleRefusedChallenge(unsigned char* buffer_in, uint16_t opcode);

  void handleWaitingPlayerPacket(unsigned char* buffer_in, uint16_t opcode);

  bool player1P2PAuthentication();

  bool player2P2PAuthentication(unsigned char* buffer_in);

  void playP2PMatch(bool firstToPlay);

  void sendMoveMessage(const uint16_t column_index);

  uint16_t recvMoveMessage(unsigned char* buffer_in);

  bool handleUserTurn(FourInARow &gameBoard);

  bool handleOpponentTurn(FourInARow &gameBoard);

  void sendP2PMatchFinished();

  bool logout();
    
};

#endif