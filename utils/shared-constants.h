#ifndef SHARED_CONSTANTS_H
#define SHARED_CONSTANTS_H

#include <openssl/evp.h>

const uint16_t SERVER_PORT = atoi("2000");
static const EVP_CIPHER *sym_enc_dec_cipher = EVP_aes_128_gcm();
const unsigned int sym_enc_dec_iv_len = EVP_CIPHER_iv_length(sym_enc_dec_cipher);
const unsigned int sym_enc_dec_block_size = EVP_CIPHER_block_size(sym_enc_dec_cipher);
const unsigned int sym_enc_dec_key_len = EVP_CIPHER_key_length(sym_enc_dec_cipher);


#define SERVER_IP                       "127.0.0.1"
#define SERVER_CERT_FILE_NAME           "server_files/4_in_a_row_server_cert.pem"
#define SERVER_PRIVKEY_FILE_PATH        "server_files/4_in_a_row_server_privkey.pem"
#define SERVER_DH_KEY_FILE_PATH         "server_files/4_in_a_row_server_dh_key.pem"
#define CA_CERT_FILE_NAME               "client_files/ca_cert.pem"
#define CRL_FILE_NAME                   "client_files/crl.pem"

#define MAX_PACKET_SIZE                 4096
#define MAX_USERNAME_LEN                17 // 16 chars + end of string
#define NONCE_LEN                       2
#define IV_LEN                          12
#define OPCODE_LEN                      2
#define ENCRYPTED_CERT_SIZE_LEN         2
#define TAG_LEN                         16

// OPCODES (Name format: main-info-in-the-packet_who-sends-the-message(C or S)_PKT)
#define LOG_OUT_C_PKT                       0
#define HELLO_C_PKT                         1
#define HELLO_S_PKT                         2
#define HELLO_DONE_C_PKT                    3
#define REQ_PLAYERS_LIST_C_PKT              4
#define REP_PLAYERS_LIST_S_PKT              5
#define REQ_CHALLENGE_C_PKT                 6
#define FWD_REQ_CHALLENGE_S_PKT             7
#define PLAYER_NOT_AVAILABLE_S_PKT          8 
#define ACCEPT_CHALLENGE_C_PKT              9
#define REFUSE_CHALLENGE_C_PKT              10
#define FWD_ACC_CHALLENGE_S_PKT             11
#define FWD_REF_CHALLENGE_S_PKT             12
#define PLAYER1_HELLO_P_PKT                 13
#define PLAYER2_HELLO_P_PKT                 14
#define END_HANDSHAKE_P_PKT                 15
#define MOVE_P_PKT                          16
#define P2P_MATCH_FINISHED_C_PKT            17
#define ERR_USER_LOGGED_S_PKT               51
#define ERR_CONNECTION_S_PKT                52
#define ERR_AUTHENTICATION_S_PKT            53
#define ERR_INTERNAL_S_PKT                  54
#define ERR_SEND_S_PKT                      55

// CLIENT STATES
#define CONNECTED                       1   // After the HELLO PACKET
#define ON_LINE                         2   // After authentication, not playing 
#define WAITING_CHALLENGE_REP           3   // After sending challenge request 
#define IN_A_MATCH                      4   // Playing 

// GAME

const uint16_t  COLUMNS = 7;
const uint16_t  ROWS = 7;
#define EMPTY_SPACE                     0
#define OPPONENT_TOKEN                  -1
#define MY_TOKEN                        1

#endif 
