#include <iostream>
#include <vector>
#include <termios.h>
#include <unistd.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "./shared-constants.h"

using namespace std;

bool opcode_is_ok(uint16_t arrived_opcode, unsigned int correct_opcode){

    if(arrived_opcode != correct_opcode)
		return false;

	return true;
}

uint16_t get_opcode(unsigned char *buffer_in){

	uint16_t opcode;

	memcpy(&opcode, buffer_in, 2);
	opcode = ntohs(opcode);

	return opcode;
}

int get_variable_len_fields(vector<unsigned char*> dsts, vector<unsigned int> dsts_len, unsigned char *src, int dsts_num){//unsigned char** dsts, const unsigned int* dsts_len, unsigned char *src, int dsts_num){
	
	unsigned int index = 2; // we start soon afetr the opcode (2 bytes)

	for(int i = 0; i < dsts_num; i++){

		if(dsts.at(i) == NULL){
			// Fixed len field, only update the index
			index += dsts_len.at(i);

		} else {
			// Variale len field --> store it
			memcpy(dsts.at(i), src + index , dsts_len.at(i));
			index += dsts_len.at(i);

		}

	}

	return index;

}

int get_fixed_len_fields(vector<unsigned char*> dsts, vector<unsigned int> dsts_len, unsigned char *src, 
							int dsts_num, bool with_opcode){
	
	unsigned int index;
	if(with_opcode)
		index = 2; // We start soon afetr the opcode (2 bytes)
	else 
		index = 0;

	for(int i = 0; i < dsts_num; i++){

		if(dsts_len.at(i) != 0){

			memset(dsts.at(i), 0, dsts_len.at(i)); // Clean the buffer

			memcpy((dsts.at(i)), src + index , dsts_len.at(i));

			index += dsts_len.at(i);

		} else {
			// Variable len fields (dsts[i] == 0)

			// The length is always stored in the previous field (unsigned int)
			unsigned int len_tmp; 
			memset(&len_tmp, 0, sizeof(unsigned int));
			memcpy(&len_tmp, dsts[i-1], sizeof(unsigned int));

			len_tmp = ntohs(len_tmp);

			index += len_tmp;
		}

	}

	return index;
}


bool nonces_are_equal(unsigned char* nonce_a, unsigned char* nonce_b, uint16_t nonce_len){

	for(int i = 0; i < nonce_len; i++){

		if(nonce_a[i] != nonce_b[i])
			return false;

	}

	return true;
}

int load_in_buffer(unsigned char* dest, vector<unsigned char *> srcs, vector<unsigned int> srcs_len, uint16_t srcs_num){

	unsigned int index = 0;

	for(int i = 0; i < srcs_num; i++){

		memcpy(dest + index, srcs.at(i), srcs_len.at(i));
		index += srcs_len.at(i);

	}

	return index;

}

void setStdinEcho(bool enable = true) {
    struct termios tty;
    tcgetattr(STDIN_FILENO, &tty);
    if(!enable)
        tty.c_lflag &= ~ECHO;
    else
        tty.c_lflag |= ECHO;
    (void)tcsetattr(STDIN_FILENO, TCSANOW, &tty);
}