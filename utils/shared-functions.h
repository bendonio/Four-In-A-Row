#ifndef SHARED_FUNCTION_H
#define SHARED_FUNCTION_H

#include <vector>
#include "./shared-constants.h"

using namespace std;

int get_variable_len_fields(vector<unsigned char*> dsts, vector<unsigned int> dsts_len, unsigned char *src, 
                            int dsts_num);

int get_fixed_len_fields(vector<unsigned char*> dsts, vector<unsigned int> dsts_len, unsigned char *src, 
                            int dsts_num, bool with_opcode);

bool nonces_are_equal(unsigned char* nonce_a, unsigned char* nonce_b, uint16_t nonce_len);

int load_in_buffer(unsigned char* dest, vector<unsigned char *> srcs, vector<unsigned int> srcs_len, 
                    uint16_t srcs_num);

bool opcode_is_ok(uint16_t arrived_opcode, unsigned int correct_opcode);

uint16_t get_opcode(unsigned char *buffer_in);

void setStdinEcho(bool enable = true);

#endif 