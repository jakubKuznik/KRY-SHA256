// Faculty: BUT FIT 
// Course: KRY 
// Project Name: SHA-256, Length extension attack 
// Name: Jakub Kuznik
// Login: xkuzni04
// Year: 2024

#include <iostream>
#include <list>
#include <string.h>
#include <algorithm>
#include <regex>

#define MAC_SIZE 256 
#define MAC_SIZE_HEX 64 
#define MAC_SIZE_CHAR 32 

#define C_SHA_COUNT 0
#define S_MAC_COUNT 1 
#define V_VALIDATE_MAC 2 
#define E_LEN_EXT_ATTACK 3 
#define NOTHING 4 

#define INIT_SIZE 1024 


// SHA CONST 
#define RESERVED_FOR_MESSAGE_LEN_BITS 64
#define RESERVED_ONE_BYTE 8 
#define MESS_BLOCK_SIZE_BITS 512
#define MESS_SCHEDULE_SIZE 64 // 64 x uint_32
#define RESERVED_BIT 0x80
#define H0 0x6a09e667
#define H1 0xbb67ae85
#define H2 0x3c6ef372
#define H3 0xa54ff53a
#define H4 0x510e527f
#define H5 0x9b05688c
#define H6 0x1f83d9ab
#define H7 0x5be0cd19

#define W0 0
#define W1 1
#define W9 9
#define W14 14
#define W16 16

/**
 * Structure that represents program configuration.
 * 
 * @program program that'll be executed
 *   can be: C_SHA_COUNT | S_MAC_COUNT | V_VALIDATE_MAC | E_LEN_EXT_ATTACK
 * 
 * @key Specify secret key for MAC calculation. 
 *          KEY format: ^[A-Fa-f0-9]*$
 * @mac Specify MAC of the input message for its 
 * 		verification or attack execution.
 * @num Specify length of the secret key 
 * @msgExt  Specify extension of input message for attack execution.
 *         MSG format: ^[a-zA-Z0-9!#$%&'"()*+,\-.\/:;<>=?@[\]\\^_{}|~]*$
*/
typedef struct {
	char program[1];
	char *key;
	char mac[MAC_SIZE_CHAR];
	uint64_t num;
	char *msgExt;
} programConfig;

// Regex for key - validate format 
// ^[A-Fa-f0-9]*$.
std::regex keyRegex("^[A-Za-z0-9]*$");

// Regex for msgExt - validate format
// ^[a-zA-Z0-9!#$%&’"()*+,\-.\/:;<>=?@[\]\\^_{}|~]*$
std::regex msgExtRegex("^[a-zA-Z0-9!#$%&’\"()*+,\\-.\\/:;<>=?@[\\]\\\\^_{}|~]*$");