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
#define MESS_BLOCK_SIZE_UINT 16
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

const uint32_t K[] = {
0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

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
	uint64_t keySize;
	char mac[MAC_SIZE_CHAR];
	uint64_t num;
	char *msgExt;
	uint64_t msgSize;
} programConfig;

// Regex for key - validate format 
// ^[A-Fa-f0-9]*$.
std::regex keyRegex("^[A-Za-z0-9]*$");

// Regex for msgExt - validate format
// ^[a-zA-Z0-9!#$%&’"()*+,\-.\/:;<>=?@[\]\\^_{}|~]*$
std::regex msgExtRegex("^[a-zA-Z0-9!#$%&’\"()*+,\\-.\\/:;<>=?@[\\]\\\\^_{}|~]*$");