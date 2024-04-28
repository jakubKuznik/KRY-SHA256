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
#define NOTHING 255 

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
std::regex keyRegex("^[A-Fa-f0-9]*$");

// Regex for msgExt - validate format
// ^[a-zA-Z0-9!#$%&’"()*+,\-.\/:;<>=?@[\]\\^_{}|~]*$
std::regex msgExtRegex("^[a-zA-Z0-9!#$%&’\"()*+,\\-.\\/:;<>=?@[\\]\\\\^_{}|~]*$");