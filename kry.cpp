// Faculty: BUT FIT 
// Course: KRY 
// Project Name: SHA-256, Length extension attack 
// Name: Jakub Kuznik
// Login: xkuzni04
// Year: 2024

#include "kry.hpp"

using namespace std;

/**
 * Prints help and exit program with return code 1
*/
void printHelp(){
	cout << "Execution:" << endl;
	cout << "  ./kry {-c | -s | -v | -e} [-k KEY] [-m CHS] [-n NUM] [-a MSG]" << endl; 
	cout << "       Program reads from STDIN and print output to STDOUT.";
	cout << endl;
	cout << "    -c" << endl;
	cout << "        Count the SHA-256 of input message." << endl;
	cout << "    -s" << endl;
	cout << "        Count MAC of input messgae using SHA-256." << endl;
	cout << "    -v -m CHS -k KEY" << endl;
	cout << "        Validate MAC (-m) for given key (-k) and returns 0 if valid else 1." << endl;
	cout << "    -e -m CHS -n NUM -a MSG" << endl;
	cout << "        Execute the Length Extension Attack on given MAC (-m) and" << endl;
	cout << "        input message (-a), it uses the key length (-n)" << endl;
	cout << endl;
	cout << "    -k KEY" << endl;
	cout << "           Specify secret key for MAC calculation. " << endl;
	cout << "           KEY format: ^[A-Za-Z0-9]*$" << endl;
	cout << "    -m CHS" << endl;
	cout << "           Specify MAC of the input message for its verification or " << endl;
	cout << "           attack execution." << endl;
	cout << "    -n NUM" << endl;
	cout << "           Specify length of the secret key" << endl;
	cout << "    -a MSG" << endl;
	cout << "           Specify extension of input message for attack execution." << endl;
	cout << "           MSG format: ^[a-zA-Z0-9!#$%&\'\"()*+,\\-.\\/:;<>=?@[\\]\\\\^_{}|~]*$" << endl;
	exit(1);
}

/***************** PARSE INPUT CODE **************************/
/** 
 * Free the memory allocated for program config.
*/
void freeConfig(programConfig *prConf){
	if (prConf->key != nullptr){
		delete[] prConf->key;
	}
	if (prConf->msgExt != nullptr){
		delete[] prConf->msgExt;
	}
}

/**
 * Store hex string into the char *  
 * 
 * 23 15 87 96 a4 5a 93 92 
 * 95 1d 9a 72 df fd 6a 53 
 * 9b 14 a0 78 32 39 0b 93 
 * 7b 94 a8 0d db 6d c1 8e
 *
 * 035 021 135 150 164 090 147 146 149 029 154
 * 114 223 253 106 083 155 020 160 120 050 057 
 * 011 147 123 148 168 013 219 109 193 142
 * 
 */
void hexToChar(char *hex, char *out){

	char hexDigits[3];
	int j = 0;
	for (size_t i = 0; i < strlen(hex); i+=2){
		
		hexDigits[0] = hex[i];
		hexDigits[1] = hex[i+1];
		hexDigits[2] = '\0';

        out[j++] = static_cast<uint8_t>(std::stoi(hexDigits, nullptr, 16));
	}

	return;
}

/**
 * Parse input args
*/
void argParse(int argc, char **argv, programConfig *prConf){

	// We cannot combine -c -s -v -e 
	bool onlyOne = false;

	prConf->key = nullptr;
	prConf->msgExt = nullptr;

	bool keySet = false;
	bool macSet = false;
	bool numSet = false;
	bool msgSet = false;

	// if there are no args 
	if (argc == 1){
		printHelp();
	}

	for (int i = 1; i < argc; i++){
		if (strcmp(argv[i],"-c") == 0){
			if (onlyOne == true){
				goto errorArgs;
			}
			onlyOne = true;
			prConf->program[0] = C_SHA_COUNT;
		}
		else if (strcmp(argv[i],"-s") == 0){
			if (onlyOne == true){
				goto errorArgs;
			}
			onlyOne = true;
			prConf->program[0] = S_MAC_COUNT;
		}
		else if (strcmp(argv[i],"-v") == 0){
			if (onlyOne == true){
				goto errorArgs;
			}
			onlyOne = true;
			prConf->program[0] = V_VALIDATE_MAC;
		}
		else if (strcmp(argv[i],"-e") == 0){
			if (onlyOne == true){
				goto errorArgs;
			}
			onlyOne = true;
			prConf->program[0] = E_LEN_EXT_ATTACK;
		}
		// -m key
		else if (strcmp(argv[i],"-k") == 0){
			keySet = true;
			i++;
			if (i == argc){
				goto errorArgs;
			}
			try {
				prConf->key = new char[strlen(argv[i]) + 1];
			}
			catch (const bad_alloc& e){
				goto errorAllocation;
			}
			strcpy(prConf->key, argv[i]);
			// ^[A-Fa-f0-9]*$.
			if (!regex_match(prConf->key, keyRegex)){
				goto errorFormat;
			}
		}
		// -m CHS
		else if (strcmp(argv[i],"-m") == 0){
			macSet = true;
			i++;
			if (i == argc){
				goto errorArgs;
			}
			if (strlen(argv[i]) != MAC_SIZE_HEX){
				goto errorMacSize;
			}

			hexToChar(argv[i], prConf->mac);
			macToUint32(prConf->mac_u32, prConf->mac);

		}
		// -n NUM 
		else if (strcmp(argv[i],"-n") == 0){
			numSet = true;
			i++;
			if (i == argc){
				goto errorArgs;
			}
            try {
                prConf->num = std::stoi(argv[i]);
            } catch (const std::invalid_argument& e) {
				goto errorNum;
			} catch (const std::out_of_range& e) {
				goto errorNum;
            }
		}
		// -a MSG
		else if (strcmp(argv[i],"-a") == 0){
			msgSet= true;
			i++;
			if (i == argc){
				goto errorArgs;
			}
			try {
				prConf->msgExt = new char[strlen(argv[i]) + 1];
			}
			catch (const bad_alloc& e){
				goto errorAllocation;
			}
			strcpy(prConf->msgExt, argv[i]);
			// ^[a-zA-Z0-9!#$%&’"()*+,\-.\/:;<>=?@[\]\\^_{}|~]*$
			if (!regex_match(prConf->msgExt, msgExtRegex)){
				goto errorFormat;
			}
		}
		else{
			goto errorArgs;
		}
	}

	if (prConf->program[0] == NOTHING){
		goto errorArgs;	
	}
	else if (prConf->program[0] == C_SHA_COUNT){
		if (macSet == true || keySet == true || numSet == true || msgSet == true){
			goto errorArgs;	
		}
	}
	else if (prConf->program[0] == S_MAC_COUNT){
		if (macSet == true || keySet == false || numSet == true || msgSet == true){
			goto errorArgs;	
		}
	}
	else if (prConf->program[0] == V_VALIDATE_MAC){
		if (macSet == false || keySet == false || numSet == true || msgSet == true){
			goto errorArgs;	
		}
	}
	else if (prConf->program[0] == E_LEN_EXT_ATTACK){
		if (macSet == false || keySet == true || numSet == false || msgSet == false){
			goto errorArgs;	
		}
	}
	
	return;

errorArgs:
	cerr << "Error: wrong arguments. Try run without args for help message!" << endl;
	freeConfig(prConf);
	exit(2);
errorAllocation:
	cerr << "Error: Memory allocation error"<< endl;
	freeConfig(prConf);
	exit(3);
errorNum:
	cerr << "Error: wrong arguments. There has to be an int after -n" << endl;
	freeConfig(prConf);
	exit(4);
errorFormat:
	cerr << "Error: wrong arg format check -m or -k" << endl;
	freeConfig(prConf);
	exit(5);
errorMacSize:
	cerr << "Error: wrong arg format MAC should be 64 hexa symbols" << endl;
	freeConfig(prConf);
	exit(5);
}

/**
 * Read from STDIN to *out.
 * 
 * key will be appendend in front of message 
 * 
 * If malloc error return -1
 * else return input string size  
*/
int readInput(char **out, uint64_t *length, char *key){

	int c;
	uint64_t allocatedSize = INIT_SIZE;
	*length = 0;

	*out = (char *)malloc(INIT_SIZE * sizeof(char));
	if (*out == NULL){
		return -1;
	}

	// if there is a key append it before message 
	if (key != nullptr){
		while ((*length) < strlen(key)){
			if ((*length) + 1 > allocatedSize){
				allocatedSize += INIT_SIZE;
				char *temp = (char *)realloc(out, allocatedSize * sizeof(char));
				if (temp == NULL){
					free(out);
					return -1;
				}
				*out = temp;
			}
			(*out)[(*length)] = key[(*length)];
			(*length)++;
		}
	}

	while ((c = getchar()) != EOF){
		if ((*length) + 1 > allocatedSize){
			allocatedSize += INIT_SIZE;
			char *temp = (char *)realloc(out, allocatedSize * sizeof(char));
			if (temp == NULL){
				free(out);
				return -1;
			}
			*out = temp;
		}
		(*out)[(*length)++] = c;
	}

	return 0;
}
/******************************************************/

/***************** SHA CODE **************************/

/**
 * Create message block from input message 
 *
 * output block is always n*512 bits (16*uint_32) 
*/
uint32_t *createMessBlock(char *inputMess, uint64_t inputLen, uint64_t *blocksCount){
	
	uint32_t *blocks;
	uint64_t i;
	uint64_t index; 
	uint64_t offset;

	// 512 bit 
	// 64 bit left for message len 
	// 512 - 64 = 448 bit 
	// count number of blocks 
	*blocksCount = ((inputLen * 8 + RESERVED_FOR_MESSAGE_LEN_BITS) / MESS_BLOCK_SIZE_BITS) + 1;
	blocks = (uint32_t *)malloc((*blocksCount) * 16 * sizeof(uint32_t));
	if (blocks == NULL){
		return NULL;
	}

	// initialize block with zeros 0 
	for (uint64_t i = 0; i < (*blocksCount) * 16; i++){
		blocks[i] = 0;
	}

	// Copy the message into the array, byte by byte
    for (i = 0; i < inputLen; i++) {
        index = i / sizeof(uint32_t);
        offset = sizeof(char)* 8 * (3 - (i % sizeof(uint32_t)));
		blocks[index] |= (uint32_t)(inputMess[i]) << offset;
    }
	// append 1 
    index = i / sizeof(uint32_t);
    offset = sizeof(char)* 8 * (3 - (i % sizeof(uint32_t)));
	blocks[index] |= (uint32_t)(RESERVED_BIT) << offset;
	
	// store message len to the message block 
	//  in last 64 bits  
	blocks[((*blocksCount) * 16)-1] = (uint32_t)(inputLen*8);
	blocks[((*blocksCount) * 16)-2] = (uint32_t)((inputLen*8) >> 32);
	
	return blocks;
}

/**
 * Inititalize message schedule 
 * 
 * block is always 2048bits = (64*uint_32)  
*/
void initMessSchedule(uint32_t *messSchedule, uint32_t *messBlocks, uint64_t blockNum){
	
	uint32_t sigma0;
	uint32_t sigma1;

	uint32_t temp1;
	uint32_t temp2;
	uint32_t temp3;

	// initialize block with zeros 0 
	for (int i = 0; i < MESS_SCHEDULE_SIZE; i++){
		messSchedule[i] = 0;
	}

	// copy n-th chunk into 1st 16 words w[0..15] of the message schedule 
	for (int i = 0; i < 16; i++){
		messSchedule[i] = messBlocks[(blockNum * MESS_BLOCK_SIZE_UINT) + i];
	}

	// sigma 0 = w1  right rotate  7 XOR  w1 right rotate 18 XOR  w1 right shift 3  
	// sigma 1 = w14 right rotate 17 XOR w19 right rotate 19 XOR w10 right shift 10 
	// w16     = w0 OR sigma0 OR w9 OR sigma1 
	for (int i = 0; i < (MESS_SCHEDULE_SIZE - W16); i++){
		temp1 = (messSchedule[i+W1] >> 7)  | (messSchedule[i+W1] << (32-7));
		temp2 = (messSchedule[i+W1] >> 18) | (messSchedule[i+W1] << (32-18));
		temp3 = (messSchedule[i+W1] >> 3);
		sigma0 = temp1 ^ temp2 ^ temp3;
		
		temp1 = (messSchedule[i+W14] >> 17)  | (messSchedule[i+W14] << (32-17));
		temp2 = (messSchedule[i+W14] >> 19)  | (messSchedule[i+W14] << (32-19));
		temp3 = (messSchedule[i+W14] >> 10);
		sigma1 = temp1 ^ temp2 ^ temp3;
		
		messSchedule[i+W16] = messSchedule[i+W0] + sigma0 + messSchedule[i+W9] + sigma1;
	}
}

/**
 * Count SHA or count sha for Lenght extension attack 
 * 
 * if attack = true execute lenght extension attack  
 * 
 * return -1 if malloc error.
*/
int countSHA(char *inputMess, uint64_t inputLen, uint32_t SHA[8],
			programConfig *programConf, bool attack){

	uint32_t *messBlocks;
	uint64_t blocksCount;
	uint32_t messSchedule[MESS_SCHEDULE_SIZE];

	uint32_t h0, h1, h2, h3, h4, h5, h6, h7;

	// normal SHA computation 
	if (attack == false){
		// split the message to the chunks 
		messBlocks = createMessBlock(inputMess, inputLen, &blocksCount);
		if (messBlocks == NULL){
			return -1;
		}
		h0 = H0;
		h1 = H1;
		h2 = H2;
		h3 = H3;
		h4 = H4;
		h5 = H5;
		h6 = H6;
		h7 = H7;
	}
	// If the Lenght extension attack is happening 
	else {
		// how many blocks were in original messgae 	
		uint64_t origMessBlocks;

		// extend input message by key-len
		uint64_t origMessSize = inputLen + programConf->num;
	
		uint64_t maliciousLen;

		// count how many message blocks were in the original message 
		origMessBlocks = ((origMessSize * 8 + RESERVED_FOR_MESSAGE_LEN_BITS) / MESS_BLOCK_SIZE_BITS) + 1;
		
		// create blocks, but then put the malicious len there 		
		messBlocks = createMessBlock(programConf->msgExt, strlen(programConf->msgExt), &blocksCount);
		if (messBlocks == NULL){
			return -1;
		}	
	
		maliciousLen = (64 * origMessBlocks) + strlen(programConf->msgExt);

		// store malicious message len to the message block 
		//  in last 64 bits  
		messBlocks[(blocksCount * 16)-1] = (uint32_t)(maliciousLen*8);
		messBlocks[(blocksCount * 16)-2] = (uint32_t)((maliciousLen*8) >> 32);

		h0 = programConf->mac_u32[0];
		h1 = programConf->mac_u32[1];
		h2 = programConf->mac_u32[2];
		h3 = programConf->mac_u32[3];
		h4 = programConf->mac_u32[4];
		h5 = programConf->mac_u32[5];
		h6 = programConf->mac_u32[6];
		h7 = programConf->mac_u32[7];
	}

	uint32_t a,b,c,d,e,f,g,h;

	uint32_t temp1, temp2;
	
	uint32_t sum0, sum1;
	uint32_t choice;
	uint32_t majority;
	
	uint32_t help1, help2, help3;

	// for each chunk do the callculation 
	for (uint64_t i = 0; i < blocksCount; i++){

		// Inititialize message schedule   
		initMessSchedule(messSchedule, messBlocks, i);
	
		a = h0; b = h1; c = h2; d = h3;
		e = h4; f = h5; g = h6; h = h7;
		
		// work with message schedule 
		for (int j = 0; j < MESS_SCHEDULE_SIZE; j++){

			help1 = (e >> 6) | (e << (32-6));
			help2 = (e >> 11) | (e << (32-11));
			help3 = (e >> 25) | (e << (32-25));
			sum1  = help1 ^ help2 ^ help3;

			choice = (e & f) ^ (~e & g);

			temp1 = h + sum1 + choice + K[j] + messSchedule[j];

			help1 = (a >> 2) | (a << (32-2));
			help2 = (a >> 13) | (a << (32-13));
			help3 = (a >> 22) | (a << (32-22));
			sum0 = help1 ^ help2 ^ help3;

			majority = (a & b) ^ (a & c) ^ (b & c);

			temp2 = majority + sum0;

			h = g;
			g = f;
			f = e;
			e = d + temp1;
			d = c;
			c = b; 
			b = a;
			a = temp1 + temp2;
		}
		h0 = h0 + a;
		h1 = h1 + b;
		h2 = h2 + c;
		h3 = h3 + d;
		h4 = h4 + e;
		h5 = h5 + f;
		h6 = h6 + g;
		h7 = h7 + h;
	}
	
	SHA[0] = h0;
	SHA[1] = h1;
	SHA[2] = h2;
	SHA[3] = h3;
	SHA[4] = h4;
	SHA[5] = h5;
	SHA[6] = h6;
	SHA[7] = h7;

	free(messBlocks);
	return 0;
}

/**
 * copy Hash from char * into the uint32 array 
*/
void macToUint32(uint32_t SHA1[8], char *SHA2){
	
	// Copy the message into the array, byte by byte
    for (int i = 0; i < MAC_SIZE_CHAR; i++) {
        int index = i / sizeof(uint32_t);
        int offset = sizeof(char)* 8 * (3 - (i % sizeof(uint32_t)));
		
		SHA1[index] |= (uint32_t)(static_cast<unsigned char>(SHA2[i])) << offset;
    }
}

/**
 * Compare MAC stored in char* and SHA stored in uint32_t
 * 
 * Retunr true if they are the same 
*/
bool compareSHA(uint32_t SHA1[8], uint32_t SHA2[8]){
	
	for (uint8_t i = 0; i < 8; i++){
		if (SHA1[i] != SHA2[i]){
			return false;
		}
	}

	return true;
}
/******************************************************/


int main(int argc, char **argv){
	
	programConfig prConf;
	char *inputMessage = NULL;
	uint64_t inputLen;
	uint32_t SHA[8];

	// arg parsing 
	argParse(argc, argv, &prConf);

	//read from stdin
	if(readInput(&inputMessage, &inputLen, prConf.key) == -1){
		goto errorMalloc;
	}

	// -c || -s -k KEY 
	if(prConf.program[0] == C_SHA_COUNT || prConf.program[0] == S_MAC_COUNT){
		if (countSHA(inputMessage, inputLen, SHA, &prConf, false) == -1){
			goto errorMalloc;
		}
		// print SHA256 to STDOUT 
		for (int x = 0; x < 8; x++) {
        	printf("%08x", SHA[x]);
		}
		cout << endl;
	} 
	// -v -k KEY -m MAC 
	else if(prConf.program[0] == V_VALIDATE_MAC){
		if (countSHA(inputMessage, inputLen, SHA, &prConf, false) == -1){
			goto errorMalloc;
		}

		if(compareSHA(SHA, prConf.mac_u32) == true){
			free(inputMessage);
			freeConfig(&prConf);
			return 0;
		}
		else{
			free(inputMessage);
			freeConfig(&prConf);
			return 1;
		}
	}
	else if(prConf.program[0] == E_LEN_EXT_ATTACK){
	 	
		if (countSHA(inputMessage, inputLen, SHA, &prConf, true) == -1){
			goto errorMalloc;
		}
		
		uint32_t *messBlocks;
		uint64_t blocksCount;

		// split the message to the chunks 
		messBlocks = createMessBlock(inputMessage, (inputLen+prConf.num), &blocksCount);
		if (messBlocks == NULL){
			return -1;
		}

		// print SHA256 to STDOUT 
		for (int x = 0; x < 8; x++) {
        	printf("%08x", SHA[x]);
		}
		cout << endl;
		for (uint64_t x = 0; x < inputLen; x++) {
        	printf("%c", inputMessage[x]);
		}
		for (uint64_t i = 0; i < (blocksCount)*16; i++){
			for (int p = 0; p < 4; p++){
				if ((i * 4) + p < (inputLen + prConf.num)){
					continue;
				}
				if ((i * 4) + p == (inputLen + prConf.num)){
					cout << "\\x80";	
					continue;
				}
				int offset = 24 - ((p % 4) * 8);
				cout << "\\x" << hex << setw(2) << setfill('0') 
						<< ((messBlocks[i] >> offset) & 0xFF);
			}
		}
		free(messBlocks);
		cout << prConf.msgExt << endl;
	}

	free(inputMessage);
	freeConfig(&prConf);
	return 0;

errorMalloc:
	cerr << "Error: Memory allocation error"<< endl;
	freeConfig(&prConf);
	exit(3);
}

