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
	cout << "           KEY format: ^[A-Fa-f0-9]*$" << endl;
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
			// ^[a-zA-Z0-9!#$%&’"()*+,\-.\/:;<>=?@[\]\\^_{}|~]*$
			if (!regex_match(prConf->msgExt, msgExtRegex)){
				goto errorFormat;
			}
			strcpy(prConf->msgExt, argv[i]);
		
		}
		else{
			goto errorArgs;
		}
	}

	if (prConf->program[0] == NOTHING){
		goto errorArgs;	
	}
	else if (prConf->program[0] == V_VALIDATE_MAC){
		if (macSet == false || keySet == false){
			goto errorArgs;	
		}
	}
	else if (prConf->program[0] == E_LEN_EXT_ATTACK){
		if (macSet == false || numSet == false || msgSet == false){
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
 * If malloc error return -1
 * else return input string size  
*/
int readInput(char **out, uint64_t *length){

	int c;
	uint64_t allocatedSize = INIT_SIZE;
	*length = 0;

	*out = (char *)malloc(INIT_SIZE * sizeof(char));
	if (*out == NULL){
		return -1;
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
int initMessSchedule(uint32_t *messSchedule, uint32_t *messBlocks){
	
	uint32_t sigma0;
	uint32_t sigma1;

	uint32_t temp1;
	uint32_t temp2;
	uint32_t temp3;

	// initialize block with zeros 0 
	for (int i = 0; i < MESS_SCHEDULE_SIZE; i++){
		messSchedule[i] = 0;
	}

	// copy 1st chunk into 1st 166 words w[0..15] of the message schedule 
	for (int i = 0; i < 16; i++){
		messSchedule[i] = messBlocks[i];
	}

	// sigma 0 =     w1 right rotate 7 
	//       	 XOR w1 right rotate 18 
	//           XOR w1 right shift 3  
	// sigma 1 =     w14 right rotate 17 
	//       	 XOR w19 right rotate 19
	//           XOR w10 right shift 10 
	// w16     =     w0 
	//       	  OR sigma0 
	//       	  OR w9
	//       	  OR sigma1 
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


	return 0;
}

/**
 * Count SHA 
 * 
 * return -1 if malloc error.
*/
int countSHA(char *inputMess, uint64_t inputLen){

	uint32_t * messBlocks;
	uint64_t blocksCount;
	
	uint32_t messSchedule[MESS_SCHEDULE_SIZE];
	
	// split the message to the chunks 
	messBlocks = createMessBlock(inputMess, inputLen, &blocksCount);
	if (messBlocks == NULL){
		return -1;
	}
	
	cout << "Input Message: " << endl;
	for (uint64_t i = 0; i < inputLen; ++i) {
        printf("%02X ", static_cast<unsigned char>(inputMess[i]));
	}
	cout << endl << "Message block: " << endl;
	for (uint64_t i = 0; i < (16 * blocksCount); ++i) {
        printf("%08X ", messBlocks[i]);
	}

	// Inititialize message schedule   
	initMessSchedule(messSchedule, messBlocks);
	cout << endl << "Message schedule: " << endl;
	for (int i = 0; i < MESS_SCHEDULE_SIZE; ++i) {
        printf("%08X ", messSchedule[i]);
	}


	free(messBlocks);
	return 0;
}
/******************************************************/


int main(int argc, char **argv){
	
	programConfig prConf;
	char *inputMessage = NULL;
	uint64_t inputLen;

	// arg parsing 
	argParse(argc, argv, &prConf);

	//read from stdin
	if(readInput(&inputMessage, &inputLen) == -1){
		goto errorMalloc;
	}

	// TODO remove debug  
	// -s -k KEY 
	// KEYmessage 
	cout << "Key: " << endl;
	if (prConf.key != nullptr)
		cout << prConf.key << endl;
	cout << "MSG ext: " << endl;
	if (prConf.msgExt != nullptr)
		cout << prConf.msgExt << endl;
	cout << "program config: " << endl;
	cout << prConf.program[0] << endl;
	cout << "MAC: " << endl;
	for (int i = 0; i < MAC_SIZE_CHAR; ++i) {
        printf("%02X ", static_cast<unsigned char>(prConf.mac[i]));
    }
	cout << endl << "Input Length: " << endl;
	cout << inputLen << endl;
	cout << "Input Message: " << endl;
	for (uint64_t i = 0; i < inputLen; ++i) {
        printf("%02X ", static_cast<unsigned char>(inputMessage[i]));
	}

	if(prConf.program[0] == C_SHA_COUNT){
		if (countSHA(inputMessage, inputLen) == -1){
			goto errorMalloc;
		}
	}
	else if(prConf.program[0] == S_MAC_COUNT){

	}
	else if(prConf.program[0] == V_VALIDATE_MAC){

	}
	else if(prConf.program[0] == E_LEN_EXT_ATTACK){

	}


	free(inputMessage);
	freeConfig(&prConf);
	return 0;



errorMalloc:
	cerr << "Error: Memory allocation error"<< endl;
	freeConfig(&prConf);
	exit(3);
}