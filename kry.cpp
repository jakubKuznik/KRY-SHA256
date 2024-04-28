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
 * 23 15 87 96 
 * a4 5a 93 92 
 * 95 1d 9a 72 
 * df fd 6a 53 
 * 9b 14 a0 78 
 * 32 39 0b 93 
 * 7b 94 a8 0d 
 * db 6d c1 8e

 * 0010 0011 0001 0101 1000 0111 1001 0110 
 * 1010 0100 0101 1010 1001 0011 1001 0010 
 * 1001 0101 0001 1101 1001 1010 0111 0010 
 * 1101 1111 1111 1101 0110 1010 0101 0011 
 * 1001 1011 0001 0100 1010 0000 0111 1000
 * 0011 0010 0011 1001 0000 1011 1001 0011
 * 0111 1011 1001 0100 1010 1000 0000 1101 
 * 1101 1011 0110 1101 1100 0001 1000 1110
 * 
 *  35  21 135 150 164  90 147 146 149  29 154
 * 114 223 253 106  83 155  20 160 120  50  57 
 *  11 147 123 148 168  13 219 109 193 142
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

//	for (int i = 0; i < MAC_SIZE_CHAR; i++){
//		printf("%u ", static_cast<unsigned char>(out[i]));
//	}
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

int main(int argc, char **argv){
	programConfig prConf;

	// arg parsing 
	argParse(argc, argv, &prConf);

	cout << "Key: " << endl;
	cout << prConf.key << endl;
	cout << "MSG ext: " << endl;
	cout << prConf.msgExt << endl;
	cout << "program config: " << endl;
	cout << prConf.program << endl;
	cout << "MAC: " << endl;
	for (size_t i = 0; i < MAC_SIZE_CHAR; ++i) {
        printf("%02X ", static_cast<unsigned char>(prConf.mac[i]));
    }

	freeConfig(&prConf);
	return 0;
}