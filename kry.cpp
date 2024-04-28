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
	
	cout << prConf->key << endl;
	
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
	exit(4);
}

int main(int argc, char **argv){
	programConfig prConf;

	// arg parsing 
	argParse(argc, argv, &prConf);
  
	cerr << " ll" << endl;
	
	freeConfig(&prConf);
	return 0;
}