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
 * Parse input args
*/
void argParse(int argc, char **argv, programConfig *prConf){

	// We cannot combine -c -s -v -e 
	bool one = false;

	// if there are no args 
	if (argc == 1){
		printHelp();
	}



	for (int i = 1; i < argc; i++){
		if (strcmp(argv[i],"-c") == 0){
		
		}
		else if (strcmp(argv[i],"-s") == 0){
		
		}
		else if (strcmp(argv[i],"-v") == 0){
		
		}
		else if (strcmp(argv[i],"-e") == 0){
		
		}
		else if (strcmp(argv[i],"-k") == 0){
		
		}
		else if (strcmp(argv[i],"-m") == 0){
		
		}
		else if (strcmp(argv[i],"-n") == 0){
		
		}
		else if (strcmp(argv[i],"-a") == 0){
		
		}
		else{
			goto errorArgs;
		}
	}

	return;

errorArgs:
	cerr << "Error wrong arguments. Try run without args for help message!" << endl;
	exit(2);
}

int main(int argc, char **argv){
	programConfig prConf;

	// arg parsing 
	argParse(argc, argv, &prConf);
  
	cerr << " ll" << endl;

	return 0;
}