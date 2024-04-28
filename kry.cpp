

#include "kry.hpp"

using namespace std;


void argParse(int argc, char **argv){
  
  char * temp;  

//   for (int i = 1; i < argc; i++){
//     if (strcmp(argv[i],"-ma") == 0){
//       set[MONEY_A] = stoull(argv[++i]);
//     }
//     else if (strcmp(argv[i],"-mb") == 0){
//       set[MONEY_B] = stoull(argv[++i]);
//     }
//     else if (strcmp(argv[i],"-ra") == 0){
//       temp = strtok(argv[++i], ":");
//       set[OFF_RATIO_A] = stoull(temp);
//       temp = strtok(NULL, ":");
//       set[DEF_RATIO_A] = stoull(temp);
//     }
//     else if (strcmp(argv[i],"-rb") == 0){
//       temp = strtok(argv[++i], ":");
//       set[OFF_RATIO_B] = stoull(temp);
//       temp = strtok(NULL, ":");
//       set[DEF_RATIO_B] = stoull(temp);
//     }
//     else{
//       goto errorArgs;
//     }
//   }

//   for (int i = 0; i < 6; i++){
//     if (set[i] == 0)
//       goto errorArgs;
//   }

  return;

errorArgs:
  cerr << "Error bad args" << endl;
  exit(1);
}


int main(int argc, char **argv){

  // arg parsing 
  argParse(argc, argv);
  
  cerr << "\nAfter battle:" << endl;

  return 0;
}