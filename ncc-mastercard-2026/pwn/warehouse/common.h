#include <stdio.h>
#include <stdlib.h>

#ifndef __NCCCTF_2025_PWN__
#define __NCCCTF_2025_PWN__ 1






#ifndef DEBUG
#define DEBUG 1
#endif


#define CODE_OK 0 
#define CODE_CHALLENGE_FAILURE                                                 \
  1 
    
#define CODE_MALLOC_FAIL 2 
#define CODE_OTHER                                                             \
  3 
#define CODE_NO_FLAG 4 


#define FLAG "./flag.txt"
#define FLAG_SIZE 64


void __attribute__((noreturn)) malloc_fail() {
  perror("Malloc failure, contact the CTF organizers.");
  exit(CODE_MALLOC_FAIL);
}


void __attribute__((constructor, noinline)) ignore_me() {
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stdin, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);
}

#endif /** __NCCCTF_2025_PWN__ */
