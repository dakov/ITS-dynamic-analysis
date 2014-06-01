#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/user.h> // struct user_regs_struct
#include <sys/syscall.h> // __NR_* constants
#include <assert.h>
#include <ctype.h>
#include <fcntl.h>

#include <sys/mman.h> // mmap(prot) flags

#ifndef __x86_64
#error Target architecture of the source code is x86_64
#endif

#include <stdbool.h>
#include <string.h>

#include "pl.h"

int counter = 1;

extern FILE * output;

void printPlValue(int type, unsigned long long int val) {

    int intval;

    switch (type) {
	case POINTER:
	    fprintf(output, "%llu", val);
	    break;
	case SYMBOLIC:
	case INT:
	    intval = (int) val;  
	    fprintf(output, "%d", intval);
	    break;

	case UINT:
	    intval = (int) val;
	    fprintf(output, "%u", intval);
	    break;
    }

}

void printPlSyscall(int id, int pid, char* name,
	int argc,  int* types, struct user_regs_struct regs) {
    
    int maxArg = 6;

    fprintf(output, "syscall(%d, %d, %d, '%s' ", counter++, id, pid, name );
    
    for (int i = 0; i< maxArg; ++i) { //max 6 argumentů
	
	if (i < argc) {
	    printPlValue(types[i], getArgValue(regs, i));
	} else {
	    fprintf(output, "0");
	}
	
	if (i != maxArg-1) {
	    fprintf(output, ", ");
	}
    }
    
    fprintf(output, ").\n");

}

void printPlHeader(char * proc, int argc, char **argv) {
    fprintf(output, "process('%s'", proc);

    if (argc > 0) {

	fprintf(output, ", '");

	for (int i = 0; i < argc; ++i) {
	    fprintf(output, "%s", argv[i]);
	    
	    if (i != argc-1) {
		fprintf(output, " ");
	    }
	}

	fprintf(output, "').");
    } else {
	fprintf(output, ").");
    }
    
    fprintf(output, "\n");

}