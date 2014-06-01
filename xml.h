
#ifndef XML_H_
#define XML_H_

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
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

#include <sys/user.h>

#include "tracer.h"

void setXmlOutputFile(FILE * f);

void printValue(int type, unsigned long long int val);
 
void printToplevelOpen();

void printToplevelClose();

void printTraceOpen();

void printTraceClose();

void printXmlSyscall(int id, int pid, char* name,
	int argc, char** argNames, int* types,
	int rettype, struct user_regs_struct regs);

void printProcessTag(char * proc, int argc, char **argv);





#endif /* XML_H_ */