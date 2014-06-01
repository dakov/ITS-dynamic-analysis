
#ifndef PL_H_
#define PL_H_

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

void printPlValue(int type, unsigned long long int val);

void printPlSyscall(int id, int pid, char* name,
	int argc, int* types, struct user_regs_struct regs);

void printPlHeader(char * proc, int argc, char **argv);





#endif /* PL_H_ */