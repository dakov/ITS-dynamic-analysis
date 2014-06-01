/**
 * Example of ptrace(2) usage.
 *
 * Source:
 * http://stackoverflow.com/questions/7514837/why-this-ptrace-programe-always-saying-syscall-returned-38/7522990#7522990
 * Author: Matthew Slattery, 2011
 */

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

#include <sys/mman.h> // symbolic values

#ifndef __x86_64
#error Target architecture of the source code is x86_64
#endif

#include <stdbool.h>
#include <string.h>

#include "xml.h"
#include "pl.h"

typedef struct TConf {
    bool xml;
    char * output;
    char * command;
    int binArgc;
    char ** args;
    
    int offset; // index v argv programu, kde zacina argv spousteneho procesu
    bool valid;
} TConf;


pid_t child_pid;
TConf conf;

FILE * output;
 
unsigned long long int getArgValue(struct user_regs_struct regs, int n) {

    unsigned long long int ret;

    switch (n) {
	case 0: ret = regs.rdi;
	    break;
	case 1: ret = regs.rsi;
	    break;
	case 2: ret = regs.rdx;
	    break;
	case 3: ret = regs.r10;
	    break;
	case 4: ret = regs.r8;
	    break;
	case 5: ret = regs.r9;
	    break;
    }

    return ret;
}



bool isTraced(unsigned int call) {

    switch (call) {

	case __NR_munlockall:
	case __NR_brk:
	case __NR_munlock:
	case __NR_mlock:
	case __NR_munmap:
	case __NR_mlockall:
	case __NR_mmap:
	case __NR_mprotect:
	case __NR_msync: return true;

	default: return false;
    }

}

void argparse(int argc, char** argv, TConf * c) {

    if (argc < 2) {
	c->valid = false;
	return;
    }

    c->valid = true;

    bool isXml = (strcmp(argv[1], "-x") == 0);
    bool isPl = (strcmp(argv[1], "-p") == 0);

    if (isXml || isPl) {
	c->xml = isXml;
	c->output = argv[2];

	c->output = argv[2];

	c->command = argv[3];
	c->binArgc = argc - 4;

	if (c->binArgc != 0) {
	    c->args = (argv + 4);
	}
	
	c->offset = 3;

    } else {
	fprintf(stderr, "[WARNING] Implicitni metoda je tisk databaze prologu na standardni vystup\n");

	c->xml = false;
	c->output = NULL;
	c->command = argv[1];

	c->binArgc = argc - 2;

	if (c->binArgc != 0) {
	    c->args = (argv + 2);
	}
	
	c->offset = 1;
    }

}

void child(char *argv[], char *envp[]) {
    /* Request tracing by parent: */
    ptrace(PTRACE_TRACEME, 0, NULL, NULL);

    /* Stop before doing anything, giving parent a chance to catch the exec: */
    kill(getpid(), SIGSTOP);


    /* Now exec: */
    execve(argv[0], argv, envp);

    //    execl("/bin/ls", "ls", NULL);
}

struct syscall_status {
    unsigned long syscall;
    int status;
};

/// syscall_stack BEGIN
/**
 * system call stack -- each system call may be ptrace_stopped multiple times,
 * normally 2-times: before_enter, after_exit
 */
#define syscall_stack_capacity 100
struct syscall_status syscall_stack[syscall_stack_capacity];
int syscall_stack_top = 0;

struct syscall_status *top_syscall() {
    return &syscall_stack[syscall_stack_top];
}

void push_syscall(unsigned long syscall) {
    if (top_syscall()->syscall == syscall)
	top_syscall()->status += 1;
    else {
	syscall_stack_top++;
	assert(syscall_stack_top < syscall_stack_capacity);
	syscall_stack[syscall_stack_top].syscall = syscall;
	syscall_stack[syscall_stack_top].status = 1;
    }
}

void pop_syscall() {
    syscall_stack_top--;
    assert(syscall_stack_top >= 0);
}

/// syscall_stack END

void printSyscall( char* name,
	int argc, char** argNames, int* types,
	int rettype, struct user_regs_struct regs) {
    
    if (conf.xml) {
	printXmlSyscall(regs.orig_rax, child_pid, name, argc, argNames, types, rettype, regs);
    } else {
	printPlSyscall(regs.orig_rax, child_pid, name, argc, types, regs);
    }

}

void init_munlockall(struct user_regs_struct regs) {
    char name[] = "munlockall";

    int argc = 0;

    char *argNames[] = {};
    int types[] = {};

    int retType = INT;

    printSyscall( name, argc, argNames, types, retType, regs);
}

void init_brk(struct user_regs_struct regs) {

    char name[] = "brk";

    int argc = 1;

    char *argNames[] = {"addr"};
    int types[] = {POINTER};

    int retType = INT;

    printSyscall( name, argc, argNames, types, retType, regs);

}

void init_munlock(struct user_regs_struct regs) {
    char name[] = "munlock";

    int argc = 2;

    char *argNames[] = {"addr", "len"};
    int types[] = {POINTER, UINT};

    int retType = INT;

    printSyscall( name, argc, argNames, types, retType, regs);
}

void init_mlock(struct user_regs_struct regs) {
    char name[] = "mlock";

    int argc = 2;

    char *argNames[] = {"addr", "len"};
    int types[] = {POINTER, UINT};

    int retType = INT;

    printSyscall( name, argc, argNames, types, retType, regs);
}

void init_munmap(struct user_regs_struct regs) {
    char name[] = "munmap";

    int argc = 2;

    char *argNames[] = {"addr", "length"};
    int types[] = {POINTER, UINT};

    int retType = INT;

    printSyscall(name, argc, argNames, types, retType, regs);
}

void init_mmap(struct user_regs_struct regs) {
    char name[] = "mmap";

    int argc = 6;

    char *argNames[] = {"addr", "length", "prot", "flags", "fd", "offest"};
    int types[] = {POINTER, UINT, SYMBOLIC, SYMBOLIC, INT, UINT};

    int retType = POINTER;

    printSyscall(name, argc, argNames, types, retType, regs);
}

void init_mlockall(struct user_regs_struct regs) {
    char name[] = "mlockall";

    int argc = 1;

    char *argNames[] = {"flags"};
    int types[] = {SYMBOLIC};

    int retType = INT;

    printSyscall(name, argc, argNames, types, retType, regs);
}

void init_mprotect(struct user_regs_struct regs) {
    char name[] = "mprotect";

    int argc = 3;

    char *argNames[] = {"addr", "len", "print"};
    int types[] = {POINTER, UINT, SYMBOLIC};

    int retType = INT;

    printSyscall(name, argc, argNames, types, retType, regs);
}

void init_msync(struct user_regs_struct regs) {
    char name[] = "msync";

    int argc = 3;

    char *argNames[] = {"addr", "length", "flags"};
    int types[] = {POINTER, UINT, SYMBOLIC};

    int retType = INT;

    printSyscall(name, argc, argNames, types, retType, regs);
}

void handleSyscall(struct user_regs_struct regs) {

    long syscall = regs.orig_rax;

    push_syscall(syscall);
    // report only after exitting the call
    if (top_syscall()->status == 2) {
	// parameters, cf.:
	// http://www.x86-64.org/documentation/abi.pdf Section A.2.1


	switch (syscall) {

	    case __NR_munlockall: init_munlockall(regs);
		break;

	    case __NR_brk: init_brk(regs);
		break;

	    case __NR_munlock: init_munlock(regs);
		break;

	    case __NR_mlock: init_mlock(regs);
		break;

	    case __NR_munmap: init_munmap(regs);
		break;

	    case __NR_mlockall:init_mlockall(regs);
		break;

	    case __NR_mmap: init_mmap(regs);
		break;

	    case __NR_mprotect: init_mprotect(regs);
		break;

	    case __NR_msync: init_msync(regs);
		break;
	}

	pop_syscall();
    }

}

void parent() {
    int status;

    if (conf.xml) {
	
	printToplevelOpen();
	printProcessTag(conf.command, conf.binArgc, conf.args);

	printTraceOpen();
    } else {
	printPlHeader(conf.command, conf.binArgc, conf.args);
    }

    while (1) {
	/* Wait for child status to change: */
	wait(&status);

	if (WIFEXITED(status)) {
	    //exit(0);
	    break;
	}
	if (WIFSIGNALED(status)) {
	    //exit(0);
	    break;
	}
	if (!WIFSTOPPED(status)) {
	    //exit(0);
	    break;
	}
	if (WSTOPSIG(status) == SIGTRAP) {
	    /* Note that there are *three* reasons why the child might stop
	     * with SIGTRAP:
	     *  1) syscall entry
	     *  2) syscall exit
	     *  3) child calls exec
	     */

	    struct user_regs_struct regs;
	    ptrace(PTRACE_GETREGS, child_pid, 0, &regs);

	    long syscall = regs.orig_rax;

	    if (isTraced(syscall)) {
		handleSyscall(regs);
	    } 


	} else {
	    // printf("Child stopped due to signal %d\n", WSTOPSIG(status));
	    //printf("|     N/A | Signal %2d        |\n", WSTOPSIG(status));
	}
	fflush(stdout);

	/* Resume child, requesting that it stops again on syscall enter/exit
	 * (in addition to any other reason why it might stop):
	 */
	ptrace(PTRACE_SYSCALL, child_pid, NULL, NULL);
    }

    if (conf.xml) {
	printTraceClose();
	printToplevelClose();
    } 

}

int main(int argc, char *argv[], char *envp[]) {


    argparse(argc, argv, &conf);

    if (!conf.valid) {
	fprintf(stderr, "Usage:\n  tracer [-x trace.xml | -p trace.pl] /path/to/command [args]\n");
	return EXIT_FAILURE;
    }
    
    int offset = 3;
    
    if (conf.output == NULL) {
	output = stdout;
	offset = 1;
    } else {
	output = fopen(conf.output, "w");

	if (output == NULL) {
	    fprintf(stderr, "Unable to open output file!\n");
	    return 1;
	}
    }
    
	
	
    child_pid = fork();

    if (child_pid == 0)
	child(&argv[offset], envp); //samostatne polozky pro jmeno a char** args, tzn. nzev bin je (args-1)
    else
	parent();
    
    if (output != stdout)
	fclose(output);
    
    return 0;
}