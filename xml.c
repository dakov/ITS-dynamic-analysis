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

#include "xml.h"

extern FILE * output;

void printValue(int type, unsigned long long int val) {

    void * ptr;
    int intval;

    switch (type) {
	case POINTER:
	    ptr = (void *) val;

	    if (ptr == NULL) {
		fprintf(output,"NULL");
	    } else {
		fprintf(output,"%p", ptr);
	    }
	    break;
	case SYMBOLIC:
	case INT:
	    intval = (int) val;
	    fprintf(output,"%d", intval);
	    break;

	case UINT:
	    intval = (int) val;
	    fprintf(output,"%u", intval);
	    break;
    }

}

void printToplevelOpen() {
    fprintf(output,"<syscalltrace>\n");
}

void printToplevelClose() {
    fprintf(output,"</syscalltrace>\n");
}

void printTraceOpen() {
    fprintf(output,"\t<trace>\n");
}

void printTraceClose() {
    fprintf(output,"\t</trace>\n");
}

int leftMostVal(int val) {
    int counter = 0;

    while (val > 1) {
	counter++;
	val = val >> 1;
    }

    val = val << counter;

    return val;
}

void printDelim(int highest, int val) {

    if (val == highest)
	return;

    fprintf(output,"|");
}

void printMmapProtSymbolic(unsigned long long int val) {

    int highest = leftMostVal(val);

    if (val == PROT_NONE) {
	fprintf(output,"PROT_NONE");
	return;

    }
    if (val & PROT_READ) {
	fprintf(output,"PROT_READ");

	printDelim(highest, PROT_READ);

    }
    if (val & PROT_WRITE) {
	fprintf(output,"PROT_WRITE");

	printDelim(highest, PROT_WRITE);

    }
    if (val & PROT_EXEC) {
	fprintf(output,"PROT_EXEC");

	printDelim(highest, PROT_EXEC);
    }

    if (val & PROT_GROWSDOWN) {
	fprintf(output,"PROT_GROWSDOWN");

	printDelim(highest, PROT_GROWSDOWN);
    }

    if (val & PROT_GROWSUP) {
	fprintf(output,"PROT_GROWSUP");

	printDelim(highest, PROT_GROWSUP);
    }

}

void printMmapFlagsSymbolic(unsigned long long int val) {

    int highest = leftMostVal(val);

    if (val == MAP_FILE) {
	fprintf(output,"MAP_SHARED");
	return;
    }
    /* Sharing types (must choose one and only one of these).  */
    if (val & MAP_SHARED) {
	fprintf(output,"MAP_SHARED");
	printDelim(highest, MAP_SHARED);
    } else if (val & MAP_PRIVATE) {
	fprintf(output,"MAP_PRIVATE");
	printDelim(highest, MAP_PRIVATE);
    } else if (val & MAP_TYPE) {
	fprintf(output,"MAP_TYPE");
	printDelim(highest, MAP_TYPE);
    }

    /* Other flags.  */
    if (val & MAP_FIXED) {
	fprintf(output,"MAP_FIXED");
	printDelim(highest, MAP_FIXED);
    }

    if (val & MAP_ANON || val & MAP_ANONYMOUS) {
	fprintf(output,"MAP_ANONYMOUS");
	printDelim(highest, MAP_ANONYMOUS);
    }

    if (val & MAP_32BIT) {
	fprintf(output,"MAP_32BIT");
	printDelim(highest, MAP_32BIT);
    }


    /* These are Linux-specific.  */

    if (val & MAP_GROWSDOWN) {
	fprintf(output,"MAP_GROWSDOWN");
	printDelim(highest, MAP_GROWSDOWN);
    }

    if (val & MAP_DENYWRITE) {
	fprintf(output,"MAP_DENYWRITE");
	printDelim(highest, MAP_DENYWRITE);
    }
    if (val & MAP_EXECUTABLE) {
	fprintf(output,"MAP_EXECUTABLE");
	printDelim(highest, MAP_EXECUTABLE);
    }

    if (val & MAP_LOCKED) {
	fprintf(output,"MAP_LOCKED");
	printDelim(highest, MAP_LOCKED);
    }

    if (val & MAP_NORESERVE) {
	fprintf(output,"MAP_NORESERVE");
	printDelim(highest, MAP_NORESERVE);
    }
    if (val & MAP_POPULATE) {
	fprintf(output,"MAP_POPULATE");
	printDelim(highest, MAP_POPULATE);
    }
    if (val & MAP_NONBLOCK) {
	fprintf(output,"MAP_NONBLOCK");
	printDelim(highest, MAP_NONBLOCK);
    }

    if (val & MAP_STACK) {
	fprintf(output,"MAP_STACK");
	printDelim(highest, MAP_STACK);
    }

    if (val & MAP_HUGETLB) {
	fprintf(output,"MAP_HUGETLB");
	printDelim(highest, MAP_HUGETLB);
    }

}

void printMlockallFlagsSymbolic(unsigned long long int val) {
    
    if (val == 3) { //MCL_FUTURE|MCL_CURRENT
	fprintf(output,"MCL_FUTURE|MCL_CURRENT");
    } else if (val == 2) { 
	fprintf(output,"MCL_FUTURE");
    } else {
	fprintf(output,"MCL_CURRENT");
    }

}

void printMsyncFlagsSymbolic(unsigned long long int val) {
    if (val & MS_ASYNC) {
	fprintf(output,"MS_ASYNC");
	if (val & MS_INVALIDATE) {
	    fprintf(output,"|MS_INVALIDATE");
	}

    } else if (val & MS_SYNC) {
	fprintf(output,"MS_SYNC");
	if (val & MS_INVALIDATE) {
	    fprintf(output,"|MS_INVALIDATE");
	}
    }
}

void printMProtectProtSymbolic(unsigned long long int val) {


    int highest = leftMostVal(val);

    if (val == PROT_NONE) {
	fprintf(output,"PROT_NONE");
	return;
    }

    if (val & PROT_READ) {
	fprintf(output,"PROT_READ");
	printDelim(highest, PROT_READ);
    }

    if (val & PROT_WRITE) {
	fprintf(output,"PROT_WRITE");
	printDelim(highest, PROT_WRITE);
    }
    
    if (val & PROT_EXEC) {
	fprintf(output,"PROT_EXEC");
	printDelim(highest, PROT_EXEC);
    }


}

void printSymbolic(int syscall, char * arg, unsigned long long int val) {

    fprintf(output,"\t\t\t\t<symbolic>");

    switch (syscall) {


	case __NR_mmap:

	    if (strcmp(arg, "prot") == 0) { // mmap: prot
		printMmapProtSymbolic(val);
	    } else if (strcmp(arg, "flags") == 0) {
		printMmapFlagsSymbolic(val);
	    }

	    break;

	case __NR_msync:
	    printMsyncFlagsSymbolic(val);
	    break;
	case __NR_mprotect:
	    printMProtectProtSymbolic(val);
	    break;
	case __NR_mlockall:
	    printMlockallFlagsSymbolic(val);
	    break;

    }
    fprintf(output,"</symbolic>\n");
}

void printXmlSyscall(int id, int pid, char* name,
	int argc, char** argNames, int* types,
	int rettype, struct user_regs_struct regs) {

    fprintf(output,"\t\t<syscall id=\"%d\" pid=\"%d\">\n", id, pid);

    fprintf(output,"\t\t\t<name>%s</name>\n", name);

    for (int i = 0; i < argc; ++i) {
	fprintf(output,"\t\t\t<arg name=\"%s\">\n", argNames[i]);

	fprintf(output,"\t\t\t\t<value>");
	printValue(types[i], getArgValue(regs, i));

	fprintf(output,"</value>\n");

	if (types[i] == SYMBOLIC) {
	    printSymbolic(id, argNames[i], getArgValue(regs, i));
	}

	fprintf(output,"\t\t\t</arg>\n");
    }

    fprintf(output,"\t\t\t<retcode>");
    printValue(rettype, regs.rax);
    fprintf(output,"</retcode>\n");

    fprintf(output,"\t\t</syscall>\n");

}

void printProcessTag(char * proc, int argc, char **argv) {
    fprintf(output,"\t<process>\n");

    fprintf(output,"\t\t<binary>%s</binary>\n", proc);

    if (argc > 0) {

	fprintf(output,"\t\t<arguments>\n");

	for (int i = 0; i < argc; ++i) {
	    fprintf(output,"\t\t\t<arg>%s</arg>\n", argv[i]);
	}

	fprintf(output,"\t\t</arguments>\n");
    }


    fprintf(output,"\t</process>\n");
}