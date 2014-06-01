
#ifndef TRACER_H
#define	TRACER_H

enum types {
    POINTER, SYMBOLIC, INT, UINT
};

unsigned long long int getArgValue(struct user_regs_struct regs, int n); 

#endif	/* TRACER_H */

