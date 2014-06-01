# example:
# 	make
# 	./tracer /bin/ls -l

#CFLAGS=-std=gnu99 -Wall -Wextra

#tracer: tracer.o xml.o
#clean:
#	-rm tracer.o tracer


CC=gcc
CFLAGS=-std=gnu99 -Wall -Wextra

CDEST=tracer

# mezerou oddeleny seznam objektovych souboru, ten je nasledne pouzit
# pro rozgenerovani zavislosti pro kazdou jednu polozku.

OBJFILES=tracer.o xml.o pl.o


# vytvori "relativni" promennou pro kazdy .o | .c | .h soubor
vpath %.c src
vpath %.h head
vpath %.o obj

all: $(OBJFILES)
	$(CC) $(CFLAGS) $(OBJFILES) -o $(CDEST)
   
%.o : %.c
	$(CC) $(CFLAGS) -c $< -o $@ 

clear:
	rm -f *.o tracer


