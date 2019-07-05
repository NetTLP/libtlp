CC = gcc
INCLUDE := -I../include 
LDFLAGS := -L../lib 
LDLIBS  := -ltlp
CFLAGS  := -g -Wall $(INCLUDE)

PROGNAME = pmem

all: $(PROGNAME)

.c.o:
	$(CC) $< -o $@

clean:
	rm -rf *.o
	rm -rf $(PROGNAME)
