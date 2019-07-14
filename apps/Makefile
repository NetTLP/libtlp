CC = gcc
INCLUDE := -I../include 
LDFLAGS := -L../lib 
LDLIBS  := -ltlp
CFLAGS  := -g -Wall $(INCLUDE)

PROGNAME = dma_read dma_write pmem process-list pgd-walk

all: $(PROGNAME)

.c.o: util.h
	$(CC) $< -o $@

clean:
	rm -rf *.o
	rm -rf $(PROGNAME)
