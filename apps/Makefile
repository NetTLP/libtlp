CC = gcc
INCLUDE := -I../include 
LDFLAGS := -L../lib 
LDLIBS  := -ltlp -lpthread
CFLAGS  := -g -Wall $(INCLUDE)

PROGNAME = dma_read dma_write psmem process-list pgd-walk codedump \
	   tlpperf

all: $(PROGNAME)

.c.o: util.h
	$(CC) $< -o $@

clean:
	rm -rf *.o
	rm -rf $(PROGNAME)
