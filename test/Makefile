CC = gcc
INCLUDE := -I../include 
LDFLAGS := -L../lib 
LDLIBS  := -ltlp
CFLAGS  := -g -Wall $(INCLUDE)

PROGNAME = test_dma_read test_dma_write \
	   test_msg_bar4 test_msg_msix test_msg_devid

all: $(PROGNAME)

.c.o:
	$(CC) $< -o $@

clean:
	rm -rf *.o
	rm -rf $(PROGNAME)
