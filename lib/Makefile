CC = gcc
INCLUDE	:= -I./ -I../include
LDFLAGS	:=
LDLIBS	:=
CFLAGS	:= -g -Wall $(INCLUDE)

OBJECTS := libtlp.o
PROGNAME = libtlp.a

all: $(PROGNAME)

.c.o:
	$(CC) $(INCLUDE) -c $<

libtlp.a: $(OBJECTS)
	ar rcs libtlp.a $(OBJECTS)


clean:
	rm -rf *.o
	rm -rf $(PROGNAME)
