CFLAGS=-fPIC -O2 -g -Wall
.PHONY = all

all: libaeadpipe.so aeadpipe

libaeadpipe.so: libaeadpipe.o
	$(CC) -shared $^ -lcrypto -o $@

aeadpipe: aeadpipe.c libaeadpipe.so
