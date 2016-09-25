CC=gcc
CFLAGS=-fPIC -O2 -g -Wall
.PHONY = all

all: libaepipe.so aepipe

libaepipe.so: libaepipe.c
	$(CC) $(CFLAGS) -shared $^ -lcrypto -o $@

aepipe: aepipe.c libaepipe.so
	$(CC) $(CFLAGS) $^ -Wl,-rpath,. -o $@
