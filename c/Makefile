CFLAGS=-fPIC -O2 -g -Wall
.PHONY = all

all: libaepipe.so aepipe

libaepipe.so: libaepipe.o
	$(CC) -shared $^ -lcrypto -o $@

aepipe: aepipe.c libaepipe.so
	gcc $^ -Wl,-rpath,. -o $@
