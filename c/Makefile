CC=gcc
CFLAGS=-O2 -g -Wall -Wconversion -Wextra
.PHONY = all clean
TARGETS=libaepipe.so aepipe

all: $(TARGETS)

clean:
	rm -f $(TARGETS)

libaepipe.so: libaepipe.c
	$(CC) $(CFLAGS) -fPIC -shared $^ -lcrypto -o $@

aepipe: aepipe.c libaepipe.so
	$(CC) $(CFLAGS) $^ -Wl,-rpath,. -o $@
