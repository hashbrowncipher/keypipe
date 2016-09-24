CFLAGS=-fPIC -O2 -g -Wall

libaeadpipe.so: libaeadpipe.o
	$(CC) -shared $^ -lcrypto -o $@
