gcmpipe: gcm.c
	gcc -std=gnu99 -Wall -Werror -O3 -o $@ $< -lcrypto

install: gcmpipe
	install gcmpipe $(DESTDIR)/usr/bin/gcmpipe
