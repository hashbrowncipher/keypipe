gcm: gcm.c
	gcc -g -Wall -Werror -march=native -mtune=native -std=gnu99 -o gcm gcm.c -lcrypto
