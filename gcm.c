#define _BSD_SOURCE
#define _GNU_SOURCE

#include <arpa/inet.h>
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

//If you make this larger than 2^36 bytes, you will break GCM.
//You'll also be using a shit-ton of memory.
//There isn't really any good reason to increase this much.
#define MESSAGE_SIZE (1024 * 1024)

#define KEYSIZE 16

#define handle_error(message) { perror((message)); exit(EXIT_FAILURE); }


int do_decrypt(unsigned char key[KEYSIZE]) {
	unsigned char iv[12] = {0};
	char tag[16];

	void * plaintext = malloc(MESSAGE_SIZE);
	void * ciphertext = malloc(MESSAGE_SIZE);

	int rc;



	EVP_CIPHER_CTX *ctx = NULL;
	uint32_t clen;
	uint64_t counter = 0;
	do {
		rc = fread(tag, sizeof(tag), 1, stdin);
		if(rc != 1) {
                        fprintf(stderr, "Could not read tag for block %lu\n", counter);
                        exit(4);
		}

		rc = fread(&clen, sizeof(clen), 1, stdin);
		if(rc != 1) {
			fprintf(stderr, "Could not read block length for block %lu\n", counter);
			exit(4);
		}
		clen = ntohl(clen);

		if(clen > MESSAGE_SIZE) {
			fprintf(stderr, "Header for block %lu specifies illegal size\n", counter);
			exit(4);
		}

		if(clen != 0) {
			rc = fread(ciphertext, clen, 1, stdin);
			if(rc != 1) {
				fprintf(stderr, "Could not read ciphertext from block %lu\n", counter);
				exit(4);
			}
		}

		ctx = EVP_CIPHER_CTX_new();
		rc = EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);

		uint64_t counter_n = htobe64(counter);
		memcpy(iv + 4, &counter_n, 8);

		rc = EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv);

		int plen;
		rc = EVP_DecryptUpdate(ctx, plaintext, &plen, ciphertext, (int) clen);

		rc = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, sizeof(tag), tag);

		void * unused_buf = {0};
		int32_t unused_len;
		rc = EVP_DecryptFinal_ex(ctx, unused_buf, &unused_len);

                EVP_CIPHER_CTX_free(ctx);

                if(rc > 0) {
                        write(STDOUT_FILENO, plaintext, plen);
                } else {
                        fprintf(stderr, "Read corrupted block %lu\n", counter);
                        exit(4);
                }

		counter++;

	} while(clen != 0);

	return 0;
}

int do_encrypt(unsigned char key[KEYSIZE]) {
	unsigned char iv[12] = {0};
	char tag[16];

	void * plaintext = malloc(MESSAGE_SIZE);
	void * ciphertext = malloc(MESSAGE_SIZE);

	EVP_CIPHER_CTX *ctx = NULL;

	int32_t plen;
	uint64_t counter = 0;
	do {
		plen = read(STDIN_FILENO, plaintext, MESSAGE_SIZE);
		if(plen < 0) {
			handle_error("Error reading input");
		}

		uint64_t counter_n = htobe64(counter);
		memcpy(iv + 4, &counter_n, 8);

		ctx = EVP_CIPHER_CTX_new();
		int rc;
		rc = EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
		if(rc != 1) {
			//TODO: error handling
		}

		rc = EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);

		int clen;
		rc = EVP_EncryptUpdate(ctx, ciphertext, &clen, plaintext, plen);

		void * unused_buf = {0};
		int32_t unused_len;
		rc = EVP_EncryptFinal_ex(ctx, unused_buf, &unused_len);

		rc = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, sizeof(tag), tag);
		EVP_CIPHER_CTX_free(ctx);

		int plen_n = htonl(plen);

		rc = write(STDOUT_FILENO, tag, sizeof(tag));
		rc = write(STDOUT_FILENO, &plen_n, sizeof(plen_n));
		rc = write(STDOUT_FILENO, ciphertext, plen);

		counter++;
	} while(plen != 0);

	free(plaintext);
	free(ciphertext);

	return 0;
}

void usage(int argc, char* argv[]) {
	fprintf(stderr, "Usage: %s [-d] <keyfile>\n", argv[0]);
}

int main(int argc, char* argv[]) {
	int decrypt_flag = 0;
	int c;
	while((c = getopt(argc, argv, "d")) != -1) {
		switch(c) {
		case 'd':
			decrypt_flag = 1;
			break;
		}
	}

	if((argc - optind) < 1) {
		usage(argc, argv);
		exit(1);
	}

	FILE * keyfile = fopen(argv[optind], "r");
	if(keyfile == NULL) {
		handle_error("Could not open keyfile");
	}

	unsigned char key[KEYSIZE];

	int rc;
	rc = fread(key, KEYSIZE, 1, keyfile);
	if(rc != 1) {
		fprintf(stderr, "Could not read key material from file\n");
		exit(2);
	}
	rc = fclose(keyfile);

	rc = fcntl(STDIN_FILENO, F_SETPIPE_SZ, MESSAGE_SIZE);
	if(rc == -1 && errno != EBADF) {
		handle_error("Couldn't set pipe buffer size");
	}

	if(decrypt_flag) {
		do_decrypt(key);
	} else {
		do_encrypt(key);
	}
}
