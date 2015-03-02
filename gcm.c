#define _BSD_SOURCE
#include <arpa/inet.h>
#include <endian.h>
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
	void * ciphertext = malloc(MESSAGE_SIZE);
	uint32_t block_len;
	char tag[16];

	int rc;

	EVP_CIPHER_CTX *ctx = NULL;
	do {
		rc = fread(block_len, sizeof(block_len), 1, stdin);
		block_len = ntohl(block_len);

		rc = fread(tag, sizeof(tag), 1, stdin);
		
		if(block_len > MESSAGE_SIZE) {
			fprintf(stderr, "Header for block %d specifies illegal size\n", counter);
			exit(4);
		}

		if(block_len == 0) {
			ret = getchar();
			if(feof(stdin)) {
				break;
			}

			fprintf(stderr, "Block %d indicates zero length, but there are more bytes to read\n", seq);
			exit(4);
		}

		fread(ciphertext, block_len, 1, stdin);
	} while(block_len != 0);

	return 0;
}

int do_encrypt(unsigned char key[KEYSIZE]) {
	unsigned char iv[12] = {0};
	char tag[16];

	void * plaintext = malloc(MESSAGE_SIZE);
	void * ciphertext = malloc(MESSAGE_SIZE);

	EVP_CIPHER_CTX *ctx = NULL;

	void * unused_buf = {0};
	int32_t unused_len;

	int32_t plen;
	uint32_t clen;
	uint64_t counter = 0;
	do {
		counter++;

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

		rc = EVP_EncryptUpdate(ctx, ciphertext, &clen, plaintext, plen);
		rc = EVP_EncryptFinal_ex(ctx, unused_buf, &unused_len);
		rc = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, sizeof(tag), tag);
		EVP_CIPHER_CTX_free(ctx);

		rc = write(STDOUT_FILENO, tag, sizeof(tag));
		rc = write(STDOUT_FILENO, &plen_n, sizeof(plen_n));
		rc = write(STDOUT_FILENO, ciphertext, clen);
	} while(plen != 0);

	free(plaintext);
	free(ciphertext);

	return 0;
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

	if(decrypt_flag) {
		do_decrypt(key);
	} else {
		do_encrypt(key);
	}
}
