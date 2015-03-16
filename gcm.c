#define _BSD_SOURCE
#define _GNU_SOURCE

#include <arpa/inet.h>
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <openssl/err.h>
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
#define handle_openssl_error() { ERR_print_errors_fp(stderr); exit(8); }


int do_decrypt(unsigned char key[KEYSIZE]) {
	unsigned char iv[12] = {0};
	char tag[16];

	void * plaintext = malloc(MESSAGE_SIZE);
	void * ciphertext = malloc(MESSAGE_SIZE);

	int rc;

	EVP_CIPHER_CTX ctx;
	EVP_CIPHER_CTX_init(&ctx);
	rc = EVP_DecryptInit_ex(&ctx, EVP_aes_128_gcm(), NULL, key, NULL);
	if(rc != 1) {
		fprintf(stderr, "Failed to initialize decryption\n");
		handle_openssl_error();
	}

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

		uint64_t counter_n = htobe64(counter);
		memcpy(iv + 4, &counter_n, 8);

		rc = EVP_DecryptInit_ex(&ctx, NULL, NULL, NULL, iv);
		if(rc != 1) {
			fprintf(stderr, "Failed to set IV for block %lu\n", counter);
			handle_openssl_error();
		}

		int plen;
		rc = EVP_DecryptUpdate(&ctx, plaintext, &plen, ciphertext, (int) clen);
		if(rc != 1) {
			/* How the hell would this ever happen? */
			fprintf(stderr, "Failed to decrypt block %lu\n", counter);
			handle_openssl_error();
		}

		rc = EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_GCM_SET_TAG, sizeof(tag), tag);
		if(rc != 1) {
			fprintf(stderr, "Failed to set GCM tag in block %lu\n", counter);
			handle_openssl_error();
		}

		void * unused_buf = {0};
		int32_t unused_len;
		rc = EVP_DecryptFinal_ex(&ctx, unused_buf, &unused_len);
                if(rc == 1) {
                        write(STDOUT_FILENO, plaintext, plen);
                } else {
                        fprintf(stderr, "Read corrupted block %lu\n", counter);
			handle_openssl_error();
                }

		counter++;
	} while(clen != 0);

	EVP_CIPHER_CTX_cleanup(&ctx);

	return 0;
}

int do_encrypt(unsigned char key[KEYSIZE]) {
	unsigned char iv[12] = {0};
	char tag[16];

	void * plaintext = malloc(MESSAGE_SIZE);
	void * ciphertext = malloc(MESSAGE_SIZE);

	int rc;

	EVP_CIPHER_CTX ctx;
	EVP_CIPHER_CTX_init(&ctx);

	rc = EVP_EncryptInit_ex(&ctx, EVP_aes_128_gcm(), NULL, key, NULL);
	if(rc != 1) {
		fprintf(stderr, "Failed to initialize encryption\n");
		handle_openssl_error();
	}

	int32_t plen;
	uint64_t counter = 0;
	do {
		plen = read(STDIN_FILENO, plaintext, MESSAGE_SIZE);
		if(plen < 0) {
			handle_error("Error reading input");
		}

		uint64_t counter_n = htobe64(counter);
		memcpy(iv + 4, &counter_n, 8);


		rc = EVP_EncryptInit_ex(&ctx, NULL, NULL, NULL, iv);
		if(rc != 1) {
			fprintf(stderr, "Failed to set IV for block %lu\n", counter);
			handle_openssl_error();
		}

		int clen;
		rc = EVP_EncryptUpdate(&ctx, ciphertext, &clen, plaintext, plen);
		if(rc != 1) {
			fprintf(stderr, "Failed to encrypt in block %lu\n", counter);
			handle_openssl_error();
		}

		void * unused_buf = {0};
		int32_t unused_len;
		rc = EVP_EncryptFinal_ex(&ctx, unused_buf, &unused_len);
		if(rc != 1) {
			fprintf(stderr, "Failed to finalize for block %lu\n", counter);
			handle_openssl_error();
		}


		rc = EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_GCM_GET_TAG, sizeof(tag), tag);
		if(rc != 1) {
			fprintf(stderr, "Failed to get EVP tag for block %lu\n", counter);
			handle_openssl_error();
		}

		int plen_n = htonl(plen);

		rc = write(STDOUT_FILENO, tag, sizeof(tag));
		rc = write(STDOUT_FILENO, &plen_n, sizeof(plen_n));
		rc = write(STDOUT_FILENO, ciphertext, plen);

		counter++;
	} while(plen != 0);

	EVP_CIPHER_CTX_cleanup(&ctx);
	free(plaintext);
	free(ciphertext);

	return 0;
}

void do_usage(int argc, char* argv[]) {
	fprintf(stderr, "Usage: %s [-d] <keyfile>\n", argv[0]);
	fprintf(stderr, "\n");
	fprintf(stderr, "Always check the return code!\n");
	fprintf(stderr, "Nonzero means corrupted or partial data.\n");
	exit(1);
}

int main(int argc, char* argv[]) {
	int decrypt_flag = 0;
	int c;
	while((c = getopt(argc, argv, "d")) != -1) {
		switch(c) {
		case 'd':
			decrypt_flag = 1;
			break;
		default:
			do_usage(argc, argv);
			break;
		}
	}

	if((argc - optind) < 1) {
		do_usage(argc, argv);
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
