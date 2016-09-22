#define _BSD_SOURCE
#define _GNU_SOURCE

#include <arpa/inet.h>
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "libaeadpipe.h"

//If you make this larger than 2^36 bytes, you will break GCM.
//You'll also be using a shit-ton of memory.
//There isn't really any good reason to increase this much.
#define MESSAGE_SIZE (1024 * 1024)

#define ERROR(x) { ret = x; goto out; }

#define NO_MEMORY     1
#define OPENSSL_WEIRD 2
#define INPUT_ERROR   3
#define CORRUPT_DATA  4
#define OUTPUT_ERROR  5

struct gcm_context {
	uint64_t offset;
};

size_t gcm_context_size(void) {
	return sizeof(struct gcm_context);
}

void init_gcm_context(struct gcm_context* ctx) {
	ctx->offset = 0;
}

int aeadpipe_decrypt(unsigned char key[KEYSIZE], FILE *in, FILE *out) {
	unsigned char iv[12] = {0};
	char tag[16];

	int ret = 0;
	uint64_t counter = 0;

	void * buffer = malloc(2 * MESSAGE_SIZE);
	if(buffer == NULL) {
		ERROR(NO_MEMORY);
	}
	void * plaintext = buffer;
	void * ciphertext = buffer + MESSAGE_SIZE;

	int err;

	EVP_CIPHER_CTX ctx;
	EVP_CIPHER_CTX_init(&ctx);
	err = EVP_DecryptInit_ex(&ctx, EVP_aes_256_gcm(), NULL, key, NULL);
	if(err != 1) {
		ERROR(OPENSSL_WEIRD)
	}

	err = fread(&counter, sizeof(counter), 1, stdin);
	if(err != 1) {
		ERROR(INPUT_ERROR);
	}

	uint32_t clen;
	do {
		err = fread(tag, sizeof(tag), 1, stdin);
		if(err != 1) {
			ERROR(INPUT_ERROR);
		}

		err = fread(&clen, sizeof(clen), 1, stdin);
		if(err != 1) {
			ERROR(INPUT_ERROR);
		}

		clen = ntohl(clen);
		if(clen > MESSAGE_SIZE) {
			ERROR(CORRUPT_DATA);
		}

		if(clen != 0) {
			err = fread(ciphertext, clen, 1, stdin);
			if(err != 1) {
				ERROR(INPUT_ERROR);
			}
		}

		uint64_t counter_n = htobe64(counter);
		memcpy(iv + 4, &counter_n, 8);

		err = EVP_DecryptInit_ex(&ctx, NULL, NULL, NULL, iv);
		if(err != 1) {
			ERROR(OPENSSL_WEIRD);
		}

		int plen;
		err = EVP_DecryptUpdate(&ctx, plaintext, &plen, ciphertext, (int) clen);
		if(err != 1) {
			/* How the hell would this ever happen? */
			ERROR(OPENSSL_WEIRD);
		}

		err = EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_GCM_SET_TAG, sizeof(tag), tag);
		if(err != 1) {
			ERROR(OPENSSL_WEIRD);
		}

		void * unused_buf = {0};
		int32_t unused_len;
		err = EVP_DecryptFinal_ex(&ctx, unused_buf, &unused_len);
		if(err != 1) {
			ERROR(CORRUPT_DATA);
		}

		counter++;

		if(plen == 0) {
			break;
		}

		err = fwrite(plaintext, plen, 1, out);
		if(err != 1) {
			ERROR(OUTPUT_ERROR);
		}
	} while(true);

out:
	EVP_CIPHER_CTX_cleanup(&ctx);
	
	free(buffer);
	return ret;
}

int aeadpipe_encrypt(unsigned char key[KEYSIZE], struct gcm_context * aead_ctx, FILE *in, FILE *out) {
	unsigned char iv[12] = {0};
	char tag[16];

	int ret = 0;
	uint64_t counter = aead_ctx->offset;

	void * buffer = malloc(2 * MESSAGE_SIZE);
	if(buffer == NULL) {
		ERROR(1);
	}
	void * plaintext = buffer;
	void * ciphertext = buffer + MESSAGE_SIZE;

	int err;

	EVP_CIPHER_CTX ctx;
	EVP_CIPHER_CTX_init(&ctx);

	err = EVP_EncryptInit_ex(&ctx, EVP_aes_256_gcm(), NULL, key, NULL);
	if(err != 1) {
		ERROR(2)
	}

	fwrite(&counter, sizeof(counter), 1, out);

	int32_t plen;
	do {
		plen = fread(plaintext, 1, MESSAGE_SIZE, in);
		if(plen < 0) {
			ERROR(INPUT_ERROR);
		}

		uint64_t counter_n = htobe64(counter);
		memcpy(iv + 4, &counter_n, 8);

		err = EVP_EncryptInit_ex(&ctx, NULL, NULL, NULL, iv);
		if(err != 1) {
			ERROR(OPENSSL_WEIRD);
		}

		int clen;
		err = EVP_EncryptUpdate(&ctx, ciphertext, &clen, plaintext, plen);
		if(err != 1) {
			ERROR(OPENSSL_WEIRD);
		}

		void * unused_buf = {0};
		int32_t unused_len;
		err = EVP_EncryptFinal_ex(&ctx, unused_buf, &unused_len);
		if(err != 1) {
			ERROR(OPENSSL_WEIRD);
		}

		err = EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_GCM_GET_TAG, sizeof(tag), tag);
		if(err != 1) {
			ERROR(OPENSSL_WEIRD);
		}

		int plen_n = htonl(plen);

		counter++;
		err = fwrite(tag, sizeof(tag), 1, out);
		if(err != 1) {
			ERROR(OUTPUT_ERROR);
		}

		err = fwrite(&plen_n, sizeof(plen), 1, out);
		if(err != 1) {
			ERROR(OUTPUT_ERROR);
		}

		err = fwrite(ciphertext, plen, 1, out);
		if(err != 1) {
			ERROR(OUTPUT_ERROR);
		}
	} while(plen != 0);

out:
	EVP_CIPHER_CTX_cleanup(&ctx);
	aead_ctx->offset = counter;
	free(buffer);
}
