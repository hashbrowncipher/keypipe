#ifndef _BSD_SOURCE
#define _BSD_SOURCE
#endif

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

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

#include "libaepipe.h"

//If you make this larger than 2^36 bytes, you will break GCM.
//You'll also be using a shit-ton of memory.
//There isn't really any good reason to increase this much.
#define MESSAGE_SIZE (1024 * 1024)

#define ERROR(x) { ret = x; goto out; }

static typedef enum {
    OK,
    CORRUPT_DATA,
    NO_MEMORY,
    OPENSSL_WEIRD,
    INPUT_ERROR,
    OUTPUT_ERROR,
} aepipe_error;

const char* aepipe_errorstrings[6] = {
    "OK",
    "Input data was corrupt",
    "Unable to allocate memory",
    "OpenSSL returned an unexpected error",
    "Unable to read input data",
    "Unable to write output data",
};

struct aepipe_context {
	uint64_t offset;
};

size_t aepipe_context_size() {
	return sizeof(struct aepipe_context);
}

void init_gcm_context(struct aepipe_context* ctx) {
	ctx->offset = 0;
}

static struct block_header {
    char tag[16];
    uint32_t clen;
}

int aepipe_decrypt(unsigned char key[KEYSIZE], FILE* in, FILE* out) {
	unsigned char iv[12] = {0};

	int ret = CORRUPT_DATA;
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

	err = fread(&counter, sizeof(counter), 1, in);
	if(err != 1) {
		ERROR(INPUT_ERROR);
	}

	struct block_header hdr;
	do {
		err = fread(&hdr, sizeof(struct block_header), 1, in);
		if(err != 1) {
			ERROR(INPUT_ERROR);
		}

		hdr.clen = ntohl(hdr.clen);
		if(hdr.clen > MESSAGE_SIZE) {
			ERROR(CORRUPT_DATA);
		}

		if(clen != 0) {
			err = fread(ciphertext, hdr.clen, 1, in);
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
		err = EVP_DecryptUpdate(&ctx, plaintext, &plen, ciphertext, (int) hdr.clen);
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
			ret = OK;
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

int aepipe_encrypt(unsigned char key[KEYSIZE], struct gcm_context * aead_ctx, FILE *in, FILE *out) {
	unsigned char iv[12] = {0};
	char tag[16];

	int ret = CORRUPT_DATA;
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

	uint64_t counter_n = htobe64(counter);
	fwrite(&counter_n, sizeof(counter_n), 1, out);

	int32_t plen;
	while(true) {
		plen = fread(plaintext, 1, MESSAGE_SIZE, in);
		if(plen < 0) {
			ERROR(INPUT_ERROR);
		}

		counter_n = htobe64(counter);
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
			fprintf(stderr, "%d\n", err);
			ERROR(OUTPUT_ERROR);
		}

		err = fwrite(&plen_n, sizeof(plen), 1, out);
		if(err != 1) {
			fprintf(stderr, "%d\n", err);
			ERROR(OUTPUT_ERROR);
		}

		if(plen < MESSAGE_SIZE) {
			ret = OK;
			break;
		}

		err = fwrite(ciphertext, plen, 1, out);
		if(err != 1) {
			ERROR(OUTPUT_ERROR);
		}
	}

out:
	EVP_CIPHER_CTX_cleanup(&ctx);
	aead_ctx->offset = counter;
	free(buffer);

	return ret;
}
