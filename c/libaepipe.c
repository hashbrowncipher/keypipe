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

typedef enum {
	OK,
	CORRUPT_DATA,
	NO_MEMORY,
	OPENSSL_WEIRD,
	INPUT_ERROR,
	OUTPUT_ERROR,
	CONCURRENCY_ERROR,
} aepipe_error;

const char* aepipe_errorstrings[7] = {
	"OK",
	"Input data was corrupt",
	"Unable to allocate memory",
	"OpenSSL returned an unexpected error",
	"Unable to read input data",
	"Unable to write output data",
	"Improper concurrent access of an aepipe context",
};

struct aepipe_context {
	uint64_t offset;
	bool flag;
};

size_t aepipe_context_size() {
	return sizeof(struct aepipe_context);
}

void aepipe_init_context(struct aepipe_context* ctx) {
	ctx->offset = 0;
	__sync_lock_release(&ctx->flag);
}

struct block_state {
	unsigned char plaintext[MESSAGE_SIZE];
	char unused[4076];
	unsigned char tag[16];
	uint32_t len;
	unsigned char ciphertext[MESSAGE_SIZE];
};

struct iv_numeric {
	uint64_t unused;
	uint64_t counter;
};

#define HEADER_SIZE (sizeof(uint32_t) + sizeof(unsigned char[16]))
#define CHECK(err, x, y)  { if(x != y) { ERROR(err); } }

int aepipe_unseal(unsigned char key[KEYSIZE], FILE* in, FILE* out) {
	struct iv_numeric iv;
	iv.unused = 0;

	int ret = CORRUPT_DATA;
	uint64_t counter = 0;

	struct block_state * s = malloc(sizeof(struct block_state));
	if(s == NULL) {
		ERROR(NO_MEMORY);
	}

	int err;

	EVP_CIPHER_CTX ctx;
	EVP_CIPHER_CTX_init(&ctx);
	CHECK(OPENSSL_WEIRD, 1, EVP_DecryptInit_ex(&ctx, EVP_aes_256_gcm(), NULL, key, NULL));

	err = fread(&counter, sizeof(counter), 1, in);
	CHECK(INPUT_ERROR, 0, ferror(in));
	CHECK(CORRUPT_DATA, 1, err);

	while(true) {
		err = fread(s->tag, 20, 1, in);
		CHECK(INPUT_ERROR, 0, ferror(in));
		CHECK(CORRUPT_DATA, 1, err);

		uint32_t len = ntohl(s->len);
		if(len > MESSAGE_SIZE) {
			ERROR(CORRUPT_DATA);
		}

		if(len != 0) {
			err = fread(s->ciphertext, len, 1, in);
			CHECK(INPUT_ERROR, 0, ferror(in));
			CHECK(CORRUPT_DATA, 1, err);
		}

		iv.counter = htobe64(counter);
		counter++;
		CHECK(OPENSSL_WEIRD, 1, EVP_DecryptInit_ex(&ctx, NULL, NULL, NULL, (unsigned char *)&iv + 4));

		int plen;
		CHECK(OPENSSL_WEIRD, 1, EVP_DecryptUpdate(&ctx, s->plaintext, &plen, s->ciphertext, (int) len));
		CHECK(OPENSSL_WEIRD, 1, EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_GCM_SET_TAG, sizeof(s->tag), s->tag));

		void * unused_buf = {0};
		int32_t unused_len;
		CHECK(CORRUPT_DATA, 1, EVP_DecryptFinal_ex(&ctx, unused_buf, &unused_len));

		if(plen == 0) {
			ret = OK;
			break;
		}

		CHECK(OUTPUT_ERROR, 1, fwrite(s->plaintext, plen, 1, out));
	};

out:
	EVP_CIPHER_CTX_cleanup(&ctx);

	free(s);
	return ret;
}


int aepipe_seal(unsigned char key[KEYSIZE], struct aepipe_context * aepipe_ctx, FILE *in, FILE *out) {
	if(__sync_lock_test_and_set(&aepipe_ctx->flag, true)) {
		return CONCURRENCY_ERROR;
	}
	int ret = CORRUPT_DATA;
	struct iv_numeric iv;
	iv.unused = 0;

	uint64_t counter = aepipe_ctx->offset;

    struct block_state * s = malloc(sizeof(struct block_state));
	if(s == NULL) {
		ERROR(NO_MEMORY);
	}

	EVP_CIPHER_CTX ctx;
	EVP_CIPHER_CTX_init(&ctx);

	CHECK(OPENSSL_WEIRD, 1, EVP_EncryptInit_ex(&ctx, EVP_aes_256_gcm(), NULL, key, NULL));

	iv.counter = htobe64(counter);
	CHECK(OUTPUT_ERROR, 1, fwrite(&iv.counter, sizeof(iv.counter), 1, out));

	int32_t plen;
	bool do_read = 1;
	while(true) {
		if(do_read) {
			plen = fread(s->plaintext, 1, MESSAGE_SIZE, in);
			CHECK(INPUT_ERROR, 0, ferror(in));
			if(plen < MESSAGE_SIZE) {
				do_read = 0;
			}
		} else {
			// Emit a zero length block to indicate the end of input
			plen = 0;
		}

		iv.counter = htobe64(counter);
		counter++;
		CHECK(OPENSSL_WEIRD, 1, EVP_EncryptInit_ex(&ctx, NULL, NULL, NULL, (unsigned char*)&iv + 4));

		int32_t unused_len;
		CHECK(OPENSSL_WEIRD, 1, EVP_EncryptUpdate(&ctx, s->ciphertext, &unused_len, s->plaintext, plen));

		void * unused_buf = {0};
		CHECK(OPENSSL_WEIRD, 1, EVP_EncryptFinal_ex(&ctx, unused_buf, &unused_len));
		CHECK(OPENSSL_WEIRD, 1, EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_GCM_GET_TAG, sizeof(s->tag), s->tag));

		s->len = htonl(plen);
		CHECK(OUTPUT_ERROR, 1, fwrite(s->tag, HEADER_SIZE + plen, 1, out));

		if(0 == plen) {
			ret = OK;
			break;
		}
	}

out:
	EVP_CIPHER_CTX_cleanup(&ctx);
	aepipe_ctx->offset = counter;
	free(s);
	__sync_lock_release(&aepipe_ctx->flag);
	return ret;
}
