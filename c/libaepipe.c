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

#define TAG_SIZE 16
#define HEADER_SIZE (sizeof(uint32_t) + TAG_SIZE)

#define ERROR(x) { ret = x; goto out; }

typedef enum {
	OK,
	CORRUPT_DATA,
	NO_MEMORY,
	OPENSSL_WEIRD,
	INPUT_ERROR,
	OUTPUT_ERROR,
	CONCURRENCY_ERROR,
	UNKNOWN_VERSION,
} aepipe_error;

const char* aepipe_errorstrings[8] = {
	"OK",
	"Input data was corrupt",
	"Unable to allocate memory",
	"OpenSSL returned an unexpected error",
	"Unable to read input data",
	"Unable to write output data",
	"Improper concurrent access of an aepipe context",
	"Unrecognized version number",
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

struct seal_block_state {
	unsigned char plaintext[MESSAGE_SIZE];
	// pad to 16 byte alignment
	char padding[12];
	uint32_t len;
	unsigned char tag[TAG_SIZE];
	unsigned char ciphertext[MESSAGE_SIZE];
} __attribute__((__packed__));

struct unseal_block_state {
	unsigned char plaintext[MESSAGE_SIZE];
	unsigned char input[MESSAGE_SIZE + TAG_SIZE + 4];
} __attribute__((__packed__));

struct iv_numeric {
	uint64_t unused;
	uint64_t counter;
};

#define CHECK(err, x, y)  { if(x != y) { ERROR(err); } }

size_t fdread(void *ptr, size_t size, size_t nmemb, int fd) {
	int want = size * nmemb;
	int have = 0;
	while(want > 0) {
		int got = read(fd, ptr + have, want);
		if(got == -1 && errno != EINTR) {
			break;
		}
		if(got == 0) {
			break;
		}
		have += got;
		want -= got;
	}
	return have / size;
}

size_t fdwrite(void *ptr, size_t size, size_t nmemb, int fd) {
	int want = size * nmemb;
	int have = 0;
	while(want > 0) {
		int got = write(fd, ptr + have, want);
		if(got == -1 && errno != EINTR) {
			break;
		}
		if(got == 0) {
			break;
		}
		have += got;
		want -= got;
	}
	return have / size;
}

int aepipe_unseal(unsigned char key[KEYSIZE], int in, int out) {
	struct iv_numeric iv;
	iv.unused = 0;

	int ret = CORRUPT_DATA;

	struct unseal_block_state * s = NULL;
	CHECK(NO_MEMORY, 0, posix_memalign((void **)&s, 4096, sizeof(struct unseal_block_state)))

	EVP_CIPHER_CTX ctx;
	EVP_CIPHER_CTX_init(&ctx);
	CHECK(OPENSSL_WEIRD, 1, EVP_DecryptInit_ex(&ctx, EVP_aes_256_gcm(), NULL, key, NULL));

	uint8_t version;
	uint64_t counter;
	CHECK(CORRUPT_DATA, 1, fdread(&s->input, sizeof(version) + sizeof(counter) + HEADER_SIZE, 1, in));

	void* input_ptr = s->input;

	CHECK(UNKNOWN_VERSION, 1, *(uint8_t *)input_ptr);
	input_ptr += sizeof(uint8_t);

	counter = *(uint64_t *)input_ptr;
	input_ptr += sizeof(counter);

	while(true) {
		uint32_t len = ntohl(*(uint32_t *)input_ptr);
		input_ptr += sizeof(len);
		if(len > MESSAGE_SIZE) {
			ERROR(CORRUPT_DATA);
		}

		iv.counter = htobe64(counter);
		CHECK(OPENSSL_WEIRD, 1, EVP_DecryptInit_ex(&ctx, NULL, NULL, NULL, (unsigned char *)&iv + 4));
		CHECK(OPENSSL_WEIRD, 1, EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_GCM_SET_TAG, TAG_SIZE, input_ptr));
		input_ptr += TAG_SIZE;

		input_ptr = s->input;
		if(len != 0) {
			CHECK(CORRUPT_DATA, 1, fdread(s->input, len + HEADER_SIZE, 1, in));
		}

		int plen;
		CHECK(OPENSSL_WEIRD, 1, EVP_DecryptUpdate(&ctx, s->plaintext, &plen, input_ptr, (int) len));
		input_ptr += len;

		void * unused_buf = {0};
		int32_t unused_len;
		CHECK(CORRUPT_DATA, 1, EVP_DecryptFinal_ex(&ctx, unused_buf, &unused_len));

		if(plen == 0) {
			ret = OK;
			break;
		}

		counter++;
		CHECK(OUTPUT_ERROR, 1, fdwrite(s->plaintext, plen, 1, out));
	};

out:
	EVP_CIPHER_CTX_cleanup(&ctx);

	free(s);
	return ret;
}

int aepipe_seal(unsigned char key[KEYSIZE], struct aepipe_context * aepipe_ctx, int in, int out) {
	if(__sync_lock_test_and_set(&aepipe_ctx->flag, true)) {
		//Guarantee ourselves mutual exclusion by complaining if we don't have it.
		return CONCURRENCY_ERROR;
	}
	int ret = CORRUPT_DATA;
	struct iv_numeric iv;
	iv.unused = 0;

	uint64_t counter = aepipe_ctx->offset;

	struct seal_block_state * s = NULL;
	CHECK(NO_MEMORY, 0, posix_memalign((void **)&s, 4096, sizeof(struct unseal_block_state)))

	EVP_CIPHER_CTX ctx;
	EVP_CIPHER_CTX_init(&ctx);

	CHECK(OPENSSL_WEIRD, 1, EVP_EncryptInit_ex(&ctx, EVP_aes_256_gcm(), NULL, key, NULL));

	uint8_t version = 1;
	CHECK(OUTPUT_ERROR, 1, fdwrite(&version, sizeof(version), 1, out));

	iv.counter = htobe64(counter);
	CHECK(OUTPUT_ERROR, 1, fdwrite(&iv.counter, sizeof(iv.counter), 1, out));

	int32_t plen;
	bool do_read = 1;
	while(true) {
		if(do_read) {
			plen = fdread(s->plaintext, 1, MESSAGE_SIZE, in);
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
		CHECK(OUTPUT_ERROR, 1, fdwrite(&s->len, HEADER_SIZE + plen, 1, out));

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
