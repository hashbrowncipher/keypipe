#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
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
#include <sys/mman.h>
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

#define CHECK(err, x, y)  { if(x != y) { ERROR(err); } }

size_t fdread(void *ptr, size_t size, size_t nmemb, int fd) {
	size_t want = size * nmemb;
	size_t have = 0;
	while(want > 0) {
		ssize_t got = read(fd, ptr + have, want);
		if(got > 0) {
			have += (size_t) got;
			want -= (size_t) got;
		}
		if(got == -1 && errno != EINTR) {
			break;
		}
		if(got == 0) {
			break;
		}
	}
	return have / size;
}

size_t fdwrite(void *ptr, size_t size, size_t nmemb, int fd) {
	size_t want = size * nmemb;
	size_t have = 0;
	while(want > 0) {
		ssize_t got = write(fd, ptr + have, want);
		if(got > 0) {
			have += (size_t) got;
			want -= (size_t) got;
		}
		if(got == -1 && errno != EINTR) {
			break;
		}
		if(got == 0) {
			break;
		}
	}
	return have / size;
}

#define round_up(dividend, divisor) ((((dividend) + divisor - 1) / divisor) * divisor)

int aepipe_unseal(unsigned char key[KEYSIZE], int in, int out) {
	int ret = CORRUPT_DATA;

	const unsigned long page_size = (unsigned long) sysconf(_SC_PAGESIZE);
	size_t alloc_size = 0;
	alloc_size += page_size; // guard page
	alloc_size += round_up(MESSAGE_SIZE + TAG_SIZE + 4, page_size); // input
	alloc_size += page_size; // guard page
	alloc_size += MESSAGE_SIZE; //plaintext
	alloc_size += page_size; // guard page

	unsigned char * s = mmap(NULL, alloc_size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if(s == NULL) {
		return NO_MEMORY;
	}

	unsigned char * buf = s;
	buf += page_size; //guard page
	unsigned char * plaintext = buf;
	buf += MESSAGE_SIZE; //plaintext
	buf += page_size; // guard page
	unsigned char * input = buf;

	//mark memory we want useable as useable
	mprotect(plaintext, MESSAGE_SIZE, PROT_READ | PROT_WRITE);
	mprotect(input, MESSAGE_SIZE + TAG_SIZE + 4, PROT_READ | PROT_WRITE);

	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	CHECK(OPENSSL_WEIRD, 1, EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, NULL));

	uint8_t version;
	uint64_t counter;
	CHECK(CORRUPT_DATA, 1, fdread(input, sizeof(version) + sizeof(counter) + HEADER_SIZE, 1, in));

	void* input_ptr = input;

	CHECK(UNKNOWN_VERSION, 1, *(uint8_t *)input_ptr);
	input_ptr += sizeof(uint8_t);

	counter = *(uint64_t *)input_ptr;
	input_ptr += sizeof(counter);

	unsigned char *iv = alloca(12);
	memset(iv, 0, 12);
	uint64_t * iv_numeric = (uint64_t *)(iv + 4);

	while(true) {
		uint32_t len = ntohl(*(uint32_t *)input_ptr);
		input_ptr += sizeof(len);
		if(len > MESSAGE_SIZE) {
			ERROR(CORRUPT_DATA);
		}

		*iv_numeric = htobe64(counter);
		CHECK(OPENSSL_WEIRD, 1, EVP_DecryptInit_ex(ctx, NULL, NULL, NULL, iv));
		CHECK(OPENSSL_WEIRD, 1, EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, TAG_SIZE, input_ptr));
		input_ptr += TAG_SIZE;

		input_ptr = input;
		if(len != 0) {
			CHECK(CORRUPT_DATA, 1, fdread(input, len + HEADER_SIZE, 1, in));
		}

		int plen;
		CHECK(OPENSSL_WEIRD, 1, EVP_DecryptUpdate(ctx, plaintext, &plen, input_ptr, (int) len));
		input_ptr += len;

		void * unused_buf = {0};
		int32_t unused_len;
		CHECK(CORRUPT_DATA, 1, EVP_DecryptFinal_ex(ctx, unused_buf, &unused_len));

		counter++;
		if(plen == 0) {
			ret = OK;
			break;
		} else {
			CHECK(OUTPUT_ERROR, 1, fdwrite(plaintext, (size_t) plen, 1, out));
		}
	};

out:
	EVP_CIPHER_CTX_free(ctx);
	munmap(s, alloc_size);

	return ret;
}

int aepipe_seal(unsigned char key[KEYSIZE], struct aepipe_context * aepipe_ctx, int in, int out) {
	if(__sync_lock_test_and_set(&aepipe_ctx->flag, true)) {
		//Guarantee ourselves mutual exclusion by complaining if we don't have it.
		return CONCURRENCY_ERROR;
	}

	int ret = CORRUPT_DATA;
	uint64_t counter = aepipe_ctx->offset;

	const unsigned long page_size = (unsigned long) sysconf(_SC_PAGESIZE);
	size_t alloc_size = 0;
	alloc_size += page_size; //guard page
	alloc_size += MESSAGE_SIZE; //plaintext
	alloc_size += page_size; //guard page
	// padding for 16 byte alignment, length, tag
	alloc_size += round_up(12 + sizeof(uint32_t) + TAG_SIZE, page_size);
	alloc_size += MESSAGE_SIZE; //ciphertext
	alloc_size += page_size;

	unsigned char * s = NULL;
	s = mmap(NULL, alloc_size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if(s == NULL) {
		return NO_MEMORY;
	}

	unsigned char * buf = s;
	buf += page_size;
	unsigned char * plaintext = buf;
	buf += MESSAGE_SIZE;
	buf += page_size;
	uint32_t * len = (uint32_t *) buf;
	buf += sizeof(uint32_t);
	unsigned char * tag = buf;
	buf += TAG_SIZE;
	unsigned char * ciphertext = buf;

	CHECK(NO_MEMORY, 0, mprotect(plaintext, MESSAGE_SIZE, PROT_READ | PROT_WRITE))
	CHECK(NO_MEMORY, 0, mprotect(len, 4 + TAG_SIZE + MESSAGE_SIZE, PROT_READ | PROT_WRITE));

	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

	CHECK(OPENSSL_WEIRD, 1, EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, NULL));

	uint8_t version = 1;
	CHECK(OUTPUT_ERROR, 1, fdwrite(&version, sizeof(version), 1, out));

	unsigned char * iv = alloca(12);
	memset(iv, 0, 12);
	uint64_t * iv_numeric = (uint64_t *)(iv + 4);
	*iv_numeric = htobe64(counter);
	CHECK(OUTPUT_ERROR, 1, fdwrite(iv_numeric, sizeof(uint64_t), 1, out));

	size_t plen;
	bool do_read = 1;
	while(true) {
		if(do_read) {
			plen = fdread(plaintext, 1, MESSAGE_SIZE, in);
			if(plen < MESSAGE_SIZE) {
				do_read = 0;
			}
		} else {
			// Emit a zero length block to indicate the end of input
			plen = 0;
		}

		*iv_numeric = htobe64(counter);
		counter++;
		CHECK(OPENSSL_WEIRD, 1, EVP_EncryptInit_ex(ctx, NULL, NULL, NULL, iv));

		int32_t unused_len;
		CHECK(OPENSSL_WEIRD, 1, EVP_EncryptUpdate(ctx, ciphertext, &unused_len, plaintext, (int) plen));

		void * unused_buf = {0};
		CHECK(OPENSSL_WEIRD, 1, EVP_EncryptFinal_ex(ctx, unused_buf, &unused_len));
		CHECK(OPENSSL_WEIRD, 1, EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, TAG_SIZE, tag));

		*len = htonl((uint32_t) plen);
		CHECK(OUTPUT_ERROR, 1, fdwrite(len, HEADER_SIZE + plen, 1, out));

		if(0 == plen) {
			ret = OK;
			break;
		}
	}

out:
	EVP_CIPHER_CTX_free(ctx);
	aepipe_ctx->offset = counter;
	munmap(s, alloc_size);
	__sync_lock_release(&aepipe_ctx->flag);
	return ret;
}
