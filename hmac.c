#include <fcntl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

#define KEYSIZE 32
#define BUFSIZE 1024 * 1024

#define handle_error(message) { perror((message)); exit(EXIT_FAILURE); }

// Needs to compile without padding
struct block_header {
	uint32_t seq;
	uint32_t size;
	unsigned char mac[32];
};

inline void fread_one(void *ptr, size_t size, FILE * stream, char* message) {
	int ret = fread(ptr, size, 1, stream);
	if(ret != 1) {
		fprintf(stderr, "%s\n", message);
		exit(2);
	}
}

int do_usage(char* name) {
	fprintf(stderr, "Usage: %s <keyfile>\n", name);
	exit(2);
}

int do_verify(void* key[KEYSIZE]) {
	unsigned char md[KEYSIZE];
	void* buf = malloc(BUFSIZE);

	int ret;
	struct block_header header;

	for(int seq = 0;; seq++) {
		ret = fread(&header, sizeof(struct block_header), 1, stdin);
		if(ret != 1) {
			fprintf(stderr, "Failed reading block header of block %d\n", seq);
			exit(4);
		}
		if(header.size > BUFSIZE) {
			fprintf(stderr, "Header for block %d specifies illegal size\n", seq);
			exit(4);
		}

		if(header.seq != seq) {
			fprintf(stderr, "Invalid sequence number in block %d: got %d\n", seq, header.seq);
			exit(4);
		}

		if(header.size == 0) {
			ret = getchar();
			if(feof(stdin)) {
				break;
			}

			fprintf(stderr, "Block %d indicates zero length, but there are more bytes to read\n", seq);
			exit(4);
		}

		ret = fread(buf, header.size, 1, stdin);
		if(ret != 1) {
			if(header.size == 0 && feof(stdin)) {
				break;
			}

			fprintf(stderr, "Failed reading %d bytes from block %d\n", header.size, seq);
			exit(4);
		}

		HMAC(EVP_sha256(), key, KEYSIZE, buf, header.size, md, NULL);
		if(CRYPTO_memcmp(md, header.mac, KEYSIZE) != 0) {
			fprintf(stderr, "MAC mismatch in block %d\n", seq);
			exit(4);
		}

		ret = write(STDOUT_FILENO, buf, header.size);
	}

	free(buf);
}

int do_sign(void* key[KEYSIZE]) {
	unsigned char md[KEYSIZE];
	void* message = malloc(BUFSIZE);
	uint32_t block_size;
	uint32_t seq = 0;

	do {
		block_size = read(STDIN_FILENO, message, BUFSIZE);
		if(block_size < 0) {
			handle_error("Error reading input");
		}
		HMAC(EVP_sha256(), key, KEYSIZE, message, block_size, md, NULL);
		int ret;
		ret = write(STDOUT_FILENO, &seq, sizeof(seq));
		ret = write(STDOUT_FILENO, &block_size, sizeof(block_size));
		ret = write(STDOUT_FILENO, md, 32);
		ret = write(STDOUT_FILENO, message, block_size);

		seq++;
	} while(block_size != 0);
}

int main(int argc, char* argv[]) {
	void* key[KEYSIZE];

	int verify_flag = 0;
	int c;

	while((c = getopt(argc, argv, "v")) != -1) {
		switch(c) {
		case 'v':
			verify_flag = 1;
			break;
		}
	}

	if(argc - optind != 1) {
		do_usage(argv[0]);
	}

	FILE * keyfile = fopen(argv[optind], "r");
	if(keyfile == NULL) {
		handle_error("Error opening key file");
	}

	int ret = fread(key, KEYSIZE, 1, keyfile);
	if(ret != 1) {
		fprintf(stderr, "Could not read key material from file\n");
		exit(4);
	}
	ret = fclose(keyfile);

	if(verify_flag) {
		do_verify(key);
	} else {
		do_sign(key);
	}

	return 0;
}
