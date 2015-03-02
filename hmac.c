#include <fcntl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

#define KEYSIZE 32

#define SEQ_OFFSET 0
#define SIZE_OFFSET 4
#define MESSAGE_OFFSET 8
#define MESSAGE_SIZE (1024 * 1024)
#define BUFSIZE (MESSAGE_SIZE + MESSAGE_OFFSET)

#define handle_error(message) { perror((message)); exit(EXIT_FAILURE); }

int do_usage(char* name) {
	fprintf(stderr, "Usage: %s <keyfile>\n", name);
	exit(2);
}

int do_verify(void* key[KEYSIZE]) {
	unsigned char md[KEYSIZE];

	unsigned char block_mac[KEYSIZE];
	void* buf = malloc(BUFSIZE);
	uint32_t* block_seq = buf;
	uint32_t* block_size = buf + SIZE_OFFSET;
	void* message = buf + MESSAGE_OFFSET;

	int ret;

	for(uint32_t seq = 0;; seq++) {
		ret = fread(&block_mac, sizeof(block_mac), 1, stdin);
		if(ret != 1) {
			fprintf(stderr, "Failed reading block MAC of block %d\n", seq);
			exit(4);
		}

		ret = fread(buf, MESSAGE_OFFSET, 1, stdin);
		if(ret != 1) {
			fprintf(stderr, "Failed reading block header of block %d\n", seq);
			exit(4);
		}

		if(*block_seq != seq) {
			fprintf(stderr, "Invalid sequence number in block %d: got %d\n", seq, *block_seq);
			exit(4);
		}

		if(*block_size > MESSAGE_SIZE) {
			fprintf(stderr, "Header for block %d specifies illegal size\n", seq);
			exit(4);
		}

		if(*block_size == 0) {
			ret = getchar();
			if(feof(stdin)) {
				break;
			}

			fprintf(stderr, "Block %d indicates zero length, but there are more bytes to read\n", seq);
			exit(4);
		}

		ret = fread(message, *block_size, 1, stdin);
		if(ret != 1) {
			fprintf(stderr, "Failed reading %d bytes from block %d\n", *block_size, seq);
			exit(4);
		}

		HMAC(EVP_sha256(), key, KEYSIZE, buf, *block_size + MESSAGE_OFFSET, md, NULL);
		if(CRYPTO_memcmp(md, block_mac, KEYSIZE) != 0) {
			fprintf(stderr, "MAC mismatch in block %d\n", seq);
			exit(4);
		}

		ret = write(STDOUT_FILENO, message, *block_size);
	}

	free(buf);
}

int do_sign(void* key[KEYSIZE]) {
	unsigned char md[KEYSIZE];

	void* buffer = malloc(BUFSIZE);
	uint32_t* seq = buffer;
	uint32_t* block_size = buffer + SIZE_OFFSET;
	void* message = buffer + MESSAGE_OFFSET;
	
	*seq = 0;

	const EVP_MD* evp = EVP_sha256();

	do {
		*block_size = read(STDIN_FILENO, message, MESSAGE_SIZE);
		if(*block_size < 0) {
			handle_error("Error reading input");
		}
		uint32_t output_size = *block_size + MESSAGE_OFFSET;
		HMAC(evp, key, KEYSIZE, buffer, output_size, md, NULL);
		int ret;
		ret = fwrite(md, sizeof(md), 1, stdout);
		ret = fwrite(buffer, output_size, 1, stdout);
		fflush(stdout);
		(*seq)++;
	} while(*block_size != 0);

	free(buffer);
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
