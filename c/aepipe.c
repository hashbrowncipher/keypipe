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

#include "libaepipe.h"

#define EXIT_FAILURE 1
#define handle_error(message) { perror((message)); exit(EXIT_FAILURE); }

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
		exit(1);
	}

	unsigned char key[KEYSIZE];

	int rc;
	rc = fread(key, KEYSIZE, 1, keyfile);
	if(rc != 1) {
		fprintf(stderr, "Could not read key material from file\n");
		exit(2);
	}
	rc = fclose(keyfile);

	rc = fcntl(STDIN_FILENO, F_SETPIPE_SZ, 1024 * 1024);
	if(rc == -1 && errno != EBADF) {
		handle_error("Couldn't set pipe buffer size");
	}

	setbuf(stdin, NULL);
	setbuf(stdout, NULL);

	int ret;
	if(decrypt_flag) {
		ret = aepipe_unseal(key, STDIN_FILENO, STDOUT_FILENO);
	} else {
		struct aepipe_context * ctx = alloca(aepipe_context_size());
		aepipe_init_context(ctx);
		ret = aepipe_seal(key, ctx, STDIN_FILENO, STDOUT_FILENO);
	}
	if(ret) {
		fprintf(stderr, "%s\n", aepipe_errorstrings[ret]);
	}
	exit(ret);
}
