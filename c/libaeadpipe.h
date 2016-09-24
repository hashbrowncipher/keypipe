#define KEYSIZE 32

typedef enum {
    OK,
    CORRUPT_DATA,
    NO_MEMORY,
    OPENSSL_WEIRD,
    INPUT_ERROR,
    OUTPUT_ERROR,
} aeadpipe_error;

const char* aeadpipe_errorstrings[6];

struct gcm_context;
size_t gcm_context_size(void);
void init_gcm_context(struct gcm_context* ctx);

aeadpipe_error aeadpipe_decrypt(unsigned char key[KEYSIZE], FILE *in, FILE *out);
aeadpipe_error aeadpipe_encrypt(unsigned char key[KEYSIZE], struct gcm_context * aead_ctx, FILE *in, FILE *out);
