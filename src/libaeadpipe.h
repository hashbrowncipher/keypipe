#define KEYSIZE 32

struct gcm_context;
size_t gcm_context_size(void);
void init_gcm_context(struct gcm_context* ctx);

int aeadpipe_decrypt(unsigned char key[KEYSIZE], FILE *in, FILE *out);
int aeadpipe_encrypt(unsigned char key[KEYSIZE], struct gcm_context * aead_ctx, FILE *in, FILE *out);
