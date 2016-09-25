#define KEYSIZE 32

struct aepipe_context;
const char* aepipe_errorstrings[6];

size_t aepipe_context_size(void);
void aepipe_init_context(struct aepipe_context* ctx);

int aepipe_decrypt(unsigned char key[KEYSIZE], FILE* in, FILE* out);
int aepipe_encrypt(unsigned char key[KEYSIZE], struct aepipe_context * ctx, FILE* in, FILE* out);
