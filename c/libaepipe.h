#define KEYSIZE 32

/*
 * array of strings describing error conditions that libaepipe may encounter
 * zero means "everything is fine"
 */
extern const char* aepipe_errorstrings[];

/*
 * unseal (decrypt and verify) an aepipe stream
 * args:
 *   key: the unseal key
 *   in: file descriptor from which input should be read
 *   out: file descriptor to which output should be written
 *
 * returns 0 on success
 * returns non-zero on failure. Any non-zero return codes can be looked up in
 * aepipe_errorstrings.
 */
int aepipe_unseal(unsigned char key[KEYSIZE], FILE* in, FILE* out);

/*
 * an opaque struct for use with aepipe_seal, as described below.
 */
struct aepipe_context;

/*
 * seal (encrypt and authenticate) an aepipe stream
 * args:
 *   same as aepipe_unseal, AND
 *   ctx: an opaque pointer, used by aepipe_seal to manage successive calls
 *   to aepipe_seal with the same key.
 *
 * Use an aepipe_ctx as follows:
 *   1. query aepipe_context_size to learn sizeof(struct aepipe_context)
 *   2. allocate a pointer to that many bytes
 *   3. call aepipe_init_context on that pointer
 *   4. pick a key
 *   5. call aepipe_seal(...)
 *   6. repeat step 5 as desired
 *
 * Note that it *is* acceptable to call aepipe_seal multiple times with the
 * same key IF AND ONLY IF the same aepipe_context object is passed to
 * aepipe_seal every time. Otherwise it is unacceptable.
 */
int aepipe_seal(unsigned char key[KEYSIZE], struct aepipe_context * aepipe_ctx, FILE* in, FILE* out);

/* Returns sizeof(struct aepipe_context) */
size_t aepipe_context_size(void);

/* Initializes a struct aepipe_context */
void aepipe_init_context(struct aepipe_context* ctx);
