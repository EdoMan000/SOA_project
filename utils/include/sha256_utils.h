#ifndef SHA256_UTILS_H
#define SHA256_UTILS_H

#define SHA256_DIGEST_SIZE 32

#include <crypto/hash.h>

int do_sha256(const char *data, unsigned char *out_digest);
int authenticate(const char *passw_to_check, const unsigned char *reference_digest);

#endif