#ifndef SHA256_UTILS_H
#define SHA256_UTILS_H

#include <crypto/hash.h>
#include <linux/slab.h> 
#include <linux/err.h>
#include <linux/types.h> 

#define SHA256_DIGEST_SIZE 32

int compute_sha256(const unsigned char *data, unsigned int datalen, unsigned char *digest);

int verify_password(const unsigned char *password, unsigned int passlen, const unsigned char *expected_hash);

#endif // SHA256_UTILS_H
