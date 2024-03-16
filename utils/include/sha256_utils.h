#ifndef SHA256_UTILS_H
#define SHA256_UTILS_H

#include <linux/types.h> 

#define SHA256_DIGEST_SIZE 32

/**
 * Computes the SHA256 hash of the given data.
 * 
 * @param data Pointer to the data to hash.
 * @param datalen Length of the data to hash.
 * @param digest Buffer to store the resulting hash; must be at least SHA256_DIGEST_SIZE bytes.
 * @return 0 on success, negative error code on failure.
 */
int compute_sha256(const unsigned char *data, unsigned int datalen, unsigned char *digest);

/**
 * Verifies if the given password matches the expected hash.
 * 
 * @param password Pointer to the password to verify.
 * @param passlen Length of the password.
 * @param expected_hash Expected SHA256 hash to compare against.
 * @return 0 if the password matches the expected hash, -EINVAL if not, or another negative error code on failure.
 */
int verify_password(const unsigned char *password, unsigned int passlen, const unsigned char *expected_hash);

#endif // SHA256_UTILS_H