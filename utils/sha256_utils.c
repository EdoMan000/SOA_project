#include "include/sha256_utils.h"

/**
 * @brief Computes the SHA256 hash of the given data.
 * 
 * @param data Pointer to the data to hash.
 * @param datalen Length of the data to hash.
 * @param digest Buffer to store the resulting hash; must be at least SHA256_DIGEST_SIZE bytes.
 * @return 0 on success, negative error code on failure.
 */
int compute_sha256(const unsigned char *data, unsigned int datalen, unsigned char *digest)
{
    struct crypto_shash *alg;
    struct shash_desc *shash;
    int size, ret;

    alg = crypto_alloc_shash("sha256", 0, 0);
    if (IS_ERR(alg)) {
        pr_err("Error allocating SHA256 transform: %ld\n", PTR_ERR(alg));
        return PTR_ERR(alg);
    }
    size = sizeof(struct shash_desc) + crypto_shash_descsize(alg);
    shash = kmalloc(size, GFP_KERNEL);
    if (!shash) {
        crypto_free_shash(alg);
        return -ENOMEM;
    }
    shash->tfm = alg;
    ret = crypto_shash_digest(shash, data, datalen, digest);
    kfree(shash);
    crypto_free_shash(alg);
    return ret;
}

/**
 * @brief Verifies if the given password matches the expected hash.
 * 
 * @param password Pointer to the password to verify.
 * @param passlen Length of the password.
 * @param expected_hash Expected SHA256 hash to compare against.
 * @return 0 if the password matches the expected hash, -EINVAL if not, or another negative error code on failure.
 */
int verify_password(const unsigned char *password, unsigned int passlen, const unsigned char *expected_hash)
{
    int ret;

    unsigned char *computed_hash = kmalloc(SHA256_DIGEST_SIZE, GFP_KERNEL);
    if(!computed_hash){
        pr_err("Couldn't allocate memory to store computed hash\n");
        return -ENOMEM;
    }

    ret = compute_sha256(password, passlen, computed_hash);
    if (ret) {
        pr_err("SHA-256 computation failed\n");
        kfree(computed_hash);
        return ret;
    }

    if (memcmp(computed_hash, expected_hash, SHA256_DIGEST_SIZE) == 0) {
        kfree(computed_hash);
        return 0; 
    } else {
        kfree(computed_hash);
        return -EINVAL; 
    }
}
