#include "include/sha256_utils.h"
#include <crypto/hash.h>
#include <linux/slab.h> 
#include <linux/err.h>

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

int verify_password(const unsigned char *password, unsigned int passlen, const unsigned char *expected_hash)
{
    unsigned char computed_hash[SHA256_DIGEST_SIZE];
    int ret;

    ret = compute_sha256(password, passlen, computed_hash);
    if (ret) {
        pr_err("SHA-256 computation failed\n");
        return ret;
    }

    if (memcmp(computed_hash, expected_hash, SHA256_DIGEST_SIZE) == 0) {
        return 0; 
    } else {
        return -EINVAL; 
    }
}
