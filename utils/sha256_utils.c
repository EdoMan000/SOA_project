#include "include/sha256_utils.h"

int do_sha256(const char *data, unsigned char *out_digest)
{
    struct crypto_shash *alg;
    char *hash_alg_name = "sha256";
    unsigned int datalen = strlen(data);

    alg = crypto_alloc_shash(hash_alg_name, 0, 0);
    if (IS_ERR(alg)) {
        return PTR_ERR(alg);
    }

    if (crypto_shash_digest(alg, data, datalen, out_digest)) {
        crypto_free_shash(alg);
        return -EPERM;
    }

    crypto_free_shash(alg);
    return 0;
}

int authenticate(const char *passw_to_check, const unsigned char *reference_digest)
{
    unsigned char passw_to_check_digest[SHA256_DIGEST_SIZE];
    int sha_ret = do_sha256(passw_to_check, passw_to_check_digest);

    if (sha_ret) {
        return -1;
    }

    if (memcmp(passw_to_check_digest, reference_digest, SHA256_DIGEST_SIZE) == 0) {
        return 0;
    } else {
        return -1;
    }
}