#include "include/sha256_utils.h"

struct sdesc {
    struct shash_desc shash;
    char ctx[];
};

static struct sdesc *init_sdesc(struct crypto_shash *alg)
{
    struct sdesc *sdesc;
    int size;

    size = sizeof(struct shash_desc) + crypto_shash_descsize(alg);
    sdesc = kmalloc(size, GFP_KERNEL);
    if (!sdesc)
        return ERR_PTR(-ENOMEM);
    sdesc->shash.tfm = alg;
    return sdesc;
}

static int calc_hash(struct crypto_shash *alg,
             const unsigned char *data, unsigned int datalen,
             unsigned char *digest)
{
    struct sdesc *sdesc;
    int ret;

    sdesc = init_sdesc(alg);
    if (IS_ERR(sdesc)) {
        return PTR_ERR(sdesc);
    }

    ret = crypto_shash_digest(&sdesc->shash, data, datalen, digest);
    kfree(sdesc);
    return ret;
}

int do_sha256(const unsigned char *data, unsigned char *out_digest)
{
    struct crypto_shash *alg;
    char *hash_alg_name = "sha256";
    unsigned int datalen = sizeof(data) - 1; 

    alg = crypto_alloc_shash(hash_alg_name, 0, 0);
    if(IS_ERR(alg)){
        return PTR_ERR(alg);
    }
    calc_hash(alg, data, datalen, out_digest);

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