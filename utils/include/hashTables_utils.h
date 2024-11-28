#include <linux/uuid.h>

#define HASH_TABLE_BITS 16  // Adjust as needed

unsigned long compute_hash_key(unsigned long inode_num, uuid_t *fs_uuid);

